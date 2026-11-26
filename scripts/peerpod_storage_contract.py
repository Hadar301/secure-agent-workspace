"""Closed lab-only Pod contract. Does not enable production enrollment."""
import copy
import ipaddress
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import uuid


class ContractError(ValueError):
    pass


DRIVER_COMMAND = "mount -t devtmpfs none /dev && exec /usr/bin/azurediskplugin --drivername={driver} --endpoint=unix:///csi/backend.sock --nodeid=$KUBE_NODE_NAME --allow-empty-cloud-config=true --cloud-config-secret-name= --cloud-config-secret-namespace= --remove-not-ready-taint=false --never-stop-taint-removal=false --enable-migration-monitor=false --v=2"
TEST_COMMAND = "set -eu; printf saw-storage-lab > /work/saw-storage-check; test \"$(cat /work/saw-storage-check)\" = saw-storage-lab; printf 'StorageWritePassed\\n'; sleep 120"
FIELDS = {"registration", "nodeName", "runtimeClass", "image", "claimName", "podUID", "pvName", "apiAudience", "apiHost", "apiPort", "applicationUID"}


def build(site):
    """Return a preview only. Its UID and claim inputs must later be reserved."""
    try:
        if not isinstance(site, dict) or set(site) != FIELDS:
            raise ValueError()
        registration = site["registration"]
        if not re.fullmatch("[a-f0-9]{16}", registration):
            raise ValueError()
        for key in ["nodeName", "runtimeClass", "claimName", "pvName"]:
            if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}", site[key]) or ".." in site[key]:
                raise ValueError()
        if not re.fullmatch(r"[a-z0-9][^ @]*@sha256:[a-f0-9]{64}", site["image"]):
            raise ValueError()
        if str(uuid.UUID(site["podUID"])) != site["podUID"]:
            raise ValueError()
        if (type(site["applicationUID"]) is not int or site["applicationUID"] <= 0
                or type(site["apiPort"]) is not int or site["apiPort"] != 443
                or not isinstance(site["apiAudience"], str)
                or not re.fullmatch(r"https://[a-z0-9.-]+(?::443)?", site["apiAudience"])):
            raise ValueError()
        ipaddress.ip_address(site["apiHost"])
        namespace = "saw-ppvc-probe-" + registration
        control = "saw-ppvc-" + registration
        driver = control + ".disk.csi.saw.redhat.com"
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount"
        target = "/var/lib/kubelet/pods/" + site["podUID"] + "/volumes/kubernetes.io~csi/" + site["pvName"] + "/mount"
        def security(uid, privileged=False):
            return {"runAsUser": uid, "runAsNonRoot": uid != 0,
                    "privileged": privileged, "allowPrivilegeEscalation": privileged,
                    "readOnlyRootFilesystem": True,
                    "seccompProfile": {"type": "Unconfined" if privileged else "RuntimeDefault"},
                    **({} if privileged else {"capabilities": {"drop": ["ALL"]}})}
        def container(name, command, uid, mounts, *, privileged=False, env=None, args=None):
            return {"name": name, "image": site["image"], "imagePullPolicy": "Always",
                    "command": command, **({"args": args} if args else {}),
                    "env": env or [], "securityContext": security(uid, privileged),
                    "resources": {"requests": {"cpu": "50m", "memory": "128Mi"}, "limits": {"memory": "512Mi"}},
                    "volumeMounts": mounts}
        def field(name, path):
            return {"name": name, "valueFrom": {"fieldRef": {"fieldPath": path}}}
        disk = container("azure-disk-helper", ["/bin/sh", "-ec"], 0,
            [{"name": "guest-kubelet", "mountPath": "/var/lib/kubelet", "mountPropagation": "Bidirectional"},
             {"name": "socket", "mountPath": "/csi"}, {"name": "tmp", "mountPath": "/tmp"}],
            privileged=True, env=[field("KUBE_NODE_NAME", "spec.nodeName")], args=[DRIVER_COMMAND.format(driver=driver)])
        wrapper = container("volume-wrapper", ["/usr/local/bin/csi-podvm-wrapper"], 0,
            [{"name": "socket", "mountPath": "/csi"}, {"name": "api-identity", "mountPath": token_path, "readOnly": True}],
            env=[field("POD_NAME", "metadata.name"), field("POD_NAME_SPACE", "metadata.namespace"),
                 field("POD_UID", "metadata.uid"), field("POD_NODE_NAME", "spec.nodeName"),
                 {"name": "KUBERNETES_SERVICE_HOST", "value": site["apiHost"]},
                 {"name": "KUBERNETES_SERVICE_PORT", "value": str(site["apiPort"])}],
            args=["--endpoint=/csi/guest.sock", "--target-endpoint=/csi/backend.sock", "--namespace=" + control, "--v=0"])
        app = container("mount-check", ["/bin/sh", "-ec"], site["applicationUID"],
            [{"name": "work", "mountPath": "/work", "mountPropagation": "HostToContainer"}], args=[TEST_COMMAND])
        return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "storage-mount-lab", "namespace": namespace,
            "labels": {"saw.redhat.com/peerpod-storage-lab": registration},
            "annotations": {"openshift.io/required-scc": control + "-guest", "io.confidentialcontainers.org.peerpodvolumes.target_path": target}},
            "spec": {"runtimeClassName": site["runtimeClass"], "nodeSelector": {"kubernetes.io/hostname": site["nodeName"]},
            "serviceAccountName": "storage-guest", "automountServiceAccountToken": False,
            "enableServiceLinks": False, "restartPolicy": "Never", "activeDeadlineSeconds": 300,
            "terminationGracePeriodSeconds": 20, "schedulingGates": [{"name": "saw.redhat.com/storage-lab-review"}],
            "securityContext": {"fsGroup": site["applicationUID"]},
            "containers": [disk, wrapper, app], "volumes": [
                {"name": "guest-kubelet", "hostPath": {"path": "/var/lib/kubelet", "type": "Directory"}},
                {"name": "socket", "emptyDir": {}}, {"name": "tmp", "emptyDir": {}},
                {"name": "work", "persistentVolumeClaim": {"claimName": site["claimName"]}},
                {"name": "api-identity", "projected": {"defaultMode": 0o400, "sources": [
                    {"serviceAccountToken": {"audience": site["apiAudience"], "expirationSeconds": 600, "path": "token"}},
                    {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                    {"downwardAPI": {"items": [{"path": "namespace", "fieldRef": {"fieldPath": "metadata.namespace"}}]}}]}}]}}
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ContractError("LabGuestContractRejected") from None


def validate(pod, site):
    """Unknown or changed security fields fail closed. Input is a preview."""
    try:
        if json.dumps(pod, sort_keys=True, separators=(",", ":")) != json.dumps(build(site), sort_keys=True, separators=(",", ":")):
            raise ValueError()
        return copy.deepcopy(pod)
    except (ValueError, TypeError):
        raise ContractError("LabGuestContractRejected") from None


def generator_input(pod, site):
    """Remove API-only controls. Preserve all guest security and mount fields."""
    result = validate(pod, site)
    for key in ["schedulingGates", "activeDeadlineSeconds", "automountServiceAccountToken", "enableServiceLinks"]:
        del result["spec"][key]
    for container in result["spec"]["containers"]:
        # Kubernetes validates this flag; the guest policy pins the numeric UID.
        del container["securityContext"]["runAsNonRoot"]
    # The pinned parser supports the projected volume type, not its sources.
    # validate() above checks every source against the original closed contract.
    del result["spec"]["volumes"][-1]["projected"]["sources"]
    resolved = {"metadata.name": pod["metadata"]["name"], "metadata.namespace": pod["metadata"]["namespace"],
                "metadata.uid": site["podUID"], "spec.nodeName": site["nodeName"]}
    for container in result["spec"]["containers"]:
        for env in container.get("env", []):
            if "valueFrom" in env:
                field = env.pop("valueFrom")["fieldRef"]["fieldPath"]
                env["value"] = resolved[field]
    return result


FIXED_DATA = {
    "common": "fe72866b3840675364daa789dff7f93602b5bde4ddea5b66ad1f898ad944c4bc",
    "sandbox": "ed9bcaa593756ab3759f4401a35a52bcd9499f8251fb788bbec7825b18c1606d",
    "request_defaults": "a9e85a01e5f24a3c1b6ed4e7696513de03392727956aa16d023fea6464e38621",
    "devices": "e9eade0bccab570371b3107e11f3de1f78b50bde0ea1c63a8d2a27df3f576081",
    "cluster_config": "175638aa2e84113b47c6a177e56b0ee113e892ab1402bd52fab4f5f5bbac734e",
}


FIXED_LAYOUT = {'azure-disk-helper': {'Linux': '553515bed708b2e2b6b2b98919c6f10397ef02881888447fca6ef2ca6c5873df',
                       'Mounts': '51b87d24f452ae9471276fa70eadbde3faf65ca017dc7dcef1fab7ee24b5160c'},
 'mount-check': {'Linux': '0f135a21f851f9f3441efd08be44bbc84c5108e6e56c2d7f78dd8f34f73d55b4',
                 'Mounts': '38835ad18a3638b8c31774cbf0d04e04eecad8ac0d9adc0801afbde725e62618'},
 'volume-wrapper': {'Linux': '0f135a21f851f9f3441efd08be44bbc84c5108e6e56c2d7f78dd8f34f73d55b4',
                    'Mounts': 'b8ecdc982d5ce55a673e33c48cab6a85cc9a3f9b2e345831f7b1f9f04117bbdf'}}
BASE_ENV_SHA256 = '0ab3e89661a5f07a2bddcd726dba242c96235659de751e427056fcaa1fd31921'


def compile_policy(pod, site, generated, runtime_profile):
    """Compile only the closed lab preview. Never enables SAW enrollment."""
    normalized = generator_input(pod, site)
    spec = importlib.util.spec_from_file_location("lab_canonical_attestation", Path(__file__).resolve().parents[1] / "kubernetes-runtime/saw_kubernetes/attestation.py")
    a = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(a)
    try:
        if not isinstance(generated, str) or len(generated.encode()) > 512 * 1024 or a.IDENTITY_MARKER in generated:
            raise ValueError()
        matches = list(a.POLICY_DATA.finditer(generated))
        if len(matches) != 1:
            raise ValueError()
        prefix = generated[:matches[0].start()].rstrip()
        if hashlib.sha256(prefix.encode()).hexdigest() != a.GENPOLICY_RULES_SHA256:
            raise ValueError()
        data = json.loads(generated[matches[0].end()-1:])
        if set(data) != set(FIXED_DATA) | {"containers"} or any(a.digest(data[key]) != expected for key, expected in FIXED_DATA.items()):
            raise ValueError()
        expected = {c["name"]: c for c in normalized["spec"]["containers"]}
        actual = {}
        pauses = []
        for c in data["containers"]:
            o = c["OCI"]
            if o["Annotations"]["io.kubernetes.cri.container-type"] == "sandbox":
                pauses.append(c)
            else:
                name = o["Annotations"]["io.kubernetes.cri.container-name"]
                if name in actual:
                    raise ValueError()
                actual[name] = c
        if len(pauses) != 1 or data["containers"][0] is not pauses[0] or set(actual) != set(expected):
            raise ValueError()
        roles = {}
        for name, declared in expected.items():
            o = actual[name]["OCI"]
            process = o["Process"]
            privileged = declared["securityContext"]["privileged"]
            uid = declared["securityContext"]["runAsUser"]
            caps = {key: (["$(privileged_caps)"] if privileged and key in {"Bounding", "Effective", "Permitted"} else []) for key in ["Ambient", "Bounding", "Effective", "Inheritable", "Permitted"]}
            if (process["User"]["UID"] != uid or process["NoNewPrivileges"] != (not privileged)
                    or process["Args"] != declared["command"] + declared.get("args", [])
                    or process["Capabilities"] != caps or o["Root"]["Readonly"] is not True
                    or o["Annotations"]["io.kubernetes.cri.image-name"] != site["image"]
                    or o["Annotations"]["io.kubernetes.cri.sandbox-namespace"] != pod["metadata"]["namespace"]):
                raise ValueError()
            for env in declared["env"]:
                if process["Env"].count(env["name"] + "=" + env["value"]) != 1:
                    raise ValueError()
            if any(a.digest(o[key]) != value for key, value in FIXED_LAYOUT[name].items()):
                raise ValueError()
            declared_env = {entry["name"] for entry in declared["env"]}
            base_env = [v for v in process["Env"] if v.split("=", 1)[0] not in declared_env]
            if a.digest(base_env) != BASE_ENV_SHA256:
                raise ValueError()
            propagation = "rshared" if name == "azure-disk-helper" else "rslave" if name == "mount-check" else ""
            roles[name] = {"uid": uid, "noNewPrivileges": not privileged, "rootfsPropagation": propagation}
        data["saw_identity"] = a.IDENTITY_MARKER
        raw = prefix + "\n\npolicy_data := " + a.canonical(data).replace(json.dumps(a.IDENTITY_MARKER), a.IDENTITY_MARKER) + "\n"
        crio = a._crio_module()
        converted = crio.compile_policy(pod, raw, runtime_profile)
        rules, encoded = converted.split("\n\npolicy_data := ", 1)
        needle = "    input.OCI.Process.User.UID > 0\n    input.OCI.Process.NoNewPrivileges == true"
        if rules.count(needle) != 1 or rules.count("    saw_crio_identity\n") != 1:
            raise ValueError()
        rules = rules.replace(needle, "    input.OCI.Process.User.UID == policy_data.saw_storage_lab.roles[name].uid\n    input.OCI.Process.NoNewPrivileges == policy_data.saw_storage_lab.roles[name].noNewPrivileges")
        rules = rules.replace("    saw_crio_identity\n", "    saw_crio_identity\n    saw_storage_lab_identity\n    saw_storage_lab_mounts\n")
        rules += '\n\nsaw_storage_lab_identity if {\n    input.OCI.Annotations["io.kubernetes.pod.uid"] == policy_data.saw_storage_lab.podUID\n}\n'
        propagation_check = "    count(i_linux.RootfsPropagation) == 0"
        if rules.count(propagation_check) != 1:
            raise ValueError()
        rules = rules.replace(propagation_check, "    saw_storage_lab_propagation(i_oci)")
        rules += '\n\nsaw_storage_lab_propagation(oci) if {\n    oci.Annotations["io.kubernetes.cri.container-type"] == "sandbox"\n    count(oci.Linux.RootfsPropagation) == 0\n}\n\nsaw_storage_lab_propagation(oci) if {\n    oci.Annotations["io.kubernetes.cri.container-type"] == "container"\n    name := oci.Annotations["io.kubernetes.cri.container-name"]\n    oci.Linux.RootfsPropagation == policy_data.saw_storage_lab.roles[name].rootfsPropagation\n}\n'
        converted_data = json.loads(encoded.replace(a.IDENTITY_MARKER, "null"))
        converted_data["saw_storage_lab"] = {"podUID": site["podUID"], "roles": roles, "originalPodSHA256": a.digest(pod), "previewOnly": True}
        # Generated HostToContainer uses rprivate. CRI-O uses rslave for it.
        app = next(c for c in converted_data["containers"] if c["OCI"]["Annotations"].get("io.kubernetes.cri.container-name") == "mount-check")
        mount, = [m for m in app["OCI"]["Mounts"] if m["destination"] == "/work"]
        if mount["options"] != ["rbind", "rprivate", "rw", "bind"]:
            raise ValueError()
        mount["options"] = ["rbind", "rslave", "rw", "bind"]
        target = pod["metadata"]["annotations"]["io.confidentialcontainers.org.peerpodvolumes.target_path"]
        mount["source"] = target
        disk = next(c for c in converted_data["containers"] if c["OCI"]["Annotations"].get("io.kubernetes.cri.container-name") == "azure-disk-helper")
        root_mount, = [m for m in disk["OCI"]["Mounts"] if m["destination"] == "/var/lib/kubelet"]
        if root_mount["options"] != ["rbind", "rshared", "rw", "bind"]:
            raise ValueError()
        root_mount["source"] = "/var/lib/kubelet"
        converted_data["saw_storage_lab"]["directMounts"] = {"azure-disk-helper": [copy.deepcopy(root_mount)], "mount-check": [copy.deepcopy(mount)]}
        rules += '\n\nsaw_storage_lab_mounts if {\n    input.OCI.Annotations["io.kubernetes.cri-o.ContainerType"] == "sandbox"\n}\n\nsaw_storage_lab_mounts if {\n    input.OCI.Annotations["io.kubernetes.cri-o.ContainerType"] == "container"\n    name := input.OCI.Annotations["io.kubernetes.container.name"]\n    every expected in object.get(policy_data.saw_storage_lab.directMounts, name, []) {\n        actual := [m | m := input.OCI.Mounts[_]; m.destination == expected.destination]\n        count(actual) == 1\n        actual[0] == expected\n    }\n}\n'
        converted_data["saw_identity"] = a.IDENTITY_MARKER
        return rules + "\n\npolicy_data := " + a.canonical(converted_data).replace(json.dumps(a.IDENTITY_MARKER), a.IDENTITY_MARKER) + "\n"
    except (ValueError, KeyError, TypeError, IndexError, AttributeError):
        raise ContractError("LabGuestPolicyRejected") from None
