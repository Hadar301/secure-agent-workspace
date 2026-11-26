"""Closed lab-only Pod contract. Does not enable production enrollment."""
import copy
import base64
import gzip
import io
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


def admitted_input(pod, site, context):
    """Check the observed OSC conversion and known API defaults. Keep authority."""
    try:
        expected = build(site)
        if set(context) != {"runtimeClass", "imagePullSecrets"}:
            raise ValueError()
        rc = context["runtimeClass"]
        if (set(rc) != {"name", "uid", "handler", "nodeSelector", "overhead"}
                or rc["name"] != site["runtimeClass"] or rc["handler"] != "kata-remote"
                or str(uuid.UUID(rc["uid"])) != rc["uid"]):
            raise ValueError()
        if not isinstance(rc["nodeSelector"], dict) or not isinstance(rc["overhead"], dict):
            raise ValueError()
        refs = context["imagePullSecrets"]
        if not isinstance(refs, list) or any(set(x) != {"name"} or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", x["name"]) for x in refs):
            raise ValueError()
        candidate = copy.deepcopy(pod)
        metadata = candidate["metadata"]
        if metadata.get("uid") != site["podUID"] or candidate["spec"].get("nodeName"):
            raise ValueError()
        for field in ["uid", "creationTimestamp", "resourceVersion", "generation", "managedFields"]:
            metadata.pop(field, None)
        candidate.pop("status", None)
        annotations = metadata["annotations"]
        required_scc = expected["metadata"]["annotations"]["openshift.io/required-scc"]
        for key, value in {"openshift.io/scc": required_scc,
                           "security.openshift.io/validated-scc-subject-type": "user",
                           "seccomp.security.alpha.kubernetes.io/pod": "runtime/default"}.items():
            if annotations.pop(key, None) != value:
                raise ValueError()
        if "saw.redhat.com/storage-lab-stage" in annotations:
            if annotations.pop("saw.redhat.com/storage-lab-stage") != "reserved-no-vm":
                raise ValueError()
        # Pinned peer-pod webhook: aggregate limits (CPU falls back to requests),
        # record guest sizing, remove container resources, allocate one PodVM.
        expected["metadata"]["annotations"].update({
            "io.katacontainers.config.hypervisor.default_memory": "1536",
            "io.katacontainers.config.hypervisor.default_vcpus": "1"})
        for i, container in enumerate(expected["spec"]["containers"]):
            container["resources"] = {"limits": {"kata.peerpods.io/vm": "1"}, "requests": {"kata.peerpods.io/vm": "1"}} if i == 0 else {}
        actual = candidate["spec"]
        for key, value in {"serviceAccount": "storage-guest", "dnsPolicy": "ClusterFirst",
                           "schedulerName": "default-scheduler", "priority": 0,
                           "preemptionPolicy": "PreemptLowerPriority"}.items():
            if actual.pop(key, None) != value:
                raise ValueError()
        if actual.pop("imagePullSecrets", []) != refs or actual.pop("overhead", {}) != rc["overhead"]:
            raise ValueError()
        tolerations = actual.pop("tolerations", [])
        known = [{"effect": "NoExecute", "key": "node.kubernetes.io/not-ready", "operator": "Exists", "tolerationSeconds": 300},
                 {"effect": "NoExecute", "key": "node.kubernetes.io/unreachable", "operator": "Exists", "tolerationSeconds": 300},
                 {"effect": "NoSchedule", "key": "node.kubernetes.io/memory-pressure", "operator": "Exists"}]
        if sorted(json.dumps(x, sort_keys=True) for x in tolerations) != sorted(json.dumps(x, sort_keys=True) for x in known):
            raise ValueError()
        for key, value in rc["nodeSelector"].items():
            if key in expected["spec"]["nodeSelector"] and expected["spec"]["nodeSelector"][key] != value:
                raise ValueError()
            expected["spec"]["nodeSelector"][key] = value
        expected["spec"]["securityContext"]["seccompProfile"] = {"type": "RuntimeDefault"}
        for container in actual["containers"]:
            if container.pop("terminationMessagePath", None) != "/dev/termination-log" or container.pop("terminationMessagePolicy", None) != "File":
                raise ValueError()
            container.setdefault("env", [])
            for env in container["env"]:
                if "valueFrom" in env and "fieldRef" in env["valueFrom"]:
                    if env["valueFrom"]["fieldRef"].pop("apiVersion", None) != "v1":
                        raise ValueError()
        projection = actual["volumes"][-1]["projected"]["sources"][-1]["downwardAPI"]["items"][0]["fieldRef"]
        if projection.pop("apiVersion", None) != "v1":
            raise ValueError()
        if json.dumps(candidate, sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise ValueError()
        return candidate
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        raise ContractError("LabGuestAdmissionRejected") from None


def generator_input(pod, site, *, admission_context=None):
    """Remove API-only controls. Preserve all guest security and mount fields."""
    result = validate(pod, site) if admission_context is None else admitted_input(pod, site, admission_context)
    for key in ["schedulingGates", "activeDeadlineSeconds", "automountServiceAccountToken", "enableServiceLinks"]:
        del result["spec"][key]
    if "seccompProfile" in result["spec"]["securityContext"]:
        # Every role already declares its exact profile; remove only the
        # equivalent inherited API default unsupported by this parser.
        if any("seccompProfile" not in c["securityContext"] for c in result["spec"]["containers"]):
            raise ContractError("LabGuestContractRejected")
        del result["spec"]["securityContext"]["seccompProfile"]
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


def _attestation_module():
    """Use the production constants and compiler. Do not copy them."""
    spec = importlib.util.spec_from_file_location("lab_canonical_attestation", Path(__file__).resolve().parents[1] / "kubernetes-runtime/saw_kubernetes/attestation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def launch_input(pod, site, context, expected_sha256):
    """Require the canonical measured init-data annotation before gate release."""
    try:
        if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
            raise ValueError()
        candidate = copy.deepcopy(pod)
        annotations = candidate["metadata"]["annotations"]
        key = _attestation_module().ANNOTATION
        if {k for k in annotations if k.endswith("cc_init_data")} != {key}:
            raise ValueError()
        encoded = annotations.pop(key)
        if not isinstance(encoded, str) or len(encoded) > 200_000:
            raise ValueError()
        compressed = base64.b64decode(encoded, validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            raw = stream.read(512 * 1024 + 1)
        if len(raw) > 512 * 1024 or hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise ValueError()
        return admitted_input(candidate, site, context)
    except (ValueError, TypeError, KeyError, AttributeError, OSError, EOFError):
        raise ContractError("LabInitdataAnnotationRejected") from None


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
BASE_ENV_SHA256 = 'e13a8b9ce2da83fe5d731877149240cc230b63d448299a856196e4bc59ee9c0f'


def _crio_guest_layout(data, gid):
    """Bind the reviewed CRI-O local volumes and privileged guest fields."""
    local_volumes = {"azure-disk-helper": {"/csi": "socket", "/tmp": "tmp"},
                     "volume-wrapper": {"/csi": "socket"}}
    for container in data["containers"]:
        oci = container["OCI"]
        name = oci["Annotations"].get("io.kubernetes.cri.container-name")
        volumes = local_volumes.get(name)
        if not volumes:
            continue
        original = {"driver": "", "driver_options": ["encryption_key=ephemeral"],
                    "fs_group": {"group_change_policy": 0, "group_id": gid},
                    "fstype": "ext4", "mount_point": "$(spath)/$(b64_device_id)",
                    "options": [], "shared": True, "source": ""}
        if container["storages"] != [original] * len(volumes):
            raise ValueError()
        container["storages"] = []
        for mount in oci["Mounts"]:
            volume = volumes.get(mount["destination"])
            if volume is None:
                continue
            source = "^/run/kata-containers/shared/containers/$(sandbox-id)/rootfs/local/" + volume + "$"
            mount.update(type_="local", source=source)
            container["storages"].append({"driver": "local", "driver_options": [],
                "fs_group": None, "fstype": "local", "mount_point": source,
                "options": ["mode=0777", "fsgid=" + str(gid)],
                "shared": False, "source": "local"})
        if len(container["storages"]) != len(volumes):
            raise ValueError()
        if name != "azure-disk-helper":
            continue
        # CRI-O applies all capabilities to this explicitly privileged role.
        # The host runtime must keep privileged_without_host_devices enabled.
        oci["Process"]["Capabilities"] = {key: ["$(privileged_caps)"]
                                            for key in oci["Process"]["Capabilities"]}
        options = {
            "/proc": ["nosuid", "noexec", "nodev", "rw"],
            "/dev": ["nosuid", "strictatime", "mode=755", "size=65536k", "rw"],
            "/dev/pts": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5", "rw"],
            "/dev/mqueue": ["nosuid", "noexec", "nodev", "rw"],
            "/sys": ["nosuid", "noexec", "nodev", "rw", "rslave"],
            "/sys/fs/cgroup": ["nosuid", "noexec", "nodev", "rw", "relatime", "rslave"],
            "/etc/resolv.conf": ["bind", "nodev", "nosuid", "noexec", "rw"],
            "/etc/hostname": ["bind", "rw"],
            "/run/.containerenv": ["bind", "rw"],
        }
        for mount in oci["Mounts"]:
            if mount["destination"] in options:
                mount["options"] = options[mount["destination"]]


def compile_policy(pod, site, generated, runtime_profile, *, admission_context=None):
    """Compile only the closed lab preview. Never enables SAW enrollment."""
    normalized = generator_input(pod, site, admission_context=admission_context)
    a = _attestation_module()
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
            # OpenShift injects public build labels as image environment. Keep
            # their exact values in the measured policy, but permit a new build
            # without accepting any change to executable environment variables.
            build_keys = {"OPENSHIFT_BUILD_NAME", "OPENSHIFT_BUILD_NAMESPACE"}
            build_env = [v for v in base_env if v.split("=", 1)[0] in build_keys]
            if (len(build_env) != 2 or {v.split("=", 1)[0] for v in build_env} != build_keys
                    or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", v.split("=", 1)[1]) for v in build_env)):
                raise ValueError()
            if a.digest([v for v in base_env if v.split("=", 1)[0] not in build_keys]) != BASE_ENV_SHA256:
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
        # CRI-O marks the infra container privileged when this reviewed Pod
        # contains the privileged disk helper. Child OCI annotations omit it.
        identity_privilege = '    object.get(a, "io.kubernetes.cri-o.PrivilegedRuntime", "false") == "false"'
        sandbox_privilege = '    a["io.kubernetes.cri-o.PrivilegedRuntime"] == "false"'
        if rules.count(identity_privilege) != 1 or rules.count(sandbox_privilege) != 1:
            raise ValueError()
        rules = rules.replace(identity_privilege, "    saw_storage_lab_privilege_context(a)")
        rules = rules.replace(sandbox_privilege, '    a["io.kubernetes.cri-o.PrivilegedRuntime"] == "true"')
        rules += '\n\nsaw_storage_lab_privilege_context(a) if {\n    a["io.kubernetes.cri-o.ContainerType"] == "sandbox"\n    a["io.kubernetes.cri-o.PrivilegedRuntime"] == "true"\n}\n\nsaw_storage_lab_privilege_context(a) if {\n    a["io.kubernetes.cri-o.ContainerType"] == "container"\n    object.get(a, "io.kubernetes.cri-o.PrivilegedRuntime", "false") == "false"\n}\n'
        rules += '\n\nsaw_storage_lab_identity if {\n    input.OCI.Annotations["io.kubernetes.pod.uid"] == policy_data.saw_storage_lab.podUID\n}\n'
        propagation_check = "    count(i_linux.RootfsPropagation) == 0"
        if rules.count(propagation_check) != 1:
            raise ValueError()
        rules = rules.replace(propagation_check, "    saw_storage_lab_propagation(i_oci)")
        rules += '\n\nsaw_storage_lab_propagation(oci) if {\n    oci.Annotations["io.kubernetes.cri.container-type"] == "sandbox"\n    count(oci.Linux.RootfsPropagation) == 0\n}\n\nsaw_storage_lab_propagation(oci) if {\n    oci.Annotations["io.kubernetes.cri.container-type"] == "container"\n    name := oci.Annotations["io.kubernetes.cri.container-name"]\n    oci.Linux.RootfsPropagation == policy_data.saw_storage_lab.roles[name].rootfsPropagation\n}\n'
        label_check = "    count(i_linux.MountLabel) == 0"
        if rules.count(label_check) != 1:
            raise ValueError()
        rules = rules.replace(label_check, "    saw_storage_lab_mount_label(i_oci)")
        # The host-generated MCS label is not a workspace identity claim.
        # Permit its bounded format only on the approved privileged role.
        rules += r'''

saw_storage_lab_mount_label(oci) if {
    oci.Linux.MountLabel == ""
}

saw_storage_lab_mount_label(oci) if {
    oci.Annotations["io.kubernetes.cri.container-type"] == "container"
    oci.Annotations["io.kubernetes.cri.container-name"] == "azure-disk-helper"
    label := oci.Linux.MountLabel
    regex.match("^system_u:object_r:container_file_t:s0:c[0-9]{1,4},c[0-9]{1,4}$", label)
    categories := split(trim_prefix(label, "system_u:object_r:container_file_t:s0:c"), ",c")
    low := to_number(categories[0])
    high := to_number(categories[1])
    low < high
    high <= 1023
}
'''
        converted_data = json.loads(encoded.replace(a.IDENTITY_MARKER, "null"))
        converted_data["saw_storage_lab"] = {"podUID": site["podUID"], "roles": roles, "originalPodSHA256": a.digest(pod), "previewOnly": admission_context is None, "admissionContextSHA256": a.digest(admission_context)}
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
        _crio_guest_layout(converted_data, site["applicationUID"])
        converted_data["saw_identity"] = a.IDENTITY_MARKER
        return rules + "\n\npolicy_data := " + a.canonical(converted_data).replace(json.dumps(a.IDENTITY_MARKER), a.IDENTITY_MARKER) + "\n"
    except (ValueError, KeyError, TypeError, IndexError, AttributeError):
        raise ContractError("LabGuestPolicyRejected") from None
