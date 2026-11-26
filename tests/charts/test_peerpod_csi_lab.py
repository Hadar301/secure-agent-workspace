"""The lab component must not share managed driver identities or credentials."""
import hashlib
import json
import subprocess
from pathlib import Path
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts/saw-peerpod-csi-lab"
REG = "0123456789abcdef"
NS = "saw-ppvc-" + REG


def values():
    result = yaml.safe_load((CHART / "values.yaml").read_text())
    result.update(enabled=True, registration=REG, nodeName="lab-worker", region="labregion", resourceGroup="lab-resource-group", apiServerCIDRs=["192.0.2.10/32"])
    result["images"] = {key: "registry.example.test/lab/" + key + "@sha256:" + str(i + 1) * 64 for i, key in enumerate(result["images"])}
    return result


def render(tmp_path, config=None, namespace=NS):
    path = tmp_path / "values.json"
    path.write_text(json.dumps(config if config is not None else values()))
    return subprocess.run(["helm", "template", namespace, str(CHART), "--namespace", namespace, "-f", str(path)], text=True, capture_output=True)


def docs(result):
    assert result.returncode == 0, result.stderr
    return [item for item in yaml.safe_load_all(result.stdout) if item]


def test_default_starts_nothing(tmp_path):
    config = yaml.safe_load((CHART / "values.yaml").read_text())
    assert docs(render(tmp_path, config)) == []


def test_inactive_resources_are_separate_and_credential_free(tmp_path):
    resources = docs(render(tmp_path))
    driver = next(x for x in resources if x["kind"] == "CSIDriver")
    assert driver["metadata"]["name"] == NS + ".disk.csi.saw.redhat.com"
    assert len(driver["metadata"]["name"]) <= 63
    storage = next(x for x in resources if x["kind"] == "StorageClass")
    assert storage["provisioner"] == driver["metadata"]["name"]
    assert storage["reclaimPolicy"] == "Retain"
    assert not storage["metadata"].get("annotations")
    assert not any(x["kind"] in {"Secret", "PersistentVolumeClaim", "Pod", "VirtualMachine"} for x in resources)
    for role in [x for x in resources if x["kind"] in {"Role", "ClusterRole"}]:
        assert all("secrets" not in rule["resources"] and "*" not in rule["resources"] for rule in role["rules"])
    controller = next(x for x in resources if x["kind"] == "Deployment")
    assert controller["spec"]["replicas"] == 0
    node = next(x for x in resources if x["kind"] == "DaemonSet")
    spec = node["spec"]["template"]["spec"]
    assert spec["nodeSelector"] == {"kubernetes.io/hostname": "lab-worker", "saw.redhat.com/storage-lab-disabled": REG}
    socket = next(x for x in spec["volumes"] if x["name"] == "socket")
    assert socket["hostPath"]["path"] == "/var/lib/kubelet/plugins/" + driver["metadata"]["name"]
    assert not any("/plugins/disk.csi.azure.com" in json.dumps(x) for x in resources)
    for item in resources:
        if item["kind"] not in {"Deployment", "DaemonSet"}:
            continue
        for container in item["spec"]["template"]["spec"]["containers"]:
            assert "@sha256:" in container["image"]


@pytest.mark.parametrize("field,bad,reason", [
    ("registration", "bad-registration", "LabRegistrationRejected"),
    ("nodeName", "*", "LabNodeRejected"),
    ("wrapperPatchSHA256", "0" * 64, "LabWrapperPatchRejected"),
    ("cloudConfigSecret", "*", "LabCloudConfigReferenceRejected"),
])
def test_rejects_unsafe_inputs(tmp_path, field, bad, reason):
    config = values()
    config[field] = bad
    result = render(tmp_path, config)
    assert result.returncode != 0
    assert reason in result.stderr


def test_requires_pin_without_exposing_input(tmp_path):
    config = values()
    config["images"]["wrapper"] = "registry.example.test/do-not-expose:latest"
    result = render(tmp_path, config)
    assert result.returncode != 0
    assert "LabImagePinRequired" in result.stderr
    assert "do-not-expose" not in result.stderr


def test_rejects_foreign_namespace_and_embedded_keys(tmp_path):
    result = render(tmp_path, namespace="foreign-namespace")
    assert result.returncode != 0 and "LabNamespaceRejected" in result.stderr
    config = values()
    config["api_key"] = "do-not-expose"
    result = render(tmp_path, config)
    assert result.returncode != 0 and "do-not-expose" not in result.stderr


def test_activation_requires_host_review(tmp_path):
    config = values()
    config["activate"] = True
    config["acknowledgeGuestKubeletMarker"] = True
    config["enforceGuards"] = True
    result = render(tmp_path, config)
    assert result.returncode != 0 and "LabHostAccessReviewRequired" in result.stderr
    config["acknowledgePrivilegedNodeAccess"] = True
    resources = docs(render(tmp_path, config))
    controller = next(x for x in resources if x["kind"] == "Deployment")
    assert controller["spec"]["replicas"] == 1
    node = next(x for x in resources if x["kind"] == "DaemonSet")
    assert node["spec"]["template"]["spec"]["nodeSelector"] == {"kubernetes.io/hostname": "lab-worker"}


def test_guards_bind_only_the_lab_accounts_and_alias(tmp_path):
    resources = docs(render(tmp_path))
    policies = {x["metadata"]["name"]: x for x in resources if x["kind"] == "ValidatingAdmissionPolicy"}
    assert len(policies) == 4
    assert all(x["spec"]["failurePolicy"] == "Fail" for x in policies.values())
    guest = policies[NS + "-guest-records"]
    assert "authentication.kubernetes.io/pod-uid" in guest["spec"]["validations"][0]["expression"]
    protected = " ".join(x["expression"] for x in guest["spec"]["validations"])
    for field in ["volumeID", "vmID", "targetPath", "wrapperControllerPublishVolumeReq", "wrapperNodeStageVolumeReq"]:
        assert "oldObject.spec." + field in protected
    bindings = [x for x in resources if x["kind"] == "RoleBinding" and x["metadata"]["name"] == "guest-volume-records"]
    assert bindings[0]["metadata"]["namespace"] == NS
    assert bindings[0]["subjects"][0]["namespace"] == "saw-ppvc-probe-" + REG


def test_lock_and_cleanup_schema_match_source():
    base = ROOT / "deploy/confidential/lab-storage"
    lock = yaml.safe_load((base / "source-lock.yaml").read_text())
    assert lock["status"] == "experimental-unqualified"
    assert lock["qualified"]["realCredentialUseAllowed"] is False
    for field, name in [("patchSHA256", "csi-wrapper-isolation.patch"), ("testsSHA256", "lab_isolation_test.go"), ("monitorTestsSHA256", "monitor_scope_test.go"), ("crdSHA256", "peerpodvolumes.yaml"), ("containerfileSHA256", "Containerfile")]:
        assert lock["wrapper"][field] == hashlib.sha256((base / name).read_bytes()).hexdigest()
    defaults = yaml.safe_load((CHART / "values.yaml").read_text())
    assert defaults["wrapperPatchSHA256"] == lock["wrapper"]["patchSHA256"]
    crd = yaml.safe_load((base / "peerpodvolumes.yaml").read_text())
    fields = crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]
    assert fields["wrapperNodeUnpublishVolumeReq"]["type"] == "string"
    assert fields["wrapperNodeUnstageVolumeReq"]["type"] == "string"


def test_guard_bindings_are_a_separate_inactive_stage(tmp_path):
    config = values()
    assert not any(x["kind"] == "ValidatingAdmissionPolicyBinding" for x in docs(render(tmp_path, config)))
    config["enforceGuards"] = True
    resources = docs(render(tmp_path, config))
    assert len([x for x in resources if x["kind"] == "ValidatingAdmissionPolicyBinding"]) == 4
    assert next(x for x in resources if x["kind"] == "Deployment")["spec"]["replicas"] == 0
    config["activate"] = True
    config["acknowledgeGuestKubeletMarker"] = True
    config["enforceGuards"] = False
    result = render(tmp_path, config)
    assert result.returncode != 0 and "LabAdmissionGuardsRequired" in result.stderr


def test_api_targets_required_and_network_is_confined(tmp_path):
    config = values()
    config["apiServerCIDRs"] = []
    result = render(tmp_path, config)
    assert result.returncode != 0 and "LabApiTargetsRequired" in result.stderr
    resources = docs(render(tmp_path))
    firewall = next(x for x in resources if x["kind"] == "EgressFirewall")
    assert firewall["metadata"]["namespace"] == NS
    assert {x["to"]["dnsName"] for x in firewall["spec"]["egress"] if "dnsName" in x["to"]} == {"management.azure.com", "login.microsoftonline.com"}
    assert firewall["spec"]["egress"][-1]["type"] == "Deny"
    guest_deny = next(x for x in resources if x["kind"] == "NetworkPolicy" and x["metadata"]["namespace"] == "saw-ppvc-probe-" + REG)
    assert guest_deny["spec"]["egress"] == []


def test_marker_requires_review_and_namespace_survives_uninstall(tmp_path):
    config = values()
    config.update(activate=True, enforceGuards=True, acknowledgePrivilegedNodeAccess=True)
    result = render(tmp_path, config)
    assert result.returncode != 0 and "LabHelperMarkerReviewRequired" in result.stderr
    config["acknowledgeGuestKubeletMarker"] = True
    resources = docs(render(tmp_path, config))
    for item in resources:
        if item["kind"] == "Namespace":
            assert item["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    node = next(x for x in resources if x["kind"] == "DaemonSet")
    marker = node["spec"]["template"]["spec"]["initContainers"][0]
    assert marker["command"] == ["/saw-lab-marker"]
    assert marker["volumeMounts"] == [{"name": "direct-volumes", "mountPath": "/host/direct-volumes"}]
    base = ROOT / "deploy/confidential/lab-storage"
    lock = yaml.safe_load((base / "source-lock.yaml").read_text())
    for field, name in [("sourceSHA256", "main.go"), ("testsSHA256", "main_test.go")]:
        assert lock["helperMarker"][field] == hashlib.sha256((base / "marker" / name).read_bytes()).hexdigest()
    assert lock["helperMarker"]["perWorkerOwnerLimit"] == 1


def test_internal_image_pull_grant_is_explicit_and_limited(tmp_path):
    config = values()
    assert not any(x["kind"] == "RoleBinding" and x["metadata"]["name"].endswith("-image-pull") for x in docs(render(tmp_path, config)))
    config["wrapperBuildNamespace"] = "saw-lab-build"
    resources = docs(render(tmp_path, config))
    binding = next(x for x in resources if x["kind"] == "RoleBinding" and x["metadata"]["name"].endswith("-image-pull"))
    assert binding["metadata"]["namespace"] == "saw-lab-build"
    assert binding["roleRef"]["name"] == "system:image-puller"
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": name, "namespace": NS} for name in ["controller", "node"]]
    controller = next(x for x in resources if x["kind"] == "Deployment")
    assert controller["spec"]["template"]["spec"]["securityContext"]["fsGroup"] == 65532
    config["wrapperBuildNamespace"] = "foreign-build"
    result = render(tmp_path, config)
    assert result.returncode != 0 and "LabBuildNamespaceRejected" in result.stderr


def test_node_socket_clients_can_connect_without_credential_mount(tmp_path):
    node = next(x for x in docs(render(tmp_path)) if x["kind"] == "DaemonSet")
    containers = {x["name"]: x for x in node["spec"]["template"]["spec"]["containers"]}
    owner_uid = containers["wrapper"]["securityContext"]["runAsUser"]
    for name in ["registrar", "liveness"]:
        assert containers[name]["securityContext"]["runAsUser"] == owner_uid
    probe = containers["liveness"]
    assert probe["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert probe["securityContext"]["allowPrivilegeEscalation"] is False
    assert {x["name"] for x in probe["volumeMounts"]} == {"socket"}
