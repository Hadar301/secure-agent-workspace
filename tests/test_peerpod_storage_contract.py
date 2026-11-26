"""Negative tests for the isolated guest's security boundary."""
import copy
import importlib.util
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lab_contract", ROOT / "scripts/peerpod_storage_contract.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


@pytest.fixture
def site():
    return {"registration": "0123456789abcdef", "nodeName": "lab-worker", "runtimeClass": "lab-confidential", "image": "registry.example.test/lab/helper@sha256:" + "1" * 64, "claimName": "public-work", "podUID": "01234567-89ab-4cde-8fab-0123456789ab", "pvName": "pvc-public-work", "apiAudience": "https://kubernetes.default.svc", "apiHost": "192.0.2.10", "apiPort": 443, "applicationUID": 65534}


@pytest.mark.parametrize("path,value", [
    (("spec", "containers", 0, "image"), "registry.example.test/foreign:latest"),
    (("spec", "containers", 0, "args"), ["id"]),
    (("spec", "containers", 1, "env"), [{"name": "API_KEY", "value": "test-only"}]),
    (("spec", "containers", 2, "securityContext", "runAsUser"), 0),
    (("spec", "containers", 2, "securityContext", "privileged"), True),
    (("spec", "containers", 1, "volumeMounts", 1, "readOnly"), False),
    (("spec", "volumes", 0, "hostPath", "path"), "/"),
    (("spec", "volumes", 3, "persistentVolumeClaim", "claimName"), "foreign-work"),
    (("spec", "volumes", 4, "projected", "sources", 0, "serviceAccountToken", "audience"), "foreign-audience"),
    (("spec", "serviceAccountName"), "builder"),
    (("spec", "runtimeClassName"), "default"),
    (("spec", "automountServiceAccountToken"), True),
    (("metadata", "namespace"), "foreign-namespace"),
])
def test_rejects_changes_to_identity_privilege_or_mounts(site, path, value):
    pod = M.build(site)
    target = pod
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(M.ContractError, match="^LabGuestContractRejected$"):
        M.validate(pod, site)


def test_rejects_undeclared_fields_and_secret_inputs(site):
    pod = M.build(site)
    pod["spec"]["containers"][1]["envFrom"] = [{"secretRef": {"name": "unused"}}]
    with pytest.raises(M.ContractError):
        M.validate(pod, site)
    with pytest.raises(M.ContractError):
        M.build(dict(site, api_key="test-only"))


def test_generator_keeps_authority_and_original_is_unchanged(site):
    original = M.build(site)
    snapshot = copy.deepcopy(original)
    generated = M.generator_input(original, site)
    assert original == snapshot
    expected = copy.deepcopy(original["spec"]["containers"])
    for container in expected:
        del container["securityContext"]["runAsNonRoot"]
    resolved = {"metadata.name": original["metadata"]["name"], "metadata.namespace": original["metadata"]["namespace"], "metadata.uid": site["podUID"], "spec.nodeName": site["nodeName"]}
    for container in expected:
        for env in container["env"]:
            if "valueFrom" in env:
                env["value"] = resolved[env.pop("valueFrom")["fieldRef"]["fieldPath"]]
    assert generated["spec"]["containers"] == expected
    assert [c["securityContext"]["runAsUser"] for c in generated["spec"]["containers"]] == [0, 0, 65534]
    expected_volumes = copy.deepcopy(original["spec"]["volumes"])
    del expected_volumes[-1]["projected"]["sources"]
    assert generated["spec"]["volumes"] == expected_volumes
    assert original["spec"]["volumes"][-1]["projected"]["sources"][0]["serviceAccountToken"]["audience"] == site["apiAudience"]
    assert generated["spec"]["containers"][0]["securityContext"]["privileged"] is True
    assert generated["spec"]["containers"][0]["volumeMounts"][0]["mountPropagation"] == "Bidirectional"
    assert "schedulingGates" not in generated["spec"]


def test_normal_production_contract_still_rejects_guest_helper(site):
    spec = importlib.util.spec_from_file_location("production_attestation", ROOT / "kubernetes-runtime/saw_kubernetes/attestation.py")
    production = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(production)
    with pytest.raises(production.AttestationError):
        production.launch_policy_input(M.build(site))


@pytest.fixture
def generated():
    import json
    prefix = (ROOT / "tests/fixtures/confidential/osc-1.13-rules.rego").read_text().rstrip()
    data = json.loads((ROOT / "tests/fixtures/confidential/peerpod-lab-generator-data.json").read_text())
    return prefix, data


def compiled(site, generated):
    import json
    prefix, data = generated
    return M.compile_policy(M.build(site), site, prefix + "\n\npolicy_data := " + json.dumps(data), {"name": "crio-1.35-oci-1.3.0-v1", "pauseImage": "registry.example.test/infra@sha256:" + "b" * 64})


def test_lab_template_cannot_enter_normal_enrollment(site, generated):
    import json
    template = compiled(site, generated)
    spec = importlib.util.spec_from_file_location("production", ROOT / "kubernetes-runtime/saw_kubernetes/attestation.py")
    production = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(production)
    with pytest.raises((production.AttestationError, ValueError)):
        production._crio_module().source_template(template)
    data = json.loads(template.split("\n\npolicy_data := ", 1)[1].replace(production.IDENTITY_MARKER, "null"))
    for container in data["containers"][1:]:
        name = container["OCI"]["Annotations"]["io.kubernetes.cri.container-name"]
        mounts = [m for m in container["OCI"]["Mounts"] if m["destination"] == "/var/run/secrets/kubernetes.io/serviceaccount"]
        assert bool(mounts) == (name == "volume-wrapper")


@pytest.mark.parametrize("change", ["command", "uid", "capabilities", "mount", "linux", "environment", "defaults", "foreign-role"])
def test_compiler_rejects_changed_generator_authority(site, generated, change):
    prefix, source = generated
    data = copy.deepcopy(source)
    oci = data["containers"][1]["OCI"]
    if change == "command":
        oci["Process"]["Args"] = ["/bin/sh"]
    elif change == "uid":
        oci["Process"]["User"]["UID"] = 1000
    elif change == "capabilities":
        oci["Process"]["Capabilities"]["Ambient"] = ["CAP_SYS_ADMIN"]
    elif change == "mount":
        oci["Mounts"][0]["source"] = "/etc/shadow"
    elif change == "linux":
        oci["Linux"]["Devices"] = [{"Path": "/dev/foreign"}]
    elif change == "environment":
        oci["Process"]["Env"].append("LD_PRELOAD=/tmp/foreign.so")
    elif change == "defaults":
        data["request_defaults"]["SetPolicyRequest"] = True
    else:
        oci["Annotations"]["io.kubernetes.cri.container-name"] = "foreign-role"
    import json
    with pytest.raises(M.ContractError, match="^LabGuestPolicyRejected$"):
        compiled(site, (prefix, data))


def opa_query(tmp_path, site, generated, request, query):
    import json, shutil, subprocess
    opa = shutil.which("opa")
    if not opa:
        pytest.skip("OPA is required for executable lab policy tests")
    policy = tmp_path / "lab.rego"
    policy.write_text(compiled(site, generated).replace("__SAW_IDENTITY_JSON__", json.dumps({"owner": "lab", "registration": site["registration"]})))
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps(request))
    result = subprocess.run([opa, "eval", "--format=json", "-d", str(policy), "-i", str(input_file), query], capture_output=True, text=True, check=True)
    document = json.loads(result.stdout)
    return document["result"][0]["expressions"][0]["value"] if document.get("result") else False


@pytest.mark.parametrize("name,uid,nnp,allowed", [
    ("azure-disk-helper", 0, False, True),
    ("volume-wrapper", 0, True, True),
    ("mount-check", 65534, True, True),
    ("mount-check", 0, True, False),
    ("volume-wrapper", 0, False, False),
    ("foreign-role", 0, False, False),
])
def test_runtime_authority_is_bound_to_role(tmp_path, site, generated, name, uid, nnp, allowed):
    import json
    annotations = {"io.kubernetes.cri-o.ContainerType": "container", "io.katacontainers.pkg.oci.container_type": "pod_container", "io.kubernetes.container.name": name, "io.kubernetes.cri-o.ImageName": site["image"], "io.kubernetes.cri-o.Metadata": json.dumps({"name": name})}
    request = {"OCI": {"Annotations": annotations, "Process": {"User": {"UID": uid}, "NoNewPrivileges": nnp}}}
    assert opa_query(tmp_path, site, generated, request, "data.agent_policy.saw_crio_kind(input.OCI.Annotations)") is allowed


@pytest.mark.parametrize("foreign", [False, True])
def test_runtime_registration_uses_exact_pod_uid(tmp_path, site, generated, foreign):
    request = {"OCI": {"Annotations": {"io.kubernetes.pod.uid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" if foreign else site["podUID"]}}}
    assert opa_query(tmp_path, site, generated, request, "data.agent_policy.saw_storage_lab_identity") is (not foreign)


@pytest.mark.parametrize("name,propagation,allowed", [
    ("azure-disk-helper", "rshared", True),
    ("azure-disk-helper", "", False),
    ("volume-wrapper", "", True),
    ("volume-wrapper", "rshared", False),
    ("mount-check", "rslave", True),
    ("mount-check", "rshared", False),
    ("foreign-role", "rshared", False),
])
def test_propagation_is_limited_to_its_role(tmp_path, site, generated, name, propagation, allowed):
    request = {"OCI": {"Annotations": {"io.kubernetes.cri.container-type": "container", "io.kubernetes.cri.container-name": name}, "Linux": {"RootfsPropagation": propagation}}}
    assert opa_query(tmp_path, site, generated, request, "data.agent_policy.saw_storage_lab_propagation(input.OCI)") is allowed


def test_boolean_fields_reject_numeric_substitutes(site):
    pod = M.build(site)
    pod["spec"]["containers"][0]["securityContext"]["privileged"] = 1
    with pytest.raises(M.ContractError):
        M.validate(pod, site)


@pytest.mark.parametrize("change", [None, "foreign-pod", "foreign-disk", "wrong-mode", "extra-destination"])
def test_direct_mount_source_is_exact(tmp_path, site, generated, change):
    source = "/var/lib/kubelet/pods/" + site["podUID"] + "/volumes/kubernetes.io~csi/" + site["pvName"] + "/mount"
    mount = {"destination": "/work", "source": source, "type_": "bind", "options": ["rbind", "rslave", "rw", "bind"]}
    if change == "foreign-pod":
        mount["source"] = source.replace(site["podUID"], "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    elif change == "foreign-disk":
        mount["source"] = source.replace(site["pvName"], "foreign-disk")
    elif change == "wrong-mode":
        mount["options"][1] = "rshared"
    mounts = [mount, copy.deepcopy(mount)] if change == "extra-destination" else [mount]
    request = {"OCI": {"Annotations": {"io.kubernetes.cri-o.ContainerType": "container", "io.kubernetes.container.name": "mount-check"}, "Mounts": mounts}}
    assert opa_query(tmp_path, site, generated, request, "data.agent_policy.saw_storage_lab_mounts") is (change is None)


@pytest.mark.parametrize("request_name", ["ExecProcessRequest", "SetPolicyRequest", "ReadStreamRequest", "WriteStreamRequest", "GetDiagnosticDataRequest"])
def test_lab_keeps_host_control_and_diagnostics_denied(tmp_path, site, generated, request_name):
    assert opa_query(tmp_path, site, generated, {}, "data.agent_policy." + request_name) is False


def test_contract_source_lock_and_fixture_are_portable():
    import hashlib, yaml
    lock = yaml.safe_load((ROOT / "deploy/confidential/lab-storage/source-lock.yaml").read_text())["guestPolicy"]
    assert lock["contractSHA256"] == hashlib.sha256((ROOT / lock["contractSource"]).read_bytes()).hexdigest()
    assert lock["canonicalRuntimeAdapterSHA256"] == hashlib.sha256((ROOT / lock["canonicalRuntimeAdapter"]).read_bytes()).hexdigest()
    assert lock["productionEnrollmentEnabled"] is False
    assert lock["liveGuestAccepted"] is False
    import json
    fixture = json.loads((ROOT / "tests/fixtures/confidential/peerpod-lab-generator-data.json").read_text())
    for container in fixture["containers"]:
        annotations = container["OCI"]["Annotations"]
        assert annotations["io.kubernetes.cri.sandbox-namespace"] == "saw-ppvc-probe-0123456789abcdef"
        if annotations["io.kubernetes.cri.container-type"] == "container":
            assert annotations["io.kubernetes.cri.image-name"].startswith("registry.example.test/")
