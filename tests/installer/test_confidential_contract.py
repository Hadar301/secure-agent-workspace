"""Confidential contracts use public, cluster-independent fixtures only."""
import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tomllib
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from urllib.error import HTTPError

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kubernetes-runtime"))
from saw_kubernetes.compiler import ContractError, compile_profile_files
from saw_kubernetes.boundary import (BoundaryError, approval_fingerprint,
                                     objects as boundary_objects, verify_confidential_plan)
spec = importlib.util.spec_from_file_location("attestation", ROOT/"kubernetes-runtime/saw_kubernetes/attestation.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
artifact_spec = importlib.util.spec_from_file_location(
    "confidential_artifacts", ROOT/"scripts/confidential-artifacts.py")
artifacts = importlib.util.module_from_spec(artifact_spec)
artifact_spec.loader.exec_module(artifacts)
UID = "11111111-1111-4111-8111-111111111111"
IMAGE = "registry.example.test/supervisor@sha256:" + "a"*64

def trustee_reference_values(tee):
    values = {}
    for index, suffix in enumerate(sorted(a.REFERENCE_VALUE_NAMES), start=1):
        name = f"{tee}_{suffix}"
        entry = {"name": name, "expiration": "2099-12-31T00:00:00Z",
                 "value": [format(index, "x") * 64]}
        values[name] = base64.b64encode(
            json.dumps(entry, separators=(",", ":")).encode()).decode()
    return values

@pytest.fixture
def approved():
    policy = a.KATA_AGENT_POLICY_TEMPLATE
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"trustee.example.test")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
        .sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
    reference_values = trustee_reference_values("snp")
    cfg = dict(enabled=True, schemaVersion=1, tee="snp", kbsURL="https://trustee.example.test",
               kbsCA=certificate,
               policyDigest=hashlib.sha256(policy.encode()).hexdigest(),
               referenceSet=a.digest(reference_values),
               guestPolicy=policy, imagePolicy={"default":[{"type":"reject"}],"transports":{"docker":{
                   "registry.example.test":[{"type":"sigstoreSigned","keyPath":"/etc/pki/public.pem"}]}}},
               driver=dict(capability=a.CAPABILITY,sourceRevision="c"*40,gatewayImage=IMAGE,supervisorImage=IMAGE))
    attestation_policy_data = {"policy.rego": "package policy\ndefault allow := false\n"}
    resource_policy_data = {"resource-policy.rego": "package policy\ndefault allow := false\n"}
    objects = {
        "peerPods": {"data":{"CLOUD_PROVIDER":"azure","DISABLECVM":"false","AZURE_IMAGE_ID":"reviewed-image","AZURE_INSTANCE_SIZE":"Standard_DC4as_v5"}},
        "trustee":{"spec":{"replicas":1},"status":{"observedGeneration":1,"availableReplicas":1,"updatedReplicas":1}},
        "trusteeConfig":{"spec":{"kbsSecretResources":["saw-bob-fedcba9876543210"]}},
        "attestationPolicy":{"data":attestation_policy_data},
        "resourcePolicy":{"data":resource_policy_data},
        "referenceValues":{"data":{"reference_value":json.dumps(reference_values,indent=2)}},
        "qualification":{"data":{"capability":a.CAPABILITY,"tee":"snp","gatewayImage":IMAGE,"supervisorImage":IMAGE,
            "referenceSet":cfg["referenceSet"],"policyDigest":cfg["policyDigest"],"imagePolicyDigest":a.digest(cfg["imagePolicy"]),
            "attestationPolicyDigest":a.digest(attestation_policy_data),
            "resourcePolicyDigest":a.digest(resource_policy_data),
            "cdhEndpoint":"http://127.0.0.1:8006","negativeTests":"passed"}},
    }
    paths={
        "peerPods":"/api/v1/namespaces/openshift-sandboxed-containers-operator/configmaps/peer-pods-cm",
        "trustee":"/apis/apps/v1/namespaces/trustee-system/deployments/kbs",
        "trusteeConfig":"/apis/confidentialcontainers.org/v1alpha1/namespaces/trustee-system/kbsconfigs/kbs",
        "attestationPolicy":"/api/v1/namespaces/trustee-system/configmaps/attestation-policy",
        "resourcePolicy":"/api/v1/namespaces/trustee-system/configmaps/resource-policy",
        "referenceValues":"/api/v1/namespaces/trustee-system/configmaps/references",
        "qualification":"/api/v1/namespaces/trustee-system/configmaps/qualification",
    }
    cfg["references"]={}
    by_path={}
    for key,obj in objects.items():
        obj["metadata"]={"uid":UID,"generation":1}
        field="spec" if key in {"trustee","trusteeConfig"} else "data"
        sha256=(a.trustee_config_digest(obj[field]) if key=="trusteeConfig" else a.digest(obj[field]))
        cfg["references"][key]={"path":paths[key],"uid":UID,"sha256":sha256}
        by_path[paths[key]]=obj
    return {"attestation":cfg}, by_path


def generic_profile_files():
    return {
        "profiles__developer__default__workspace.yaml": (
            "apiVersion: saw.redhat.com/v1alpha1\nkind: Workspace\n"
            "metadata: {name: default}\n"),
        "profiles__developer__default__providers.yaml": (
            "apiVersion: saw.redhat.com/v1alpha1\nkind: Providers\n"
            "spec: {providers: []}\n"),
        "profiles__developer__default__sandbox.yaml": (
            "apiVersion: saw.redhat.com/v1alpha1\nkind: Sandboxes\nspec:\n"
            "  sandboxes:\n  - name: toolbox\n    type: generic\n"
            "    image: registry.example.test/sandbox@sha256:" + "a" * 64 + "\n"
            "    providers: []\n"),
    }

def test_approved_public_objects_and_deterministic_initdata(approved):
    site,objects=approved
    assert a.verify_platform(site, objects.__getitem__)==a.digest(site["attestation"])
    args=(site,"alice","0123456789abcdef",UID,"default/notebook","supervisor")
    result=a.initdata(*args)
    assert result==a.initdata(*args)
    compressed=base64.b64decode(result["annotation"], validate=True)
    assert compressed[:4] == b"\x1f\x8b\x08\x00"
    raw=gzip.decompress(compressed)
    assert hashlib.sha256(raw).hexdigest() == result["sha256"]
    parsed=tomllib.loads(raw.decode())
    assert set(parsed["data"])=={"aa.toml","cdh.toml","policy.rego"}
    aa_config = tomllib.loads(parsed["data"]["aa.toml"])
    assert aa_config == {"token_configs": {
        "coco_as": {"url": site["attestation"]["kbsURL"]},
        "kbs": {"url": site["attestation"]["kbsURL"],
                "cert": site["attestation"]["kbsCA"]},
    }}
    cdh_config = tomllib.loads(parsed["data"]["cdh.toml"])
    assert cdh_config["kbc"]["url"] == site["attestation"]["kbsURL"]
    assert cdh_config["kbc"]["kbs_cert"]==site["attestation"]["kbsCA"]
    generated_policy=parsed["data"]["policy.rego"]
    assert "__SAW_IDENTITY_JSON__" not in generated_policy
    assert '"saw_identity": '+a.canonical(result["identity"]) in generated_policy
    assert "saw-identity" not in generated_policy
    assert a.initdata(*args[:-1],"workload")["sha256"]!=result["sha256"]
    assert a.initdata(site,"alice","fedcba9876543210",UID,"default/notebook","supervisor")["sha256"]!=result["sha256"]



@pytest.mark.parametrize("role", ["supervisor", "workload"])
def test_each_guest_tls_client_receives_the_approved_ca(approved, role):
    site, _ = approved
    result = a.initdata(site, "alice", "0123456789abcdef", UID,
                        "default/notebook", role)
    data = tomllib.loads(gzip.decompress(
        base64.b64decode(result["annotation"])).decode())["data"]
    aa = tomllib.loads(data["aa.toml"])["token_configs"]["kbs"]
    cdh = tomllib.loads(data["cdh.toml"])["kbc"]
    assert aa["url"] == cdh["url"] == site["attestation"]["kbsURL"]
    assert aa["cert"] == cdh["kbs_cert"] == site["attestation"]["kbsCA"]
    assert aa["url"].startswith("https://")


def test_confidential_boundary_pins_named_public_objects(approved):
    site, _ = approved
    config = {"namespace": "saw-alice", "namespaceUID": "namespace-uid",
              "ownerID": UID, "mode": "kata", "trustedNamespace": "saw-ctl-0123456789abcdef",
              "governanceNamespace": "saw-governance", "gateway": "alice",
              "confidentialProviderPolicy": "alice-confidential-provider-policy",
              "confidentialAttestation": {"settings": site["attestation"], "owner": "alice",
                                           "registration": "0123456789abcdef", "installation": UID}}
    refs = boundary_objects(config)
    assert {key for key in refs if key.startswith("confidential")} == {
        "confidentialPeerPods", "confidentialTrustee", "confidentialTrusteeConfig",
        "confidentialAttestationPolicy", "confidentialResourcePolicy",
        "confidentialReferenceValues", "confidentialQualification",
        "confidentialProviderPolicy"}
    assert not {"proxy", "proxyNetwork", "proxyPolicy", "publicCA"} & set(refs)
    assert refs["confidentialProviderPolicy"] == (
        "/api/v1/namespaces/saw-ctl-0123456789abcdef/configmaps/"
        "alice-confidential-provider-policy", "data")
    assert refs["confidentialTrusteeConfig"] == (
        site["attestation"]["references"]["trusteeConfig"]["path"], "spec")
    first = {"image": "policy", "kbsSecretResources": ["saw-alice-0123456789abcdef"]}
    second = {"image": "policy", "kbsSecretResources": ["saw-bob-fedcba9876543210"]}
    assert approval_fingerprint("confidentialTrusteeConfig", first) == approval_fingerprint(
        "confidentialTrusteeConfig", second)
    assert approval_fingerprint("confidentialTrusteeConfig", first) != a.digest(first)


def test_confidential_compiler_binds_each_slot_and_role(approved):
    site, _ = approved
    files = generic_profile_files()
    config = {"ownerID": UID, "namespace": "saw-alice", "namespaceUID": "namespace-uid",
              "ownerSubject": "alice-subject", "mode": "kata", "workloadRuntimeClass": "kata-remote",
              "workloadRuntimeClassUID": UID, "workloadRuntimeClassDigest": "c" * 64,
              "gatewayVersion": "0.1.2", "approvedCredentialFreeProviders": [],
              "bindings": {"default/toolbox": {"workspace": {
                  "claimName": "workspace-toolbox", "uid": "pvc-uid", "readOnly": False}}},
              "confidentialAttestation": {"settings": site["attestation"], "owner": "alice",
                                          "registration": "0123456789abcdef", "installation": UID}}
    plan = compile_profile_files(files, config)
    assert plan["schemaVersion"] == 2
    assert plan["requestedPlacement"] == {"supervisor": "confidential", "workload": "confidential"}
    controller_config = {"mode": "kata", "workloadRuntimeClass": "kata-remote"}
    confidential = config["confidentialAttestation"]
    verify_confidential_plan(controller_config, plan, confidential)
    slot = plan["attestation"]["placements"]["default/toolbox"]
    for role in ("supervisor", "workload"):
        assert slot[role]["runtime_class_name"] == "kata-remote"
        assert slot[role]["identity"] == {"owner": "alice", "registration": "0123456789abcdef",
                                           "installation": UID, "slot": "default/toolbox", "role": role}
        assert slot[role]["init_data_sha256"] == hashlib.sha256(gzip.decompress(
            base64.b64decode(slot[role]["init_data"], validate=True))).hexdigest()
    plan["attestation"]["placements"]["default/toolbox"]["supervisor"]["runtime_class_name"] = "runc"
    with pytest.raises(BoundaryError, match="^AttestationPlanMismatch$"):
        verify_confidential_plan(controller_config, plan, confidential)


def test_schema_two_plan_requires_enrolled_attestation():
    with pytest.raises(BoundaryError, match="^AttestationApprovalMissing$"):
        verify_confidential_plan({}, {"schemaVersion": 2}, None)


def test_confidential_compiler_rejects_container_mode(approved):
    site, _ = approved
    settings = site["attestation"]
    with pytest.raises(ContractError):
        compile_profile_files(generic_profile_files(), {"ownerID": UID, "namespace": "saw-alice",
            "namespaceUID": "namespace-uid", "ownerSubject": "alice-subject", "mode": "container",
            "gatewayVersion": "0.1.2", "approvedCredentialFreeProviders": [], "bindings": {},
            "confidentialAttestation": {
            "settings": settings, "owner": "alice", "registration": "0123456789abcdef",
            "installation": UID}})

def test_changed_approval_and_denied_reads_are_safe(approved):
    site,objects=approved
    first=next(iter(objects.values()));first["metadata"]["uid"]="changed"
    with pytest.raises(a.AttestationError,match="^AttestationApprovalChanged$"):
        a.verify_platform(site,objects.__getitem__)
    def denied(path): raise PermissionError("private API response")
    with pytest.raises(a.AttestationError,match="^AttestationDependencyUnavailable$"):
        a.verify_platform(site,denied)

@pytest.mark.parametrize("change,reason",[
    (lambda c:c.update(kbsURL="http://trustee.example.test"),"TrusteeTrustRejected"),
    (lambda c:c.update(kbsURL="https://private:password@trustee.example.test"),"TrusteeTrustRejected"),
    (lambda c:c.update(policyDigest="d"*64),"AttestationPolicyRejected"),
    (lambda c:c.update(kbsCA="invalid-public-certificate"),"TrusteeTrustRejected"),
    (lambda c:c["driver"].update(supervisorImage="unqualified:latest"),"AttestationDriverUnavailable"),
    (lambda c:c["imagePolicy"].update(default=[{"type":"insecureAcceptAnything"}]),"ImageSignaturePolicyRejected"),
    (lambda c:c["references"]["trustee"].update(path="/api/v1/namespaces/trustee-system/secrets/key"),"AttestationApprovalMissing"),
])
def test_rejected_configuration_never_echoes_inputs(approved,change,reason):
    site,_=approved;change(site["attestation"])
    with pytest.raises(a.AttestationError,match="^"+reason+"$"):
        a.validate(site)

@pytest.mark.parametrize("change",[
    "missing-copy-rule", "broad-copy-path", "allow-copy-by-default",
    "extra-copy-rule", "missing-create-container", "missing-create-sandbox",
    "allow-exec", "allow-policy-change", "allow-stream-read",
    "allow-traversal", "allow-absolute-symlink",
])
def test_guest_policy_requires_reviewed_kata_agent_baseline(approved,change):
    site,_=approved
    policy=site["attestation"]["guestPolicy"]
    changes={
        "missing-copy-rule":("CopyFileRequest if {\n    allow_copy_file\n}\n", ""),
        "broad-copy-path":("/run/kata-containers/shared/containers(?:/passthrough)?", "/"),
        "allow-copy-by-default":("default CopyFileRequest := false", "default CopyFileRequest := true"),
        "extra-copy-rule":("policy_data := {", "CopyFileRequest if { true }\n\npolicy_data :={"),
        "missing-create-container":("default CreateContainerRequest := true\n", ""),
        "missing-create-sandbox":("default CreateSandboxRequest := true\n", ""),
        "allow-exec":("default ExecProcessRequest := false", "default ExecProcessRequest := true"),
        "allow-policy-change":("default SetPolicyRequest := false", "default SetPolicyRequest := true"),
        "allow-stream-read":("default ReadStreamRequest := false", "default ReadStreamRequest := true"),
        "allow-traversal":("    check_directory_traversal(path)\n", ""),
        "allow-absolute-symlink":('    not startswith(input.symlink_target, "/")\n', ""),
    }
    old,new=changes[change]
    policy=policy.replace(old,new,1)
    site["attestation"]["guestPolicy"]=policy
    site["attestation"]["policyDigest"]=hashlib.sha256(policy.encode()).hexdigest()
    with pytest.raises(a.AttestationError,match="^AttestationPolicyRejected$"):
        a.validate(site)

def test_reviewed_policy_file_matches_validator_template():
    policy=(ROOT/"deploy/confidential/kata-agent-policy.rego").read_text()
    assert policy == a.KATA_AGENT_POLICY_TEMPLATE.rstrip() + "\n"

@pytest.mark.parametrize("policy",[
    "package agent_policy\npolicy_data := {\"containers\": []}\n",
    "package agent_policy\npolicy_data := {\"saw_identity\": __SAW_IDENTITY_JSON__, \"again\": __SAW_IDENTITY_JSON__}\n",
    "package agent_policy\n# \"saw_identity\": __SAW_IDENTITY_JSON__\n",
    "package agent_policy\npolicy_data := {\"saw_identity\": __SAW_IDENTITY_JSON__}\n# __SAW_IDENTITY_JSON__\n",
])
def test_identity_must_be_a_single_policy_data_claim(approved,policy):
    site,_=approved
    site["attestation"]["guestPolicy"]=policy
    site["attestation"]["policyDigest"]=hashlib.sha256(policy.encode()).hexdigest()
    with pytest.raises(a.AttestationError,match="^AttestationIdentityClaimUnavailable$"):
        a.validate(site)

def test_resource_scope_and_compatibility():
    assert a.resource("alice","0123456789abcdef","inference")=="default/saw-alice-0123456789abcdef/inference"
    for bad in ["../inference","inference/foreign","a?secret=private"]:
        with pytest.raises(a.AttestationError,match="^CredentialResourceRejected$"):
            a.resource("alice","0123456789abcdef",bad)
    assert a.verify_platform({},lambda p:pytest.fail("plain mode read Trustee")) is None
    with pytest.raises(a.AttestationError):a.enabled({"attestation":{"enabled":"true"}})

def test_packaged_contracts_are_identical():
    canonical=(ROOT/"kubernetes-runtime/saw_kubernetes/attestation.py").read_bytes()
    for chart in ["saw-portal-container","saw-users","openshell-rhdh"]:
        assert (ROOT/"charts"/chart/"files/attestation.py").read_bytes()==canonical

class _ProbeResponse:
    def __init__(self, status):
        self.status = status
        self.closed = False

    def close(self):
        self.closed = True


def test_kbs_probe_uses_empty_post_and_accepts_unauthenticated_response(approved):
    site, _ = approved
    calls = []

    def open_url(request, context, timeout):
        calls.append((request, context, timeout))
        return _ProbeResponse(401)

    assert a.verify_kbs_reachability(site, open_url) is True
    request, context, timeout = calls[0]
    assert request.full_url == "https://trustee.example.test/kbs/v0/auth"
    assert request.get_method() == "POST"
    assert request.data == b"{}"
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("Authorization") is None
    assert timeout == 5
    assert context.verify_mode == 2


@pytest.mark.parametrize("status", [400, 401])
def test_kbs_probe_accepts_protocol_error_as_reachability(approved, status):
    site, _ = approved
    assert a.verify_kbs_reachability(
        site, lambda request, context, timeout: _ProbeResponse(status)) is True


@pytest.mark.parametrize("status,accepted", [(400, True), (401, True), (403, False)])
def test_kbs_probe_handles_http_error_responses_without_echoing_body(approved, status, accepted):
    site, _ = approved

    def fail(request, context, timeout):
        raise HTTPError(request.full_url, status, "private response detail", {}, io.BytesIO(b"private body"))

    if accepted:
        assert a.verify_kbs_reachability(site, fail) is True
    else:
        with pytest.raises(a.AttestationError, match="^TrusteeEndpointRejected$") as error:
            a.verify_kbs_reachability(site, fail)
        assert "private" not in str(error.value)


@pytest.mark.parametrize("status", [200, 302, 403, 404, 500])
def test_kbs_probe_rejects_unexpected_status_without_echoing_response(approved, status):
    site, _ = approved
    with pytest.raises(a.AttestationError, match="^TrusteeEndpointRejected$"):
        a.verify_kbs_reachability(
            site, lambda request, context, timeout: _ProbeResponse(status))


@pytest.mark.parametrize("failure", [OSError("private route detail"), TimeoutError("private timeout")])
def test_kbs_probe_maps_transport_errors_to_safe_reason(approved, failure):
    site, _ = approved

    def fail(request, context, timeout):
        raise failure

    with pytest.raises(a.AttestationError, match="^TrusteeReachabilityUnavailable$") as error:
        a.verify_kbs_reachability(site, fail)
    assert "private" not in str(error.value)


@pytest.mark.parametrize("chart",["saw-portal-container","saw-users","openshell-rhdh"])
def test_no_confidential_request_can_deploy_probe_policy(approved,chart):
    site,objects=approved
    spec=importlib.util.spec_from_file_location("preflight_"+chart,ROOT/"charts"/chart/"files/preflight.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with pytest.raises(module.PreflightError,match="^AttestationLaunchPolicyRequired$"):
        module.verify_attestation(site,"kata",objects.__getitem__,
                                  lambda request, context, timeout: _ProbeResponse(401))


def test_trustee_bridge_contains_only_references(approved):
    site,_=approved
    site["credentialReferences"] = {
        "inference": "secret/data/hub/saw-alice/credentials/inference",
        "web-search": "secret/data/hub/saw-alice/credentials/web-search",
    }
    policy={"bindings":[{"secret":"inference","key":"api_key"},{"secret":"web-search","key":"api_key"}]}
    result=a.trustee_resources(site,"alice","0123456789abcdef",policy,"workspace-vault")
    assert result["metadata"]["namespace"]=="trustee-system"
    assert result["metadata"]["labels"] == {
        "saw.redhat.com/portal-owner": "alice",
        "saw.redhat.com/registration": "0123456789abcdef"}
    assert "saw-ctl" not in json.dumps(result)
    assert result["spec"]["secretStoreRef"]["kind"]=="ClusterSecretStore"
    template=result["spec"]["target"]["template"]["data"]
    assert set(template)=={"inference","web-search","image-policy"}
    assert result["spec"]["data"][0]["remoteRef"]["key"] == site["credentialReferences"]["inference"]
    for path in ["secret/data/hub/saw-bob/credentials/inference",
                 "secret/data/hub/saw-alice/credentials/web-search"]:
        site["credentialReferences"]["inference"] = path
        with pytest.raises(a.AttestationError,match="^CredentialReferenceRejected$"):
            a.trustee_resources(site,"alice","0123456789abcdef",policy,"workspace-vault")


def test_trustee_artifact_cli_selects_only_the_requested_profile(tmp_path, monkeypatch, capsys, approved):
    site, _ = approved
    selected = {
        "inference": "secret/data/hub/saw-alice/credentials/inference",
        "web-search": "secret/data/hub/saw-alice/credentials/web-search",
    }
    other = {"inference": "secret/data/hub/saw-alice/other/inference"}
    site["credentialReferences"] = {"data-science": selected, "other-profile": other}
    site["providerPolicy"] = {"bindings": [
        {"secret": "inference", "key": "api_key"},
        {"secret": "web-search", "key": "api_key"},
    ]}
    values = tmp_path / "public-values.yaml"
    import yaml
    values.write_text(yaml.safe_dump({"containerSites": {"alice": site}}))
    monkeypatch.setattr(sys, "argv", [
        "confidential-artifacts.py", "trustee-resources", "--values", str(values),
        "--owner", "alice", "--registration", "0123456789abcdef",
        "--profile", "data-science", "--secret-store", "workspace-vault",
    ])

    assert artifacts.main() == 0
    result = json.loads(capsys.readouterr().out)
    paths = {item["remoteRef"]["key"] for item in result["spec"]["data"]}
    assert paths == set(selected.values())
    assert other["inference"] not in json.dumps(result)


def test_trustee_artifact_cli_rejects_unknown_profile(approved):
    site, _ = approved
    site["credentialReferences"] = {"data-science": {"inference": "secret/data/hub/saw-alice/credentials/inference"}}
    with pytest.raises(artifacts.a.AttestationError, match="^CredentialReferenceRejected$"):
        artifacts.site_for_profile(site, "unknown-profile")


def test_approved_credential_references_are_owner_scoped(approved):
    site,_=approved
    site["credentialReferences"] = {"data-science": {
        "inference": "secret/data/hub/saw-alice/credentials/inference",
        "web-search": "secret/data/hub/saw-alice/credentials/web-search",
    }}
    refs=a.approved_credential_references(site,"alice","data-science",
        ["inference","web-search"],"secret","hub")
    assert refs == site["credentialReferences"]["data-science"]


@pytest.mark.parametrize("refs,profile,names,mount,base", [
    ({"inference": "secret/data/hub/saw-bob/credentials/inference",
      "web-search": "secret/data/hub/saw-alice/credentials/web-search"},
     "data-science", ["inference","web-search"], "secret", "hub"),
    ({"inference": "secret/data/hub/saw-alice/credentials/web-search",
      "web-search": "secret/data/hub/saw-alice/credentials/web-search"},
     "data-science", ["inference","web-search"], "secret", "hub"),
    ({"inference": "secret/data/hub/saw-alice/credentials/inference"},
     "data-science", ["inference","web-search"], "secret", "hub"),
    ({"inference": "secret/data/hub/saw-alice/credentials/inference",
      "web-search": "secret/data/hub/saw-alice/credentials/web-search",
      "extra": "secret/data/hub/saw-alice/credentials/extra"},
     "data-science", ["inference","web-search"], "secret", "hub"),
    ({"inference": "secret/data/hub/saw-alice/credentials/inference",
      "web-search": "secret/data/hub/saw-alice/credentials/web-search"},
     "other-profile", ["inference","web-search"], "secret", "hub"),
    ({"inference": "other/data/hub/saw-alice/credentials/inference",
      "web-search": "other/data/hub/saw-alice/credentials/web-search"},
     "data-science", ["inference","web-search"], "secret", "hub"),
    ({"inference": "secret/data/hub/saw-alice/credentials/inference",
      "web-search": "secret/data/hub/saw-alice/credentials/web-search"},
     "data-science", ["inference","web-search"], "secret", "hub/unsafe"),
])
def test_unapproved_credential_references_are_rejected(approved,refs,profile,names,mount,base):
    site,_=approved
    site["credentialReferences"]={"data-science":refs}
    with pytest.raises(a.AttestationError,match="^CredentialReferenceRejected$"):
        a.approved_credential_references(site,"alice",profile,names,mount,base)


def _trustee_external_secret(site, owner="alice", registration="0123456789abcdef"):
    name = "saw-" + owner + "-" + registration
    namespace = site["attestation"]["references"]["trusteeConfig"]["path"].split("/")[5]
    return ("/apis/external-secrets.io/v1/namespaces/" + namespace
            + "/externalsecrets/" + name), {
                "metadata": {"name": name, "namespace": namespace, "labels": {
                    "saw.redhat.com/portal-owner": owner,
                    "saw.redhat.com/registration": registration}},
                "spec": {"target": {"name": name}},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
            }


def test_trustee_external_secret_readiness_checks_only_its_metadata(approved):
    site, _ = approved
    path, obj = _trustee_external_secret(site)
    seen = []

    def read(target):
        seen.append(target)
        assert target == path
        assert "/secrets/" not in target
        return obj

    assert a.verify_resource_secret_ready(site, "alice", "0123456789abcdef", read) is True
    assert seen == [path]


@pytest.mark.parametrize("change", ["pending", "owner", "registration", "target", "namespace"])
def test_trustee_external_secret_readiness_rejects_wrong_or_pending_resource(approved, change):
    site, _ = approved
    path, obj = _trustee_external_secret(site)
    if change == "pending":
        obj["status"]["conditions"][0]["status"] = "False"
    elif change == "owner":
        obj["metadata"]["labels"]["saw.redhat.com/portal-owner"] = "bob"
    elif change == "registration":
        obj["metadata"]["labels"]["saw.redhat.com/registration"] = "fedcba9876543210"
    elif change == "target":
        obj["spec"]["target"]["name"] = "other"
    else:
        obj["metadata"]["namespace"] = "other"

    with pytest.raises(a.AttestationError, match="^CredentialResourceUnavailable$"):
        a.verify_resource_secret_ready(site, "alice", "0123456789abcdef",
                                       lambda target: obj if target == path else {})


def test_trustee_resource_membership_is_scoped_and_does_not_change_site_approval(approved):
    site,objects=approved
    path=site["attestation"]["references"]["trusteeConfig"]["path"]
    config=objects[path]
    assert a.verify_platform(site,objects.__getitem__)==a.digest(site["attestation"])
    config["spec"]["kbsSecretResources"].append("saw-carol-aaaaaaaaaaaaaaaa")
    assert a.verify_platform(site,objects.__getitem__)==a.digest(site["attestation"])
    with pytest.raises(a.AttestationError,match="^CredentialResourceUnavailable$"):
        a.verify_resource_membership(site,"alice","0123456789abcdef",objects.__getitem__)
    config["spec"]["kbsSecretResources"].append("saw-alice-0123456789abcdef")
    a.verify_resource_membership(site,"alice","0123456789abcdef",objects.__getitem__)
    config["spec"]["kbsSecretResources"].append("saw-alice-0123456789abcdef")
    with pytest.raises(a.AttestationError,match="^TrusteeConfigurationRejected$"):
        a.verify_platform(site,objects.__getitem__)


def test_trustee_membership_updates_use_resource_version_and_preserve_other_resources(approved):
    site, objects = approved
    path = site["attestation"]["references"]["trusteeConfig"]["path"]
    config = objects[path]
    config["metadata"]["resourceVersion"] = "1"
    writes = []

    def patch(target, body):
        assert target == path
        assert set(body) == {"metadata", "spec"}
        assert set(body["metadata"]) == {"resourceVersion"}
        assert body["metadata"]["resourceVersion"] == config["metadata"]["resourceVersion"]
        assert set(body["spec"]) == {"kbsSecretResources"}
        config["spec"].update(body["spec"])
        config["metadata"]["resourceVersion"] = str(int(config["metadata"]["resourceVersion"]) + 1)
        writes.append(body)

    assert a.ensure_resource_membership(site, "alice", "0123456789abcdef",
                                        objects.__getitem__, patch) is True
    assert config["spec"]["kbsSecretResources"] == [
        "saw-bob-fedcba9876543210", "saw-alice-0123456789abcdef"]
    assert a.ensure_resource_membership(site, "alice", "0123456789abcdef",
                                        objects.__getitem__, patch) is False
    assert a.revoke_resource_membership(site, "alice", "0123456789abcdef",
                                        objects.__getitem__, patch) is True
    assert config["spec"]["kbsSecretResources"] == ["saw-bob-fedcba9876543210"]
    assert a.revoke_resource_membership(site, "alice", "0123456789abcdef",
                                        objects.__getitem__, patch) is False
    assert len(writes) == 2


def test_trustee_revoke_uses_stored_identity_after_policy_change(approved):
    site, objects = approved
    ref = site["attestation"]["references"]["trusteeConfig"]
    config = objects[ref["path"]]
    own = "saw-alice-0123456789abcdef"
    config["spec"]["kbsSecretResources"] = ["saw-bob-fedcba9876543210", own]
    config["spec"]["policyRevision"] = "reviewed-policy-v2"
    config["metadata"]["resourceVersion"] = "7"
    writes = []

    def patch(target, body):
        assert target == ref["path"]
        assert set(body) == {"metadata", "spec"}
        assert body["metadata"] == {"resourceVersion": "7"}
        assert set(body["spec"]) == {"kbsSecretResources"}
        config["spec"].update(body["spec"])
        config["metadata"]["resourceVersion"] = "8"
        writes.append(body)

    assert a.revoke_trustee_resource_membership(
        ref, "alice", "0123456789abcdef", objects.__getitem__, patch) is True
    assert config["spec"]["kbsSecretResources"] == ["saw-bob-fedcba9876543210"]
    assert config["spec"]["policyRevision"] == "reviewed-policy-v2"
    assert len(writes) == 1
    assert a.revoke_trustee_resource_membership(
        ref, "alice", "0123456789abcdef", objects.__getitem__, patch) is False
    assert len(writes) == 1


def test_trustee_membership_retries_conflict_without_losing_concurrent_entries(approved):
    site, objects = approved
    path = site["attestation"]["references"]["trusteeConfig"]["path"]
    config = objects[path]
    config["metadata"]["resourceVersion"] = "1"
    calls = 0

    def patch(target, body):
        nonlocal calls
        calls += 1
        if calls == 1:
            config["spec"]["kbsSecretResources"].append("shared-existing")
            config["metadata"]["resourceVersion"] = "2"
            raise HTTPError("https://trustee.example.test", 409, "Conflict", {}, io.BytesIO())
        assert body["metadata"]["resourceVersion"] == "2"
        config["spec"].update(body["spec"])
        config["metadata"]["resourceVersion"] = "3"

    assert a.ensure_resource_membership(site, "alice", "0123456789abcdef",
                                        objects.__getitem__, patch) is True
    assert calls == 2
    assert config["spec"]["kbsSecretResources"] == [
        "saw-bob-fedcba9876543210", "shared-existing", "saw-alice-0123456789abcdef"]


@pytest.mark.parametrize("key,value,reason",[
    ("peerPods", {"DISABLECVM":"true"}, "ConfidentialRuntimeUnavailable"),
    ("qualification", {"negativeTests":"missing"}, "AttestationQualificationMissing"),
])
def test_reapproved_bad_platform_still_fails(approved,key,value,reason):
    site,objects=approved
    ref=site["attestation"]["references"][key]
    objects[ref["path"]]["data"].update(value)
    ref["sha256"]=a.digest(objects[ref["path"]]["data"])
    with pytest.raises(a.AttestationError,match="^"+reason+"$"):
        a.verify_platform(site,objects.__getitem__)

@pytest.mark.parametrize("reference_data", [
    {},
    {"reference_value": "null"},
    {"reference_value": "[]"},
    {"reference_value": "{}"},
])
def test_empty_or_unrecognized_reference_values_are_rejected(approved, reference_data):
    site, objects = approved
    ref = site["attestation"]["references"]["referenceValues"]
    objects[ref["path"]]["data"] = reference_data
    ref["sha256"] = a.digest(reference_data)
    with pytest.raises(a.AttestationError, match="^ReferenceValuesRejected$"):
        a.verify_platform(site, objects.__getitem__)

def test_reapproved_reference_values_must_match_the_approved_set(approved):
    site, objects = approved
    ref = site["attestation"]["references"]["referenceValues"]
    data = objects[ref["path"]]["data"]
    values = json.loads(data["reference_value"])
    item = json.loads(base64.b64decode(values["snp_pcr03"]))
    item["value"] = ["f" * 64]
    values["snp_pcr03"] = base64.b64encode(
        json.dumps(item, separators=(",", ":")).encode()).decode()
    data["reference_value"] = json.dumps(values, indent=2)
    ref["sha256"] = a.digest(data)
    with pytest.raises(a.AttestationError, match="^ReferenceValuesRejected$"):
        a.verify_platform(site, objects.__getitem__)

@pytest.mark.parametrize("mutate", [
    lambda values: values.pop("snp_pcr08"),
    lambda values: values.update({"tdx_pcr08": values.pop("snp_pcr08")}),
    lambda values: values.update({"snp_pcr08": "not-base64"}),
])
def test_invalid_trustee_reference_value_entries_are_rejected(approved, mutate):
    site, objects = approved
    cfg = site["attestation"]
    data = objects[cfg["references"]["referenceValues"]["path"]]["data"]
    values = json.loads(data["reference_value"])
    mutate(values)
    data["reference_value"] = json.dumps(values, indent=2)
    cfg["references"]["referenceValues"]["sha256"] = a.digest(data)
    with pytest.raises(a.AttestationError, match="^ReferenceValuesRejected$"):
        a.verify_platform(site, objects.__getitem__)

def test_trustee_tdx_reference_values_use_tdx_names():
    tdx_values = trustee_reference_values("tdx")
    assert a.verify_reference_values(
        {"reference_value": json.dumps(tdx_values)}, a.digest(tdx_values), "tdx") == tdx_values

@pytest.mark.parametrize("field,value", [
    ("name", "snp_pcr09"),
    ("expiration", "2000-01-01T00:00:00Z"),
    ("value", []),
    ("value", ["not-a-sha256-digest"]),
])
def test_invalid_trustee_reference_payload_is_rejected(approved, field, value):
    site, objects = approved
    cfg = site["attestation"]
    data = objects[cfg["references"]["referenceValues"]["path"]]["data"]
    values = json.loads(data["reference_value"])
    item = json.loads(base64.b64decode(values["snp_pcr03"]))
    item[field] = value
    values["snp_pcr03"] = base64.b64encode(
        json.dumps(item, separators=(",", ":")).encode()).decode()
    data["reference_value"] = json.dumps(values, indent=2)
    cfg["references"]["referenceValues"]["sha256"] = a.digest(data)
    with pytest.raises(a.AttestationError, match="^ReferenceValuesRejected$"):
        a.verify_platform(site, objects.__getitem__)

def test_chart_attestation_links_use_one_runtime_source():
    source = (ROOT / "kubernetes-runtime/saw_kubernetes/attestation.py").read_bytes()
    for relative in (
        "charts/openshell-rhdh/files/attestation.py",
        "charts/saw-users/files/attestation.py",
        "charts/saw-portal-container/files/attestation.py",
    ):
        asset = ROOT / relative
        assert asset.is_symlink()
        assert not asset.readlink().is_absolute()
        assert asset.resolve() == ROOT / "kubernetes-runtime/saw_kubernetes/attestation.py"
        assert asset.read_bytes() == source

@pytest.mark.parametrize("key", ["attestationPolicy", "resourcePolicy"])
def test_changed_trustee_policy_is_rejected(approved,key):
    site,objects=approved
    ref=site["attestation"]["references"][key]
    data=objects[ref["path"]]["data"]
    data_key=next(iter(data))
    data[data_key] += "# changed after approval\n"
    with pytest.raises(a.AttestationError,match="^AttestationApprovalChanged$"):
        a.verify_platform(site,objects.__getitem__)

def test_unready_trustee_rejected(approved):
    site,objects=approved
    obj=objects[site["attestation"]["references"]["trustee"]["path"]]
    obj["status"]["availableReplicas"]=0
    with pytest.raises(a.AttestationError,match="^TrusteeUnavailable$"):
        a.verify_platform(site,objects.__getitem__)


@pytest.fixture
def confidential_driver(approved):
    site, _ = approved
    context = {"settings":site["attestation"], "owner":"alice",
               "registration":"0123456789abcdef", "installation":UID}
    contract = a.placement_contract(site, "alice", context["registration"], UID,
                                    ["default/toolbox"], "kata-remote")
    placement = contract["placements"]["default/toolbox"]
    provider_policy={"markerPrefix":"saw","allowHosts":["api.example.test"],
        "profiles":{"nvidia":["api.example.test"]},
        "bindings":[{"secret":"inference","key":"api_key","providers":["nvidia"]}]}
    driver = {"confidential_mode":True, "default_runtime_class_name":"kata-remote",
              "supervisor_image":IMAGE,
              "confidential_supervisors":{"default/toolbox":{
                  "runtime_class_name":"kata-remote", "init_data":placement["supervisor"]["init_data"],
                  "bootstrap_json":a.supervisor_bootstrap(provider_policy,"alice","0123456789abcdef")}},
              "confidential_workloads":{"default/toolbox":{
                  "runtime_class_name":"kata-remote", "init_data":placement["workload"]["init_data"]}}}
    gateway={"spec":{"template":{"spec":{"containers":[{"name":"gateway","image":IMAGE}]}}}}
    return ({"workloadRuntimeClass":"kata-remote"}, {"schemaVersion":2,"attestation":contract},
            context, driver, gateway, provider_policy)


def test_confidential_driver_matches_enrolled_placement(confidential_driver):
    from saw_kubernetes.boundary import verify_confidential_driver
    verify_confidential_driver(*confidential_driver)


@pytest.mark.parametrize("change", ["disabled", "gateway-image", "supervisor-image", "runtime",
    "missing-supervisor", "extra-slot", "supervisor-init", "workload-init", "config-map", "config-key",
    "external-proxy", "external-proxy-ca", "insecure-proxy"])
def test_confidential_driver_rejects_actual_deployment_mismatch(confidential_driver, change):
    from saw_kubernetes.boundary import verify_confidential_driver
    config, plan, context, driver, gateway, provider_policy = confidential_driver
    supervisor=driver["confidential_supervisors"]["default/toolbox"]
    workload=driver["confidential_workloads"]["default/toolbox"]
    if change=="disabled": driver["confidential_mode"]=False
    elif change=="gateway-image": gateway["spec"]["template"]["spec"]["containers"][0]["image"]="registry.example.test/other@sha256:"+"f"*64
    elif change=="supervisor-image": driver["supervisor_image"]="registry.example.test/other@sha256:"+"f"*64
    elif change=="runtime": driver["default_runtime_class_name"]="kata"
    elif change=="missing-supervisor": driver["confidential_supervisors"]={}
    elif change=="extra-slot":
        driver["confidential_supervisors"]["default/extra"]=dict(supervisor)
        driver["confidential_workloads"]["default/extra"]=dict(workload)
    elif change=="supervisor-init": supervisor["init_data"]="changed"
    elif change=="workload-init": workload["init_data"]="changed"
    elif change=="config-map": supervisor["config_map_name"]="foreign"
    elif change=="config-key": supervisor["config_key"]="foreign.json"
    elif change=="external-proxy": driver["https_proxy"]="http://proxy.example.test:3128"
    elif change=="external-proxy-ca": driver["proxy_ca_bundle"]="/external/ca.pem"
    elif change=="insecure-proxy": driver["proxy_auth_allow_insecure"]=True
    with pytest.raises(BoundaryError,match="^ConfidentialDriverMismatch$"):
        verify_confidential_driver(config,plan,context,driver,gateway,provider_policy)


def test_plain_mode_cannot_silently_enable_confidential_driver():
    from saw_kubernetes.boundary import verify_confidential_driver
    with pytest.raises(BoundaryError,match="^UnexpectedConfidentialDriver$"):
        verify_confidential_driver({}, {}, None, {"confidential_mode":True}, {})


@pytest.fixture
def launch_pod():
    return {"apiVersion":"v1", "kind":"Pod", "metadata":{"name":"supervisor","namespace":"workspace"},
            "spec":{"automountServiceAccountToken":False,
                    "securityContext":{"seccompProfile":{"type":"RuntimeDefault"},
                                       "runAsNonRoot":True,"runAsUser":1001},
                    "containers":[{"name":"supervisor", "image":IMAGE,
                                   "command":["/approved-supervisor"],
                                   "securityContext":{"allowPrivilegeEscalation":False,
                                                      "readOnlyRootFilesystem":True}}]}}


def test_launch_input_preserves_effective_security_without_mutating_pod(launch_pod):
    import copy
    original=copy.deepcopy(launch_pod)
    result=a.launch_policy_input(launch_pod)
    assert launch_pod==original
    assert "automountServiceAccountToken" not in result["spec"]
    assert result["spec"]["securityContext"]=={"runAsUser":1001}
    security=result["spec"]["containers"][0]["securityContext"]
    assert security["seccompProfile"]=={"type":"RuntimeDefault"}
    assert security["allowPrivilegeEscalation"] is False
    assert security["readOnlyRootFilesystem"] is True
    assert result["spec"]["containers"][0]["command"]==["/approved-supervisor"]


@pytest.mark.parametrize("change",["auto-token","implicit-token","root","boolean-uid","implicit-uid",
    "unconfined","container-unconfined","root-override","host-network","privileged","secret-env","env-from"])
def test_unsafe_launch_input_is_rejected(launch_pod,change):
    spec=launch_pod["spec"]; container=spec["containers"][0]
    if change=="auto-token":spec["automountServiceAccountToken"]=True
    elif change=="implicit-token":del spec["automountServiceAccountToken"]
    elif change=="root":spec["securityContext"]["runAsUser"]=0
    elif change=="boolean-uid":spec["securityContext"]["runAsUser"]=True
    elif change=="implicit-uid":del spec["securityContext"]["runAsUser"]
    elif change=="unconfined":spec["securityContext"]["seccompProfile"]={"type":"Unconfined"}
    elif change=="container-unconfined":container["securityContext"]["seccompProfile"]={"type":"Unconfined"}
    elif change=="root-override":container["securityContext"]["runAsNonRoot"]=False
    elif change=="host-network":spec["hostNetwork"]=True
    elif change=="privileged":container["securityContext"]["privileged"]=True
    elif change=="secret-env":container["env"]=[{"name":"KEY","valueFrom":{"secretKeyRef":{"name":"provider","key":"api_key"}}}]
    elif change=="env-from":container["envFrom"]=[{"secretRef":{"name":"provider"}}]
    with pytest.raises(a.AttestationError,match="^LaunchPolicyInputRejected$"):
        a.launch_policy_input(launch_pod)


def test_launch_input_keeps_other_unsupported_fields_for_generator_rejection(launch_pod):
    launch_pod["spec"]["unknownSecurityField"]={"enabled":True}
    assert a.launch_policy_input(launch_pod)["spec"]["unknownSecurityField"]=={"enabled":True}


def test_init_container_cannot_bypass_launch_input_checks(launch_pod):
    launch_pod["spec"]["initContainers"]=[{"name":"init","image":IMAGE,
        "securityContext":{"runAsUser":0}}]
    with pytest.raises(a.AttestationError,match="^LaunchPolicyInputRejected$"):
        a.launch_policy_input(launch_pod)


def test_launch_input_cli_is_private_and_does_not_overwrite(tmp_path,monkeypatch,capsys,launch_pod):
    import yaml
    source=tmp_path/"pod.yaml"; source.write_text(yaml.safe_dump(launch_pod))
    output=tmp_path/"generator.yaml"
    monkeypatch.setattr(sys,"argv",["confidential-artifacts.py","launch-input","--pod",str(source),"--output",str(output)])
    assert artifacts.main()==0
    assert output.stat().st_mode & 0o777 == 0o600
    assert "apiVersion" not in capsys.readouterr().out
    before=output.read_bytes()
    assert artifacts.main()==1
    assert output.read_bytes()==before
    captured=capsys.readouterr()
    assert captured.out==""
    assert captured.err.strip()=="AttestationConfigurationRejected"


@pytest.fixture
def generated_launch(launch_pod, monkeypatch):
    prefix="package agent_policy\n\ndefault CreateContainerRequest := false"
    monkeypatch.setattr(a,"GENPOLICY_RULES_SHA256",hashlib.sha256(prefix.encode()).hexdigest())
    monkeypatch.setattr(a,"GENPOLICY_ENV_RULES_SHA256",a.digest([]))
    policy={"markerPrefix":"saw","allowHosts":["api.example.test"],"profiles":{"nvidia":["api.example.test"]},
            "bindings":[{"secret":"inference","key":"api_key","providers":["nvidia"]}]}
    bootstrap=a.supervisor_bootstrap(policy,"alice","0123456789abcdef")
    launch_pod["spec"]["containers"][0]["env"]=[{"name":a.BOOTSTRAP_ENV,"value":bootstrap}]
    data={"request_defaults":{"CreateContainerRequest":{"allow_env_regex":[]},"ExecProcessRequest":{"allowed_commands":[],"regex":[]},
        "ReadStreamRequest":False,"WriteStreamRequest":False,"GetDiagnosticDataRequest":False},
        "containers":[{"OCI":{"Annotations":{"io.kubernetes.cri.container-type":"sandbox"},
            "Process":{"Args":["/pause"]}}},
            {"OCI":{"Annotations":{"io.kubernetes.cri.container-type":"container",
                "io.kubernetes.cri.container-name":"supervisor",
                "io.kubernetes.cri.image-name":IMAGE,
                "io.kubernetes.cri.sandbox-namespace":"workspace"},
                "Root":{"Readonly":True},"Process":{"Args":["/approved-supervisor"],
                "Env":[a.BOOTSTRAP_ENV+"="+bootstrap],"User":{"UID":1001},"NoNewPrivileges":True}}}]}
    return launch_pod,prefix,data


def test_launch_template_uses_verified_rules_and_one_identity_marker(generated_launch):
    pod,prefix,data=generated_launch
    result=a.compile_launch_policy(pod,prefix+"\n\npolicy_data := "+json.dumps(data))
    assert result.startswith(prefix)
    assert result.count(a.IDENTITY_MARKER)==1
    assert a.IDENTITY_MEMBER.search(result) is None  # JSON output, not the legacy handwritten policy
    parsed=json.loads(result.split("policy_data := ",1)[1].replace(a.IDENTITY_MARKER,"null"))
    assert parsed["saw_identity"] is None
    assert parsed["containers"]==data["containers"]


@pytest.mark.parametrize("change",["rules","command","image","uid","namespace","readonly",
    "privilege","exec","stream","diagnostic","extra-container","extra-pause","trailing-rule","marker"])
def test_changed_launch_artifacts_fail_closed(generated_launch,change):
    import copy
    pod,prefix,data=generated_launch; data=copy.deepcopy(data)
    app=data["containers"][1]["OCI"]
    if change=="rules":prefix+="\ndefault ExecProcessRequest := true"
    elif change=="command":app["Process"]["Args"]=["/bin/sh"]
    elif change=="image":app["Annotations"]["io.kubernetes.cri.image-name"]="registry.example.test/foreign@sha256:"+"f"*64
    elif change=="uid":app["Process"]["User"]["UID"]=0
    elif change=="namespace":app["Annotations"]["io.kubernetes.cri.sandbox-namespace"]="foreign"
    elif change=="readonly":app["Root"]["Readonly"]=False
    elif change=="privilege":app["Process"]["NoNewPrivileges"]=False
    elif change=="exec":data["request_defaults"]["ExecProcessRequest"]["allowed_commands"]=[["/bin/sh"]]
    elif change=="stream":data["request_defaults"]["ReadStreamRequest"]=True
    elif change=="diagnostic":data["request_defaults"]["GetDiagnosticDataRequest"]=True
    elif change=="extra-container":
        extra=copy.deepcopy(data["containers"][1]);extra["OCI"]["Annotations"]["io.kubernetes.cri.container-name"]="foreign"
        data["containers"].append(extra)
    elif change=="extra-pause":data["containers"].append(copy.deepcopy(data["containers"][0]))
    elif change=="marker":data["untrusted"]=a.IDENTITY_MARKER
    generated=prefix+"\n\npolicy_data := "+json.dumps(data)
    if change=="trailing-rule":generated+="\nExecProcessRequest := true"
    with pytest.raises(a.AttestationError,match="^LaunchPolicyRejected$"):
        a.compile_launch_policy(pod,generated)


def test_generator_rules_digest_matches_source_lock():
    import yaml
    locked=yaml.safe_load((ROOT/"deploy/confidential/source-lock.yaml").read_text())
    assert locked["policyGenerator"]["rulesCodeSHA256"]==a.GENPOLICY_RULES_SHA256
    assert locked["status"]=="blocked"
    assert all(value is None for value in locked["qualified"].values())


def test_node_placeholder_cannot_bypass_exact_command_matching(generated_launch):
    pod,prefix,data=generated_launch
    pod["spec"]["containers"][0]["command"]=["/approved-supervisor","$(node-name)"]
    data["containers"][1]["OCI"]["Process"]["Args"]=["/approved-supervisor","$(node-name)"]
    with pytest.raises(a.AttestationError,match="^LaunchPolicyRejected$"):
        a.compile_launch_policy(pod,prefix+"\n\npolicy_data := "+json.dumps(data))


@pytest.mark.parametrize("change",["missing","duplicate","changed","wide-pattern","legacy-file"])
def test_supervisor_bootstrap_cannot_escape_measured_environment(generated_launch,change):
    pod,prefix,data=generated_launch
    process=data["containers"][1]["OCI"]["Process"]
    if change=="missing":pod["spec"]["containers"][0]["env"]=[]
    elif change=="duplicate":process["Env"]*=2
    elif change=="changed":process["Env"]=[a.BOOTSTRAP_ENV+"={}"]
    elif change=="wide-pattern":data["request_defaults"]["CreateContainerRequest"]["allow_env_regex"]=["^.*$"]
    elif change=="legacy-file":pod["spec"]["containers"][0]["env"].append({"name":"SAW_CONFIDENTIAL_CONFIG","value":"/unmeasured/file.json"})
    with pytest.raises(a.AttestationError,match="^LaunchPolicyRejected$"):
        a.compile_launch_policy(pod,prefix+"\n\npolicy_data := "+json.dumps(data))


@pytest.fixture
def launch_site(approved, generated_launch):
    import copy
    site, _ = approved
    site = copy.deepcopy(site)
    pod, prefix, data = copy.deepcopy(generated_launch)
    pod['metadata']['namespace'] = 'saw-alice'
    pod['spec']['runtimeClassName'] = 'kata-remote'
    command = ['/usr/local/bin/saw-credential-proxy', 'supervise', '/openshell-supervisor',
               '--upstream-proxy', 'http://127.0.0.1:3128',
               '--upstream-proxy-ca-bundle', '/run/openshell/saw-proxy-ca.pem']
    pod['spec']['containers'][0]['command'] = command
    oci = data['containers'][1]['OCI']
    oci['Annotations']['io.kubernetes.cri.sandbox-namespace'] = 'saw-alice'
    oci['Process']['Args'] = command
    supervisor = {'pod': pod, 'template': a.compile_launch_policy(
        pod, prefix+'\n\npolicy_data := '+json.dumps(data))}
    workload_pod, workload_data = copy.deepcopy((pod, data))
    workload_pod['spec']['containers'][0].update(
        name='workload', command=['/approved-workload'], env=[])
    workload_oci = workload_data['containers'][1]['OCI']
    workload_oci['Annotations']['io.kubernetes.cri.container-name'] = 'workload'
    workload_oci['Process'].update(Args=['/approved-workload'], Env=[])
    workload = {'pod': workload_pod, 'template': a.compile_launch_policy(
        workload_pod, prefix+'\n\npolicy_data := '+json.dumps(workload_data))}
    policies = {'default/notebook': {'supervisor': supervisor, 'workload': workload}}
    cfg = site['attestation']
    cfg.pop('guestPolicy')
    cfg.update(schemaVersion=2, launchPolicies=policies, policyDigest=a.digest(policies))
    return site


def test_launch_bundle_is_enrolled_and_generates_each_role(launch_site):
    cfg = a.validate(launch_site)
    assert cfg['schemaVersion'] == 2
    args = (launch_site, 'alice', '0123456789abcdef', UID, 'default/notebook')
    results = {role: a.initdata(*args, role) for role in ('supervisor', 'workload')}
    assert results['supervisor']['sha256'] != results['workload']['sha256']
    for role, result in results.items():
        policy = tomllib.loads(gzip.decompress(base64.b64decode(result['annotation'])).decode())['data']['policy.rego']
        parsed = json.loads(policy.split('policy_data := ', 1)[1])
        assert parsed['saw_identity'] == result['identity']
        assert parsed['saw_identity']['role'] == role
        assert a.IDENTITY_MARKER not in policy
    contract = a.placement_contract(*args[:4], ['default/notebook'], 'kata-remote')
    assert contract['policy_digest'] == a.digest(cfg['launchPolicies'])
    assert contract['placements']['default/notebook']['supervisor']['init_data'] == results['supervisor']['annotation']


@pytest.mark.parametrize('change', ['stale-digest', 'changed-command', 'changed-template',
    'extra-field', 'missing-role', 'extra-role', 'wrong-slot', 'missing-marker',
    'two-markers', 'missing-wrapper', 'external-proxy'])
def test_launch_bundle_changes_fail_closed(launch_site, change):
    cfg = launch_site['attestation']
    entry = cfg['launchPolicies']['default/notebook']['supervisor']
    if change == 'stale-digest':
        cfg['policyDigest'] = 'f'*64
    elif change == 'changed-command':
        entry['pod']['spec']['containers'][0]['command'] = ['/bin/sh']
    elif change == 'changed-template':
        entry['template'] += '\nCreateContainerRequest := true'
    elif change == 'extra-field':
        entry['qualification'] = 'self-asserted'
    elif change == 'missing-role':
        cfg['launchPolicies']['default/notebook'].pop('workload')
    elif change == 'extra-role':
        cfg['launchPolicies']['default/notebook']['gateway'] = entry
    elif change == 'wrong-slot':
        cfg['launchPolicies']['private-fixture-marker'] = cfg['launchPolicies'].pop('default/notebook')
    elif change == 'missing-marker':
        entry['template'] = entry['template'].replace(a.IDENTITY_MARKER, 'null')
    elif change == 'two-markers':
        entry['template'] += '\n# '+a.IDENTITY_MARKER
    elif change == 'missing-wrapper':
        entry['pod']['spec']['containers'][0]['command'][0] = '/unmeasured-wrapper'
    elif change == 'external-proxy':
        entry['pod']['spec']['containers'][0]['command'][4] = 'http://private-fixture-marker'
    if change != 'stale-digest':
        cfg['policyDigest'] = a.digest(cfg['launchPolicies'])
    with pytest.raises(a.AttestationError, match='^AttestationLaunchPolicyRejected$'):
        a.validate(launch_site)


@pytest.mark.parametrize('change', ['foreign-owner', 'foreign-registration', 'missing-slot', 'wrong-supervisor-image'])
def test_launch_identity_must_match_the_registration(launch_site, change):
    args = [launch_site, 'alice', '0123456789abcdef', UID, 'default/notebook', 'supervisor']
    if change == 'foreign-owner': args[1] = 'bob'
    elif change == 'foreign-registration': args[2] = 'fedcba9876543210'
    elif change == 'missing-slot': args[4] = 'other/notebook'
    else: launch_site['attestation']['driver']['supervisorImage'] = IMAGE.replace('a'*64, 'f'*64)
    with pytest.raises(a.AttestationError, match='^AttestationLaunchBindingRejected$'):
        a.initdata(*args)


@pytest.mark.parametrize('slots,runtime', [(['other/notebook'], 'kata-remote'),
                                           (['default/notebook'], 'ordinary-kata')])
def test_launch_placement_cannot_select_other_slots_or_runtime(launch_site, slots, runtime):
    with pytest.raises(a.AttestationError, match='^AttestationLaunchBindingRejected$'):
        a.placement_contract(launch_site, 'alice', '0123456789abcdef', UID, slots, runtime)


def test_driver_bootstrap_must_match_the_measured_launch_pod(confidential_driver, launch_site):
    from saw_kubernetes.boundary import verify_confidential_driver
    config, plan, context, driver, gateway, provider_policy = confidential_driver
    cfg = launch_site['attestation']
    cfg['launchPolicies']['default/toolbox'] = cfg['launchPolicies'].pop('default/notebook')
    context['settings'] = cfg
    verify_confidential_driver(config, plan, context, driver, gateway, provider_policy)
    measured = cfg['launchPolicies']['default/toolbox']['supervisor']['pod']['spec']['containers'][0]['env'][0]
    public = json.loads(measured['value'])
    public['policy']['allowHosts'] = ['foreign.example.test']
    measured['value'] = a.canonical(public)
    with pytest.raises(BoundaryError, match='^ConfidentialDriverMismatch$'):
        verify_confidential_driver(config, plan, context, driver, gateway, provider_policy)


def test_driver_api_metadata_is_removed_only_from_generator_input(launch_pod):
    import copy
    owner = {'apiVersion': 'agents.x-k8s.io/v1alpha1', 'kind': 'Sandbox',
             'name': 'approved-slot', 'uid': UID, 'controller': True, 'blockOwnerDeletion': True}
    launch_pod['metadata']['ownerReferences'] = [owner]
    launch_pod['spec']['schedulingGates'] = [{'name': 'openshell.ai/bootstrap'}]
    launch_pod['spec']['securityContext'].update(fsGroup=1001, fsGroupChangePolicy='OnRootMismatch')
    original = copy.deepcopy(launch_pod)
    normalized = a.launch_policy_input(launch_pod)
    assert launch_pod == original
    assert 'ownerReferences' not in normalized['metadata']
    assert 'schedulingGates' not in normalized['spec']
    assert normalized['spec']['securityContext']['fsGroup'] == 1001
    assert 'fsGroupChangePolicy' not in normalized['spec']['securityContext']


@pytest.mark.parametrize('field', ['owner', 'gate', 'ownership'])
def test_unknown_driver_api_field_conversion_is_rejected(launch_pod, field):
    if field == 'owner': launch_pod['metadata']['ownerReferences'] = [{'kind': 'Deployment'}]
    elif field == 'gate': launch_pod['spec']['schedulingGates'] = [{'name': 'unreviewed.example/gate'}]
    else: launch_pod['spec']['securityContext']['fsGroupChangePolicy'] = 'Always'
    with pytest.raises(a.AttestationError, match='^LaunchPolicyInputRejected$'):
        a.launch_policy_input(launch_pod)


@pytest.fixture
def supervisor_token_pod(launch_pod):
    launch_pod['spec']['volumes'] = [{'name': 'sa-token', 'projected': {
        'defaultMode': 0o440, 'sources': [{'serviceAccountToken': {
            'audience': 'openshell-gateway', 'expirationSeconds': 600, 'path': 'token'}}]}}]
    launch_pod['spec']['containers'][0]['volumeMounts'] = [
        {'name': 'sa-token', 'mountPath': '/var/run/secrets/openshell', 'readOnly': True}]
    return launch_pod


def test_projected_token_keeps_the_original_and_read_only_mount(supervisor_token_pod):
    import copy
    original = copy.deepcopy(supervisor_token_pod)
    normalized = a.launch_policy_input(supervisor_token_pod)
    assert supervisor_token_pod == original
    assert normalized['spec']['volumes'] == [{'name': 'sa-token', 'projected': {'defaultMode': 0o440}}]
    assert normalized['spec']['containers'][0]['volumeMounts'] == original['spec']['containers'][0]['volumeMounts']


@pytest.mark.parametrize('change', ['audience', 'path', 'ttl', 'writable', 'mode', 'other-source', 'extra-source', 'missing-mount'])
def test_projected_token_conversion_rejects_changed_contract(supervisor_token_pod, change):
    spec = supervisor_token_pod['spec']
    projection = spec['volumes'][0]['projected']
    token = projection['sources'][0]['serviceAccountToken']
    if change == 'audience': token['audience'] = 'unreviewed'
    elif change == 'path': token['path'] = '../token'
    elif change == 'ttl': token['expirationSeconds'] = 3601
    elif change == 'writable': spec['containers'][0]['volumeMounts'][0]['readOnly'] = False
    elif change == 'mode': projection['defaultMode'] = 0o666
    elif change == 'other-source': projection['sources'] = [{'secret': {'name': 'unreviewed'}}]
    elif change == 'extra-source': projection['sources'].append({'configMap': {'name': 'unreviewed'}})
    else: spec['containers'][0]['volumeMounts'] = []
    with pytest.raises(a.AttestationError, match='^LaunchPolicyInputRejected$'):
        a.launch_policy_input(supervisor_token_pod)


@pytest.fixture
def runtime_launch(generated_launch):
    import copy
    pod, prefix, data = copy.deepcopy(generated_launch)
    runtime_id = '11111111-1111-4111-8111-111111111111'
    pod['metadata']['name'] = 'os-supervisor-' + runtime_id
    pod['spec']['containers'][0]['env'].append({'name': a.RUNTIME_ID_ENV, 'value': runtime_id})
    for item in data['containers']:
        item['OCI']['Annotations'].update({
            'io.kubernetes.cri.sandbox-name': '^os-supervisor-' + runtime_id + '$',
            'openshell.ai/sandbox-id': runtime_id})
    data['containers'][1]['OCI']['Process']['Env'].append(a.RUNTIME_ID_ENV + '=' + runtime_id)
    return pod, prefix, data


def test_runtime_uuid_changes_do_not_change_measured_policy(runtime_launch):
    import copy
    pod, prefix, data = runtime_launch
    original = copy.deepcopy((pod, data))
    first = a.compile_launch_policy(pod, prefix+'\n\npolicy_data := '+json.dumps(data))
    other_pod, other_data = copy.deepcopy((pod, data))
    old = '11111111-1111-4111-8111-111111111111'
    new = '22222222-2222-4222-8222-222222222222'
    other_pod = json.loads(json.dumps(other_pod).replace(old, new))
    other_data = json.loads(json.dumps(other_data).replace(old, new))
    second = a.compile_launch_policy(other_pod, prefix+'\n\npolicy_data := '+json.dumps(other_data))
    assert first == second
    assert (pod, data) == original
    measured = json.loads(first.split('policy_data := ',1)[1].replace(a.IDENTITY_MARKER,'null'))
    assert measured['request_defaults']['CreateContainerRequest']['allow_env_regex'] == [a.RUNTIME_ID_RULE]
    assert not any(e.startswith(a.RUNTIME_ID_ENV+'=') for e in measured['containers'][1]['OCI']['Process']['Env'])
    assert measured['containers'][1]['OCI']['Annotations']['openshell.ai/sandbox-id'] == '^'+a.RUNTIME_UUID_V4+'$'


@pytest.mark.parametrize('change', ['not-uuid','duplicate-id','missing-id','pod-name','annotation-id','annotation-name','extra-rule'])
def test_runtime_uuid_conversion_rejects_changed_driver_contract(runtime_launch,change):
    pod,prefix,data = runtime_launch
    if change == 'not-uuid': pod['spec']['containers'][0]['env'][-1]['value'] = '.*'
    elif change == 'duplicate-id': pod['spec']['containers'][0]['env'].append(pod['spec']['containers'][0]['env'][-1])
    elif change == 'missing-id': data['containers'][1]['OCI']['Process']['Env'].pop()
    elif change == 'pod-name': pod['metadata']['name'] = 'foreign-pod'
    elif change == 'annotation-id': data['containers'][0]['OCI']['Annotations']['openshell.ai/sandbox-id'] = 'foreign'
    elif change == 'annotation-name': data['containers'][0]['OCI']['Annotations']['io.kubernetes.cri.sandbox-name'] = '.*'
    else: data['request_defaults']['CreateContainerRequest']['allow_env_regex'].append('.*')
    with pytest.raises(a.AttestationError,match='^LaunchPolicyRejected$'):
        a.compile_launch_policy(pod,prefix+'\n\npolicy_data := '+json.dumps(data))


def test_runtime_uuid_rule_is_revalidated_in_enrollment(runtime_launch,launch_site):
    pod,prefix,data = runtime_launch
    original_entry = launch_site['attestation']['launchPolicies']['default/notebook']['supervisor']
    command = original_entry['pod']['spec']['containers'][0]['command']
    pod['spec']['containers'][0]['command'] = command
    data['containers'][1]['OCI']['Process']['Args'] = command
    template = a.compile_launch_policy(pod,prefix+'\n\npolicy_data := '+json.dumps(data))
    cfg = launch_site['attestation']
    cfg['launchPolicies']['default/notebook']['supervisor'] = {'pod':pod,'template':template}
    cfg['policyDigest'] = a.digest(cfg['launchPolicies'])
    assert a.validate(launch_site) == cfg
    cfg['launchPolicies']['default/notebook']['supervisor']['template'] = template.replace(a.RUNTIME_ID_RULE, '^OPENSHELL_SANDBOX_ID=.*$')
    cfg['policyDigest'] = a.digest(cfg['launchPolicies'])
    with pytest.raises(a.AttestationError,match='^AttestationLaunchPolicyRejected$'):
        a.validate(launch_site)


@pytest.mark.parametrize('runtime_id', ['11111111-1111-1111-8111-111111111111',
    '11111111-1111-4111-7111-111111111111', '11111111-1111-4111-8111-111111111111-extra',
    'prefix-11111111-1111-4111-8111-111111111111', '.*', ''])
def test_runtime_uuid_rule_is_anchored_and_version_four(runtime_id):
    import re
    assert re.fullmatch(a.RUNTIME_ID_RULE, a.RUNTIME_ID_ENV + '=' + runtime_id) is None


def test_explicit_host_namespace_denials_survive_original_manifest(launch_pod):
    launch_pod['spec'].update(hostPID=False, hostIPC=False, shareProcessNamespace=False)
    normalized = a.launch_policy_input(launch_pod)
    assert 'hostPID' not in normalized['spec'] and 'hostIPC' not in normalized['spec']
    assert normalized['spec']['shareProcessNamespace'] is False
    assert launch_pod['spec']['hostPID'] is False and launch_pod['spec']['hostIPC'] is False


@pytest.mark.parametrize('field', ['hostPID', 'hostIPC', 'shareProcessNamespace'])
def test_shared_process_namespace_is_rejected(launch_pod, field):
    launch_pod['spec'][field] = True
    with pytest.raises(a.AttestationError, match='^LaunchPolicyInputRejected$'):
        a.launch_policy_input(launch_pod)


@pytest.fixture
def strict_group_launch(generated_launch):
    pod, prefix, data = generated_launch
    pod['spec']['securityContext'].update(runAsGroup=1001, fsGroup=1001,
        supplementalGroups=[1002], supplementalGroupsPolicy='Strict')
    data['containers'][1]['OCI']['Process']['User'].update(GID=1001, AdditionalGids=[1001, 1002])
    return pod, prefix, data


def test_strict_groups_bind_the_generated_oci_identity(strict_group_launch):
    pod, prefix, data = strict_group_launch
    normalized = a.launch_policy_input(pod)
    assert 'supplementalGroupsPolicy' not in normalized['spec']['securityContext']
    assert pod['spec']['securityContext']['supplementalGroupsPolicy'] == 'Strict'
    assert a.compile_launch_policy(pod, prefix+'\n\npolicy_data := '+json.dumps(data))


@pytest.mark.parametrize('change', ['extra-group', 'missing-group', 'wrong-gid', 'merge-mode', 'boolean-group'])
def test_strict_groups_reject_changed_or_image_groups(strict_group_launch, change):
    pod, prefix, data = strict_group_launch
    user = data['containers'][1]['OCI']['Process']['User']
    reason = 'LaunchPolicyRejected'
    if change == 'extra-group': user['AdditionalGids'].append(0)
    elif change == 'missing-group': user['AdditionalGids'].pop()
    elif change == 'wrong-gid': user['GID'] = 0
    elif change == 'merge-mode':
        pod['spec']['securityContext']['supplementalGroupsPolicy'] = 'Merge'
        reason = 'LaunchPolicyInputRejected'
    else:
        pod['spec']['securityContext']['supplementalGroups'] = [True]
        reason = 'LaunchPolicyInputRejected'
    with pytest.raises(a.AttestationError, match='^'+reason+'$'):
        a.compile_launch_policy(pod, prefix+'\n\npolicy_data := '+json.dumps(data))


def test_workload_false_host_namespaces_are_removed_only_from_input(launch_pod):
    import copy
    launch_pod['spec'].update(hostPID=False, hostIPC=False, shareProcessNamespace=False)
    original = copy.deepcopy(launch_pod)
    result = a.launch_policy_input(launch_pod)
    assert launch_pod == original
    assert 'hostPID' not in result['spec'] and 'hostIPC' not in result['spec']
    assert result['spec']['shareProcessNamespace'] is False




@pytest.mark.parametrize('changed', [False, True])
def test_workload_low_port_sysctl_must_match_generated_oci(generated_launch, changed):
    pod, prefix, data = generated_launch
    pod['spec']['securityContext']['sysctls'] = [{'name':'net.ipv4.ip_unprivileged_port_start','value':'0'}]
    data['containers'][1]['OCI']['Linux'] = {'Sysctl': {'net.ipv4.ip_unprivileged_port_start':'1' if changed else '0'}}
    assert 'sysctls' not in a.launch_policy_input(pod)['spec']['securityContext']
    if changed:
        with pytest.raises(a.AttestationError, match='^LaunchPolicyRejected$'):
            a.compile_launch_policy(pod, prefix+'\n\npolicy_data := '+json.dumps(data))
    else:
        assert a.compile_launch_policy(pod, prefix+'\n\npolicy_data := '+json.dumps(data))


def test_unreviewed_sysctl_conversion_is_rejected(launch_pod):
    launch_pod['spec']['securityContext']['sysctls'] = [{'name':'kernel.example','value':'1'}]
    with pytest.raises(a.AttestationError, match='^LaunchPolicyInputRejected$'):
        a.launch_policy_input(launch_pod)


@pytest.fixture
def pvc_launch(generated_launch):
    pod,prefix,data = generated_launch
    pod['spec']['volumes'] = [
        {'name':'data','persistentVolumeClaim':{'claimName':'retained-data','readOnly':False}},
        {'name':'gate','persistentVolumeClaim':{'claimName':'trusted-gate','readOnly':True}}]
    pod['spec']['containers'][0]['volumeMounts'] = [
        {'name':'data','mountPath':'/sandbox/workspace','readOnly':False},
        {'name':'gate','mountPath':'/sandbox/.saw/trusted','readOnly':True}]
    data['containers'][1]['OCI']['Mounts'] = [
        {'destination':path,'source':'$(sfprefix)'+path.rsplit('/',1)[-1]+'$',
         'type_':'bind','options':['rbind','rprivate','rw']}
        for path in ['/sandbox/workspace','/sandbox/.saw/trusted']]
    return pod,prefix,data


def test_pvc_policy_narrows_the_protected_mount(pvc_launch):
    pod,prefix,data = pvc_launch
    assert a.launch_policy_input(pod)['spec']['volumes'][1]['persistentVolumeClaim'] == {'claimName':'trusted-gate'}
    template = a.compile_launch_policy(pod,prefix+'\n\npolicy_data := '+json.dumps(data))
    result = json.loads(template.split('policy_data := ',1)[1].replace(a.IDENTITY_MARKER,'null'))
    mounts = result['containers'][1]['OCI']['Mounts']
    assert mounts[0]['options'] == ['rbind','rprivate','rw']
    assert mounts[1]['options'] == ['rbind','rprivate','ro']
    assert pod['spec']['volumes'][1]['persistentVolumeClaim']['readOnly'] is True


@pytest.mark.parametrize('change',['source','missing','duplicate','options','mode'])
def test_pvc_policy_rejects_unreviewed_mounts(pvc_launch,change):
    pod,prefix,data = pvc_launch
    mounts=data['containers'][1]['OCI']['Mounts']
    if change=='source':mounts[1]['source']='.*'
    elif change=='missing':mounts.pop()
    elif change=='duplicate':mounts.append(dict(mounts[1]))
    elif change=='options':mounts[1]['options'].append('shared')
    else:pod['spec']['volumes'][1]['persistentVolumeClaim']['readOnly']='true'
    reason='LaunchPolicyInputRejected' if change=='mode' else 'LaunchPolicyRejected'
    with pytest.raises(a.AttestationError,match='^'+reason+'$'):
        a.compile_launch_policy(pod,prefix+'\n\npolicy_data := '+json.dumps(data))


@pytest.mark.parametrize('field',['subPath','subPathExpr'])
def test_subpath_is_rejected_before_the_generator(launch_pod,field):
    launch_pod['spec']['containers'][0]['volumeMounts']=[
        {'name':'trusted','mountPath':'/sandbox/.saw/trusted',field:'bundle'}]
    with pytest.raises(a.AttestationError,match='^LaunchPolicySubPathUnsupported$'):
        a.launch_policy_input(launch_pod)


def test_readonly_pvc_policy_cannot_be_widened_during_enrollment(pvc_launch,launch_site):
    import copy
    pod,prefix,data=pvc_launch
    command=launch_site['attestation']['launchPolicies']['default/notebook']['supervisor']['pod']['spec']['containers'][0]['command']
    pod['spec']['containers'][0]['command']=command
    data['containers'][1]['OCI']['Process']['Args']=command
    template=a.compile_launch_policy(pod,prefix+'\n\npolicy_data := '+json.dumps(data))
    policies=copy.deepcopy(launch_site['attestation']['launchPolicies'])
    policies['default/notebook']['supervisor']={'pod':pod,'template':template}
    assert a.validate_launch_policies(policies,a.digest(policies))==a.digest(policies)
    parsed=json.loads(template.split('policy_data := ',1)[1].replace(a.IDENTITY_MARKER,'null'))
    parsed['containers'][1]['OCI']['Mounts'][1]['options']=['rbind','rprivate','rw']
    parsed['saw_identity']=a.IDENTITY_MARKER
    changed=prefix+'\n\npolicy_data := '+a.canonical(parsed).replace('"'+a.IDENTITY_MARKER+'"',a.IDENTITY_MARKER)+'\n'
    policies['default/notebook']['supervisor']['template']=changed
    with pytest.raises(a.AttestationError,match='^AttestationLaunchPolicyRejected$'):
        a.validate_launch_policies(policies,a.digest(policies))


@pytest.mark.parametrize('gid',[0,1002])
def test_explicit_container_gid_cannot_change_in_policy(generated_launch,gid):
    pod,prefix,data=generated_launch
    pod['spec']['containers'][0]['securityContext']['runAsGroup']=1001
    data['containers'][1]['OCI']['Process']['User']['GID']=gid
    with pytest.raises(a.AttestationError,match='^LaunchPolicyRejected$'):
        a.compile_launch_policy(pod,prefix+'\n\npolicy_data := '+json.dumps(data))


@pytest.fixture
def confidential_agent(approved):
    import yaml
    site, _ = approved
    files = generic_profile_files()
    provider_key = "profiles__developer__default__providers.yaml"
    providers = yaml.safe_load(files[provider_key])
    providers["spec"]["providers"] = [
        {"name": "nvidia", "type": "nvidia", "credentialSecret": "inference"}]
    files[provider_key] = yaml.safe_dump(providers)
    sandbox_key = "profiles__developer__default__sandbox.yaml"
    sandboxes = yaml.safe_load(files[sandbox_key])
    sandboxes["spec"]["sandboxes"][0].update(type="openclaw", providers=["nvidia"], inference={
        "providerRef": "nvidia", "protocol": "openai", "baseUrl": "https://integrate.api.nvidia.com/v1",
        "model": "nvidia/nemotron-3.5-lightning-30b-a3b"})
    files[sandbox_key] = yaml.safe_dump(sandboxes)
    key = base64.b64encode(bytes.fromhex("302a300506032b6570032100") + bytes(range(32))).decode()
    gate = {"ownerLogin": "alice", "receiptKey": key,
            "trusted": {"claimName": "saw-gate-toolbox", "uid": "gate-uid", "readOnly": True},
            "audit": {"claimName": "saw-audit-toolbox", "uid": "audit-uid", "readOnly": False}}
    config = {"ownerID": UID, "namespace": "saw-alice", "namespaceUID": "namespace-uid",
              "ownerSubject": "alice-subject", "mode": "kata", "workloadRuntimeClass": "kata-remote",
              "workloadRuntimeClassUID": UID, "workloadRuntimeClassDigest": "c" * 64,
              "gatewayVersion": "0.1.2", "approvedCredentialFreeProviders": [],
              "credentialBindings": [{"type": "nvidia", "secret": "inference", "key": "api_key"}],
              "bindings": {"default/toolbox": {"workspace": {
                  "claimName": "workspace-toolbox", "uid": "pvc-uid", "readOnly": False}, "toolGate": gate}},
              "confidentialAttestation": {"settings": site["attestation"], "owner": "alice",
                  "registration": "0123456789abcdef", "installation": UID}}
    return files, config


def test_confidential_gate_publication_matches_compiled_root_mounts(confidential_agent, tmp_path):
    from saw_kubernetes.core import shared
    from saw_kubernetes.prepare_gate import publish
    files, config = confidential_agent
    gate = config["bindings"]["default/toolbox"]["toolGate"]
    identity = shared.tool_gate_identity("alice", "alice-subject", "default", "toolbox")
    digest = publish(tmp_path, identity, gate["receiptKey"], whole_volume=True)
    assert publish(tmp_path, identity, gate["receiptKey"], whole_volume=True) == digest
    spec = compile_profile_files(files, config)["workspaces"][0]["sandboxes"][0]["spec"]
    mounts = spec["template"]["driver_config"]["kubernetes"]["containers"]["agent"]["volume_mounts"]
    assert mounts == [
        {"name": "saw-workspace", "mount_path": "/sandbox/workspace", "read_only": False},
        {"name": "saw-gate", "mount_path": "/sandbox/.saw/gate-volume", "read_only": True},
        {"name": "saw-audit", "mount_path": "/sandbox/.saw/audit-volume", "read_only": False}]
    command = spec["command"][2]
    assert digest in command
    assert 'mountOptions("/sandbox/.saw/gate-volume")' in command
    assert 'mountOptions("/sandbox/.saw/audit-volume")' in command
    assert '/sandbox/.saw/gate-volume/bundle/plugin' in command
    assert '/sandbox/.saw/trusted' not in command
    assert '/sandbox/.saw/audit/' not in command
    assert (tmp_path / "bundle/plugin/index.js").is_file()
    assert b'/sandbox/.saw/audit-volume/log' in (tmp_path / "bundle/plugin/index.js").read_bytes()
    assert b'/sandbox/.saw/gate-volume/bundle' in (tmp_path / "bundle/plugin/tool-gate.mjs").read_bytes()
    # PR 173 replaces the same owner's gate tree atomically. The old tree
    # stays available to existing mounts; each startup verifies its own digest.
    ordinary_digest = publish(tmp_path, identity, gate["receiptKey"])
    assert ordinary_digest != digest
    assert any(tmp_path.glob("superseded-*/bundle/plugin/index.js"))
    assert publish(tmp_path, identity, gate["receiptKey"], whole_volume=True) == digest


@pytest.mark.parametrize("field,read_only", [("trusted", False), ("audit", True)])
def test_confidential_gate_rejects_wrong_mount_mode(confidential_agent, field, read_only):
    files, config = confidential_agent
    config["bindings"]["default/toolbox"]["toolGate"][field]["readOnly"] = read_only
    with pytest.raises(ContractError, match="mount mode"):
        compile_profile_files(files, config)


@pytest.mark.parametrize("gate_mode,audit_mode,valid", [("ro", "rw", True), ("rw", "rw", False), ("ro", "ro", False)])
def test_confidential_startup_checks_mount_roots_and_nested_digest(confidential_agent, gate_mode, audit_mode, valid):
    import shutil
    import subprocess
    from saw_kubernetes.core import shared
    if not shutil.which("node"):
        pytest.skip("node is required to execute the compiled startup check")
    files, config = confidential_agent
    gate = config["bindings"]["default/toolbox"]["toolGate"]
    tree, _, _, _ = shared.tool_gate_bundle(Path(shared.__file__).parent,
        shared.tool_gate_identity("alice", "alice-subject", "default", "toolbox"), gate["receiptKey"], whole_volume=True)
    command = compile_profile_files(files, config)["workspaces"][0]["sandboxes"][0]["spec"]["command"][2]
    check = command[command.index("const root ="):command.index("const target =")]
    mounted = {"/sandbox/.saw/gate-volume/bundle/" + rel: data.decode() for rel, (data, _) in tree.items()}
    mountinfo = ("1 0 0:1 / /sandbox/.saw/gate-volume " + gate_mode + " - nfs source " + gate_mode + "\n" +
                 "2 0 0:2 / /sandbox/.saw/audit-volume " + audit_mode + " - nfs source " + audit_mode)
    js = "const files=" + json.dumps(mounted) + "; const mountinfo=" + json.dumps(mountinfo) + ";" + """
const crypto = require('crypto'); const config = {};
const fs = {constants: {}, readFileSync: p => p === '/proc/self/mountinfo' ? mountinfo : files[p],
  readdirSync: dir => [...new Set(Object.keys(files).filter(p=>p.startsWith(dir+'/'))
    .map(p=>p.slice(dir.length+1).split('/')[0]))].map(name=>({name,
      isDirectory:()=>Object.keys(files).some(p=>p.startsWith(dir+'/'+name+'/')),
      isFile:()=>Object.hasOwn(files,dir+'/'+name)}))};
"""
    result = subprocess.run(["node", "-e", js + check], capture_output=True, text=True)
    assert (result.returncode == 0) is valid, result.stderr


def test_confidential_model_and_browser_use_the_published_bundle(confidential_agent, tmp_path):
    from saw_kubernetes.core import shared
    from saw_kubernetes.prepare_gate import publish, publish_browser_proof, verify
    files, config = confidential_agent
    binding = config["bindings"]["default/toolbox"]
    binding["browser"] = {"origin": "https://workspace.example.test", "ownerLogin": "alice"}
    gate = binding["toolGate"]
    gate["modelSelector"] = True
    identity = shared.tool_gate_identity("alice", "alice-subject", "default", "toolbox")
    digest = publish(tmp_path, identity, gate["receiptKey"], whole_volume=True,
                     model="nvidia/test-model", generation=2, browser=True)
    publish_browser_proof(tmp_path / "bundle", b"a" * 64)
    tree, _, _, _ = shared.tool_gate_bundle(Path(shared.__file__).parent, identity,
                                           gate["receiptKey"], whole_volume=True)
    verify(tmp_path / "bundle", tree, model_selector=True, browser=True)
    command = compile_profile_files(files, config)["workspaces"][0]["sandboxes"][0]["spec"]["command"]
    assert command[-1] == "model-from-gate"
    assert digest in command[2]
    assert "/sandbox/.saw/gate-volume/bundle/model.json" in command[2]
    assert "/sandbox/.saw/gate-volume/bundle/relay-proof" in command[2]
    assert "/sandbox/.saw/trusted" not in command[2]


@pytest.fixture
def launch_process(launch_site):
    cfg = launch_site["attestation"]
    roles = cfg["launchPolicies"]["default/notebook"]
    roles["workload"]["pod"]["spec"]["containers"][0]["name"] = "agent"
    spec = {"command": ["sh", "-ec", "sleep infinity"], "tty": False, "template": {"image": IMAGE}}
    main = {"version": 1, "command": spec["command"], "tty": False, "await_main_process_attachment": False}
    entry = {"name": "OPENSHELL_MAIN_PROCESS_SPEC", "value": json.dumps(main)}
    roles["supervisor"]["pod"]["spec"]["containers"][0]["env"].append(entry)
    return cfg, spec, entry


def test_enrolled_main_process_matches_compiled_agent(launch_process):
    cfg, spec, _ = launch_process
    a.verify_launch_spec(cfg, "default/notebook", spec)


@pytest.mark.parametrize("change", ["command", "tty", "version", "await", "extra", "missing", "duplicate", "duplicate-json", "image", "slot", "projection"])
def test_changed_main_process_is_rejected_without_input_values(launch_process, change):
    cfg, spec, entry = launch_process
    slot = "default/notebook"
    data = json.loads(entry["value"])
    if change == "command": data["command"] = ["private-fixture-marker"]
    elif change == "tty": data["tty"] = True
    elif change == "version": data["version"] = True
    elif change == "await": data["await_main_process_attachment"] = True
    elif change == "extra": data["private-fixture-marker"] = True
    elif change == "missing": entry["name"] = "OTHER"
    elif change == "duplicate":
        cfg["launchPolicies"][slot]["supervisor"]["pod"]["spec"]["containers"][0]["env"].append(dict(entry))
    elif change == "image": spec["template"]["image"] = "private-fixture-marker"
    elif change == "slot": slot = "foreign/slot"
    elif change == "projection": entry["valueFrom"] = {"secretKeyRef": {"name": "private-fixture-marker", "key": "key"}}
    entry["value"] = json.dumps(data)
    if change == "duplicate-json": entry["value"] = '{"version":0,' + entry["value"][1:]
    with pytest.raises(a.AttestationError, match="^AttestationLaunchSpecMismatch$"):
        a.verify_launch_spec(cfg, slot, spec)


def test_unapproved_confidential_harness_fails_before_plan_publication(confidential_agent):
    import yaml
    files, cfg = confidential_agent
    name = "profiles__developer__default__sandbox.yaml"
    document = yaml.safe_load(files[name])
    document["spec"]["sandboxes"][0]["harnessRef"] = {"name": "optional", "digest": "sha256:" + "a" * 64}
    files[name] = yaml.safe_dump(document)
    with pytest.raises(ContractError) as error:
        compile_profile_files(files, cfg)
    assert "harness" in str(error.value).lower()


@pytest.mark.parametrize("ending", ["", "\n"])
def test_guest_image_policy_accepts_pem_public_key(approved, ending):
    site, _ = approved
    rule = site["attestation"]["imagePolicy"]["transports"]["docker"]["registry.example.test"][0]
    public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode().rstrip("\n") + ending
    rule.pop("keyPath")
    rule["keyData"] = public
    assert a.validate(site) is site["attestation"]


@pytest.mark.parametrize("fault", ["base64-pem", "private-label", "malformed-base64", "empty", "both", "neither", "path-type"])
def test_guest_image_policy_rejects_wrong_key_encoding_safely(approved, fault):
    site, _ = approved
    rule = site["attestation"]["imagePolicy"]["transports"]["docker"]["registry.example.test"][0]
    public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    rule.pop("keyPath")
    rule["keyData"] = public
    if fault == "base64-pem": rule["keyData"] = base64.b64encode(public.encode()).decode()
    elif fault == "private-label": rule["keyData"] = public.replace("PUBLIC KEY", "PRIVATE KEY")
    elif fault == "malformed-base64": rule["keyData"] = "-----BEGIN PUBLIC KEY-----\nprivate-fixture-marker\n-----END PUBLIC KEY-----\n"
    elif fault == "empty": rule["keyData"] = ""
    elif fault == "both": rule["keyPath"] = "/etc/pki/public.pem"
    elif fault == "neither": rule.pop("keyData")
    elif fault == "path-type": rule = {"type": "sigstoreSigned", "keyPath": 1}
    site["attestation"]["imagePolicy"]["transports"]["docker"]["registry.example.test"] = [rule]
    with pytest.raises(a.AttestationError, match="^GuestImagePolicyKeyRejected$"):
        a.validate(site)


@pytest.fixture
def deployable_launch_site(launch_site, approved):
    import copy
    site = copy.deepcopy(launch_site)
    _, source_objects = approved
    objects = copy.deepcopy(source_objects)
    ref = site["attestation"]["references"]["qualification"]
    objects[ref["path"]]["data"]["policyDigest"] = site["attestation"]["policyDigest"]
    ref["sha256"] = a.digest(objects[ref["path"]]["data"])
    return site, objects


@pytest.mark.parametrize("chart", ["saw-portal-container", "saw-users", "openshell-rhdh"])
def test_qualified_launch_preflight_passes_without_secret_reads(deployable_launch_site, monkeypatch, chart):
    site, objects = deployable_launch_site
    spec = importlib.util.spec_from_file_location("qualified_preflight_" + chart,
        ROOT / "charts" / chart / "files/preflight.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    # Use the same pinned-rule test module as the launch-policy fixture.
    monkeypatch.setattr(module, "_attestation_module", lambda: a)
    calls = []
    def read(path):
        calls.append(path)
        return objects[path]
    result = module.verify_attestation(site, "kata", read,
        lambda request, context, timeout: _ProbeResponse(401))
    assert result == a.digest(site["attestation"])
    assert set(calls) == {ref["path"] for ref in site["attestation"]["references"].values()}
    assert all("/secrets/" not in path for path in calls)


@pytest.mark.parametrize("change", ["changed", "missing", "denied", "unqualified"])
def test_deployment_approval_failure_stops_before_endpoint_probe(deployable_launch_site, change):
    site, objects = deployable_launch_site
    ref = site["attestation"]["references"]["qualification"]
    if change == "changed": objects[ref["path"]]["metadata"]["uid"] = "replaced"
    if change == "missing": del objects[ref["path"]]
    if change == "unqualified":
        obj = objects[ref["path"]]
        obj["data"]["negativeTests"] = "pending"
        ref["sha256"] = a.digest(obj["data"])
    def read(path):
        if change == "denied": raise PermissionError("private input")
        return objects[path]
    expected = "AttestationQualificationMissing" if change == "unqualified" else (
        "AttestationApprovalChanged" if change == "changed" else "AttestationDependencyUnavailable")
    with pytest.raises(a.AttestationError, match="^" + expected + "$"):
        a.verify_deployment(site, read, probe_kbs=lambda *args: pytest.fail("endpoint read after approval failure"))


def test_legacy_policy_cannot_reach_deployment_api_or_endpoint(approved):
    site, _ = approved
    with pytest.raises(a.AttestationError, match="^AttestationLaunchPolicyRequired$"):
        a.verify_deployment(site, lambda *args: pytest.fail("legacy policy reached API"),
                            probe_kbs=lambda *args: pytest.fail("legacy policy reached Trustee"))


def test_projector_scopes_approval_reads_to_one_validated_site(deployable_launch_site, monkeypatch):
    site, _ = deployable_launch_site
    source = ROOT / "charts/saw-users/files"
    for name in ("workspace", "preflight"):
        spec = importlib.util.spec_from_file_location(name, source / (name + ".py"))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(sys.modules["preflight"], "_attestation_module", lambda: a)
    spec = importlib.util.spec_from_file_location("scoped_projector", source / "projector.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    reader = object.__new__(module.Publications)
    calls = []
    reader.get = lambda path: calls.append(path) or {"metadata": {"uid": UID}}
    path = site["attestation"]["references"]["trustee"]["path"]
    with pytest.raises(module.ProjectionError): reader.preflight_resource(path)
    scoped = reader.preflight_for_site(site, "kata")
    assert scoped(path)["metadata"]["uid"] == UID
    for foreign in ("/api/v1/namespaces/trustee-system/secrets/private",
                    "/apis/apps/v1/namespaces/trustee-system/deployments/foreign"):
        with pytest.raises(module.ProjectionError): scoped(foreign)
    assert calls == [path]



def test_projection_prepares_public_placement_before_first_enrollment(launch_site, monkeypatch):
    import copy
    spec = importlib.util.spec_from_file_location("launch_workspace", ROOT / "charts/saw-users/files/workspace.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    monkeypatch.setattr(module, "_attestation_module", lambda: a)
    site = copy.deepcopy(launch_site)
    references = {"inference": "secret/data/hub/saw-alice/credentials/inference"}
    site.update(subject=UID, automaticEnrollment={"enabled": False},
                kataRuntimeClass={"name": "kata-remote", "uid": UID, "sha256": "a"*64},
                credentialReferences={"developer": references}, preparedConfidential={"untrusted": True})
    before = copy.deepcopy(site)
    owner = {"name": "alice", "registration": "0123456789abcdef", "installationID": UID,
             "ownerSubject": UID, "profiles": ["developer"], "credentialReferences": references,
             "values": {"deployment": {"mode": "kata"}}}
    catalog = {"developer": {"workspaces": [{"name": "default", "enabled": True, "sandboxes": [
        {"name": "notebook", "enabled": True, "image": IMAGE}]}]}}
    result = module.project_workspace(owner, {}, site, catalog, lambda _: {})
    prepared = result["containerSites"]["alice"]
    assert "enrollment" not in prepared
    assert prepared["preparedConfidential"] == a.placement_contract(
        site, "alice", "0123456789abcdef", UID, ["default/notebook"], "kata-remote")
    assert prepared["credentialReferences"] == references
    assert site == before


def test_confidential_approval_set_matches_the_enrollment_chart(launch_site, monkeypatch):
    from saw_kubernetes import boundary
    monkeypatch.setattr(boundary, "attestation", a)
    config = {"namespace": "saw-alice", "trustedNamespace": "saw-ctl-0123456789abcdef",
              "governanceNamespace": "governance", "gateway": "alice", "ownerID": UID,
              "mode": "kata", "confidentialProviderPolicy": "alice-confidential-provider-policy",
              "confidentialAttestation": {"settings": launch_site["attestation"], "owner": "alice",
                  "registration": "0123456789abcdef", "installation": UID}}
    result = boundary.objects(config)
    assert len(result) == 31
    assert not {"proxy", "proxyNetwork", "proxyPolicy", "publicCA"}.intersection(result)
    assert {"confidential"+key[0].upper()+key[1:] for key in launch_site["attestation"]["references"]} <= result.keys()



@pytest.fixture
def trustee_deployment_spec():
    base = {"name": "repository-dir", "mountPath": "/opt/confidential-containers/storage/repository"}
    return {"replicas": 1, "template": {"spec": {
        "volumes": [{"name": "repository-dir", "emptyDir": {"medium": "Memory"}}],
        "initContainers": [{"name": "secret-converter", "image": IMAGE, "volumeMounts": [dict(base)]}],
        "containers": [{"name": "kbs", "image": IMAGE, "volumeMounts": [dict(base)]}]}}}


def add_trustee_resource_mount(spec, name):
    pod = spec["template"]["spec"]
    pod["volumes"].append({"name": name, "secret": {"secretName": name, "defaultMode": 420}})
    pod["initContainers"][0]["volumeMounts"].append({"name": name, "mountPath": "/tmp/kbs-secrets/" + name})


def test_trustee_resource_mounts_do_not_invalidate_code_approval(trustee_deployment_spec):
    spec = trustee_deployment_spec
    approved = a.trustee_deployment_digest(spec)
    add_trustee_resource_mount(spec, "saw-alice-0123456789abcdef")
    assert a.trustee_deployment_digest(spec) == approved
    add_trustee_resource_mount(spec, "saw-bob-fedcba9876543210")
    assert a.trustee_deployment_digest(spec) == approved
    # An unrelated application resource stays in the approval hash.
    spec["template"]["spec"]["volumes"].append({"name": "unrelated-resource", "secret": {"secretName": "other", "defaultMode": 420}})
    assert a.trustee_deployment_digest(spec) != approved


@pytest.mark.parametrize("change", ["source", "permissions", "path", "subPath", "reader", "missing", "duplicate"])
def test_changed_trustee_input_mount_is_not_normalized(trustee_deployment_spec, change):
    spec = trustee_deployment_spec
    name = "saw-alice-0123456789abcdef"
    add_trustee_resource_mount(spec, name)
    pod = spec["template"]["spec"]
    volume = pod["volumes"][-1]
    mount = pod["initContainers"][0]["volumeMounts"][-1]
    if change == "source": volume["secret"]["secretName"] = "foreign-secret"
    if change == "permissions": volume["secret"]["defaultMode"] = 511
    if change == "path": mount["mountPath"] = "/etc/unapproved"
    if change == "subPath": mount["subPath"] = "inference"
    if change == "reader":
        pod["containers"][0]["volumeMounts"].append(mount)
        pod["initContainers"][0]["volumeMounts"].pop()
    if change == "missing": pod["initContainers"][0]["volumeMounts"].pop()
    if change == "duplicate": pod["volumes"].append(dict(volume))
    with pytest.raises(a.AttestationError, match="^TrusteeResourceMountRejected$"):
        a.trustee_deployment_digest(spec)


@pytest.mark.parametrize("change", ["image", "command", "security", "repository"])
def test_trustee_code_and_security_stay_pinned(trustee_deployment_spec, change):
    spec = trustee_deployment_spec
    before = a.trustee_deployment_digest(spec)
    add_trustee_resource_mount(spec, "saw-alice-0123456789abcdef")
    pod = spec["template"]["spec"]
    if change == "image": pod["containers"][0]["image"] = "registry.example.test/other@sha256:" + "f"*64
    if change == "command": pod["initContainers"][0]["command"] = ["unapproved-command"]
    if change == "security": pod["containers"][0]["securityContext"] = {"privileged": True}
    if change == "repository": pod["volumes"][0]["emptyDir"]["medium"] = ""
    assert a.trustee_deployment_digest(spec) != before


@pytest.mark.parametrize("state", ["ready", "missing", "old-generation", "old-pod", "unready", "code-change"])
def test_enrollment_waits_for_own_resource_rollout(deployable_launch_site, trustee_deployment_spec, state):
    site, objects = deployable_launch_site
    ref = site["attestation"]["references"]["trustee"]
    ref["sha256"] = a.trustee_deployment_digest(trustee_deployment_spec)
    obj = {"metadata": {"uid": ref["uid"], "generation": 2}, "spec": trustee_deployment_spec,
           "status": {"observedGeneration": 2, "readyReplicas": 1, "updatedReplicas": 1, "replicas": 1}}
    if state != "missing": add_trustee_resource_mount(obj["spec"], "saw-alice-0123456789abcdef")
    if state == "old-generation": obj["status"]["observedGeneration"] = 1
    if state == "old-pod": obj["status"]["replicas"] = 2
    if state == "unready": obj["status"]["readyReplicas"] = 0
    if state == "code-change": obj["spec"]["template"]["spec"]["containers"][0]["command"] = ["foreign"]
    objects[ref["path"]] = obj
    if state == "ready":
        assert a.verify_resource_rollout(site, "alice", "0123456789abcdef", objects.__getitem__)
    else:
        reason = "AttestationApprovalChanged" if state == "code-change" else "CredentialResourceUnavailable"
        with pytest.raises(a.AttestationError, match="^" + reason + "$"):
            a.verify_resource_rollout(site, "alice", "0123456789abcdef", objects.__getitem__)


def test_enrollment_reads_fresh_membership_and_rollout_after_patch(
        deployable_launch_site, trustee_deployment_spec, monkeypatch):
    """Execute the real enrollment function with API snapshots, without its CLI."""
    import ast
    import copy
    import urllib.error
    site, objects = deployable_launch_site
    cfg = site["attestation"]
    trustee_ref = cfg["references"]["trustee"]
    trustee_ref["sha256"] = a.trustee_deployment_digest(trustee_deployment_spec)
    objects[trustee_ref["path"]] = {
        "metadata": {"uid": trustee_ref["uid"], "generation": 1}, "spec": trustee_deployment_spec,
        "status": {"observedGeneration": 1, "replicas": 1, "readyReplicas": 1, "availableReplicas": 1, "updatedReplicas": 1}}
    config_ref = cfg["references"]["trusteeConfig"]
    objects[config_ref["path"]]["metadata"]["resourceVersion"] = "1"
    eso_path, eso = _trustee_external_secret(site)
    objects[eso_path] = eso
    objects["/api/v1/namespaces/saw-alice"] = {
        "metadata": {"uid": UID, "labels": {"saw.redhat.com/runtime-owner": UID}}}
    objects["/apis/node.k8s.io/v1/runtimeclasses/kata-remote"] = {}
    objects["/apis/kataconfiguration.openshift.io/v1/kataconfigs"] = {"items": []}
    objects["/api/v1/nodes"] = {"items": []}
    objects["/apis/config.openshift.io/v1/clusterversions/version"] = {}
    objects["/apis/admissionregistration.k8s.io/v1"] = {}
    for name in ("kataconfigs.kataconfiguration.openshift.io", "sandboxes.agents.x-k8s.io",
                 "externalsecrets.external-secrets.io", "adminnetworkpolicies.policy.networking.k8s.io"):
        objects["/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + name] = {}
    calls = []
    def api(path, patch=None):
        calls.append((path, patch is not None))
        if patch is not None:
            assert path == config_ref["path"]
            assert patch["metadata"]["resourceVersion"] == "1"
            objects[path]["spec"].update(patch["spec"])
            objects[path]["metadata"]["resourceVersion"] = "2"
            deployment = objects[trustee_ref["path"]]
            add_trustee_resource_mount(deployment["spec"], "saw-alice-0123456789abcdef")
            deployment["metadata"]["generation"] = 2
            deployment["status"]["observedGeneration"] = 2
        return copy.deepcopy(objects[path])
    class Captured(Exception): pass
    class RetryEnrollment(Exception): pass
    def capture(config, read):
        assert read(config_ref["path"])["metadata"]["resourceVersion"] == "2"
        assert read(trustee_ref["path"])["metadata"]["generation"] == 2
        raise Captured()
    monkeypatch.setattr(a, "verify_kbs_reachability", lambda *args: True)
    source = ROOT / "charts/saw-portal-container/files/enroll.py"
    function = next(node for node in ast.parse(source.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name == "once")
    namespace = {"api": api, "attestation": a, "capture": capture,
                 "RetryEnrollment": RetryEnrollment, "PreflightError": ValueError,
                 "urllib": urllib, "verify_kata_platform": lambda *args: None,
                 "crd_established": lambda *args: True, "api_resources_available": lambda *args: True}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
    with pytest.raises(Captured):
        namespace["once"]({"user": "alice", "registration": "0123456789abcdef", "subject": UID,
                           "installation": UID, "governance": "governance", "reference": {},
                           "targets": {"default/notebook": {}}, "attestation": cfg,
                           "kataRuntimeClass": {"name": "kata-remote"}})
    assert sum(patch for _, patch in calls) == 1
    assert all("/secrets/" not in path for path, _ in calls)


def test_real_kata_notebook_harness_uses_verified_whole_volume(confidential_agent):
    import subprocess, yaml
    from saw_kubernetes.core import shared
    from saw_kubernetes.harness import read_bundles
    _, cfg = confidential_agent
    rendered = subprocess.run(["helm", "template", "fixture", str(ROOT/"charts/saw-bom"),
        "--set", "profiles[0]=kata-data-science", "--set", "harnessEnabled=true",
        "--set", "webSearch.enabled=false"], text=True,capture_output=True,check=True)
    files = yaml.safe_load(rendered.stdout)["data"]
    _, raw, index = shared.split_bom_files(files)
    bundle = read_bundles(raw, index)["ds-default"]
    slot = cfg["bindings"].pop("default/toolbox")
    slot["toolGate"]["harness"] = {"name":bundle.name,"digest":bundle.digest}
    slot["browser"] = {"ownerLogin":"alice","origin":"https://workspace.example.test"}
    cfg["bindings"]["default/notebook"] = slot
    plan = compile_profile_files(files,cfg)
    spec = plan["workspaces"][0]["sandboxes"][0]["spec"]
    mounts = spec["template"]["driver_config"]["kubernetes"]["containers"]["agent"]["volume_mounts"]
    assert len(mounts) == 3 and all("sub_path" not in m for m in mounts)
    assert bundle.digest in spec["command"][2]
    assert "/sandbox/.saw/gate-volume/harness-" in spec["command"][2]
    assert 'mountOptions("/sandbox/.saw/gate-volume")' in spec["command"][2]
    assert "/sandbox/harness" not in spec["command"][2]
    assert "harness digest mismatch" in spec["command"][2]
    assert not any("credentialRef" in p for p in plan["workspaces"][0]["providers"])


@pytest.mark.parametrize("scope", ["pod", "container"])
def test_admission_mcs_label_is_host_only(launch_pod, scope):
    import copy
    security = (launch_pod["spec"]["securityContext"] if scope == "pod"
                else launch_pod["spec"]["containers"][0]["securityContext"])
    security["seLinuxOptions"] = {"level": "s0:c29,c19"}
    original = copy.deepcopy(launch_pod)
    result = a.launch_policy_input(launch_pod)
    assert launch_pod == original
    converted = (result["spec"]["securityContext"] if scope == "pod"
                 else result["spec"]["containers"][0]["securityContext"])
    assert "seLinuxOptions" not in converted


@pytest.mark.parametrize("value", [{"type": "unconfined_t"}, {"level": "s0"},
    {"level": "s0:c1,c2", "user": "system_u"}, {"level": 1}, "s0:c1,c2"])
def test_custom_selinux_conversion_is_rejected(launch_pod, value):
    launch_pod["spec"]["securityContext"]["seLinuxOptions"] = value
    with pytest.raises(a.AttestationError, match="^LaunchPolicyInputRejected$"):
        a.launch_policy_input(launch_pod)
