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

@pytest.fixture
def approved():
    policy = ("package agent_policy\n"
              "policy_data := {\n"
              '  "saw_identity": __SAW_IDENTITY_JSON__,\n'
              '  "containers": []\n'
              "}\n"
              "default ExecProcessRequest := false\n"
              "default SetPolicyRequest := false\n")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"trustee.example.test")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
        .sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
    cfg = dict(enabled=True, schemaVersion=1, tee="snp", kbsURL="https://trustee.example.test",
               kbsCA=certificate,
               policyDigest=hashlib.sha256(policy.encode()).hexdigest(), referenceSet="b"*64,
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
        "referenceValues":{"data":{"referenceSet":cfg["referenceSet"]}},
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
    assert tomllib.loads(parsed["data"]["cdh.toml"])["kbc"]["kbs_cert"]==site["attestation"]["kbsCA"]
    generated_policy=parsed["data"]["policy.rego"]
    assert "__SAW_IDENTITY_JSON__" not in generated_policy
    assert '"saw_identity": '+a.canonical(result["identity"]) in generated_policy
    assert "saw-identity" not in generated_policy
    assert a.initdata(*args[:-1],"workload")["sha256"]!=result["sha256"]
    assert a.initdata(site,"alice","fedcba9876543210",UID,"default/notebook","supervisor")["sha256"]!=result["sha256"]


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
def test_no_confidential_request_can_fall_back_to_legacy_proxy(approved,chart):
    site,objects=approved
    spec=importlib.util.spec_from_file_location("preflight_"+chart,ROOT/"charts"/chart/"files/preflight.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with pytest.raises(module.PreflightError,match="^AttestationIntegrationUnavailable$"):
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
    ("referenceValues", {"referenceSet":"e"*64}, "ReferenceValuesRejected"),
])
def test_reapproved_bad_platform_still_fails(approved,key,value,reason):
    site,objects=approved
    ref=site["attestation"]["references"][key]
    objects[ref["path"]]["data"].update(value)
    ref["sha256"]=a.digest(objects[ref["path"]]["data"])
    with pytest.raises(a.AttestationError,match="^"+reason+"$"):
        a.verify_platform(site,objects.__getitem__)

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
