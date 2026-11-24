"""Cluster-independent policy tests use public, synthetic claims only."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from datetime import datetime

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kubernetes-runtime"))
from saw_kubernetes.trustee_policy import PolicyError, render, is_policy_denial


@pytest.fixture
def approval():
    return {"schemaVersion": 1, "bindings": [{
        "owner": "alice", "registration": "0123456789abcdef",
        "installation": "11111111-1111-4111-8111-111111111111",
        "slot": "default/notebook", "role": "supervisor", "pcr08": "a" * 64,
        "initdataSHA256": "b" * 64, "referenceSetSHA256": "c" * 64,
        "expiresAt": "2099-01-01T00:00:00Z", "resources": ["image-policy", "inference"]}]}


@pytest.fixture
def claims():
    return {"submods": {"cpu0": {
        "ear.trustworthiness-vector": {"executables": 3, "configuration": 2, "hardware": 2},
        "ear.veraison.annotated-evidence": {"init_data": "a" * 64, "az-snp-vtpm": {
            "policy_debug_allowed": "false", "policy_migrate_ma": "false",
            "tpm": {"pcr08": "a" * 64}}}}}}


@pytest.fixture
def evaluate(tmp_path):
    opa = os.environ.get("OPA") or shutil.which("opa")
    if not opa:
        pytest.skip("OPA is required for executable Rego policy cases")
    def run(approval, claims, path=None, plugin="resource", at_time=None):
        policy = tmp_path / "policy.rego"
        policy.write_text(render(approval))
        request = tmp_path / "request.json"
        request.write_text(json.dumps({"plugin": plugin, "resource-path": path or
            ["default", "saw-alice-0123456789abcdef", "inference"]}))
        command = [opa, "eval", "--format=json", "--data", str(policy),
                   "--data", str(request), "--stdin-input"]
        query = "data.policy.allow"
        if at_time:
            timestamp = int(datetime.fromisoformat(at_time.replace("Z", "+00:00")).timestamp()) * 1_000_000_000
            query += f" with time.now_ns as {timestamp}"
        command.append(query)
        result = subprocess.run(command, input=json.dumps(claims), text=True,
                                capture_output=True, check=True)
        return json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
    return run


def test_render_is_deterministic_and_contains_no_credential(approval):
    assert render(approval) == render(copy.deepcopy(approval))
    assert "default allow := false" in render(approval)
    assert "api_key" not in render(approval)


@pytest.mark.parametrize("field,value", [
    ("owner", "alice/foreign"), ("registration", "new"), ("installation", "invalid"),
    ("slot", "../slot"), ("role", "gateway"), ("pcr08", "unreviewed-input"),
    ("initdataSHA256", "short"), ("referenceSetSHA256", "short"),
    ("expiresAt", "2020-01-01T00:00:00Z"), ("resources", ["*"]),
    ("resources", ["inference", "inference"]), ("resources", []),
])
def test_bad_approvals_fail_with_fixed_reason(approval, field, value):
    approval["bindings"][0][field] = value
    with pytest.raises(PolicyError, match="^TrusteeMeasurementApprovalRejected$"):
        render(approval)


def test_a_measurement_cannot_bind_two_identities(approval):
    other = dict(approval["bindings"][0], owner="bob")
    approval["bindings"].append(other)
    with pytest.raises(PolicyError, match="^TrusteeMeasurementApprovalRejected$"):
        render(approval)


def test_workload_binding_cannot_request_credentials(approval):
    approval["bindings"][0]["role"] = "workload"
    with pytest.raises(PolicyError):
        render(approval)


def test_exact_approved_measurement_can_fetch_own_resource(approval, claims, evaluate):
    assert evaluate(approval, claims) is True


@pytest.mark.parametrize("role", ["supervisor", "workload"])
def test_both_roles_can_fetch_only_their_image_policy(approval, claims, evaluate, role):
    approval["bindings"][0].update(role=role, resources=["image-policy"])
    assert evaluate(approval, claims, ["default", "saw-alice-0123456789abcdef", "image-policy"])
    assert evaluate(approval, claims) is False


@pytest.mark.parametrize("path", [
    ["default", "saw-bob-0123456789abcdef", "inference"],
    ["default", "saw-alice-fedcba9876543210", "inference"],
    ["default", "saw-alice-0123456789abcdef", "web-search"],
    ["default", "saw-alice-0123456789abcdef", "inference", "extra"],
    ["foreign", "saw-alice-0123456789abcdef", "inference"],
    "default/saw-alice-0123456789abcdef/inference",
])
def test_foreign_or_malformed_resource_is_denied(approval, claims, evaluate, path):
    assert evaluate(approval, claims, path) is False


@pytest.mark.parametrize("field,value", [
    ("policy_debug_allowed", "true"), ("policy_debug_allowed", True),
    ("policy_debug_allowed", 0), ("policy_debug_allowed", "False"),
    ("policy_migrate_ma", "true"), ("policy_migrate_ma", True),
])
def test_unsafe_or_noncanonical_guest_configuration_is_denied(approval, claims, evaluate, field, value):
    claims["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["az-snp-vtpm"][field] = value
    assert evaluate(approval, claims) is False


def test_boolean_false_is_supported_without_truthiness_coercion(approval, claims, evaluate):
    platform = claims["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["az-snp-vtpm"]
    platform.update(policy_debug_allowed=False, policy_migrate_ma=False)
    assert evaluate(approval, claims)


@pytest.mark.parametrize("change", ["pcr", "init", "missing-debug", "missing-measurement", "missing-evidence", "bad-vector", "extra-device", "fake-owner", "wrong-plugin", "revoked"])
def test_unapproved_evidence_and_revocation_fail_closed(approval, claims, evaluate, change):
    cpu = claims["submods"]["cpu0"]
    evidence = cpu["ear.veraison.annotated-evidence"]
    plugin = "resource"
    if change == "pcr": evidence["az-snp-vtpm"]["tpm"]["pcr08"] = "d" * 64
    elif change == "init": evidence["init_data"] = "d" * 64
    elif change == "missing-debug": del evidence["az-snp-vtpm"]["policy_debug_allowed"]
    elif change == "missing-measurement": del evidence["az-snp-vtpm"]["tpm"]
    elif change == "missing-evidence": del cpu["ear.veraison.annotated-evidence"]
    elif change == "bad-vector": cpu["ear.trustworthiness-vector"]["executables"] = 33
    elif change == "extra-device": claims["submods"]["cpu1"] = copy.deepcopy(cpu)
    elif change == "fake-owner":
        evidence["init_data"] = evidence["az-snp-vtpm"]["tpm"]["pcr08"] = "d" * 64
        evidence["init_data_claims"] = {"saw_identity": {"owner": "alice"}}
    elif change == "wrong-plugin": plugin = "auth"
    elif change == "revoked": approval["bindings"] = []
    assert evaluate(approval, claims, plugin=plugin) is False


def test_expiry_is_enforced_when_the_policy_runs(approval, claims, evaluate):
    assert evaluate(approval, claims, at_time="2100-01-01T00:00:00Z") is False


def test_cli_errors_do_not_expose_approval_values(tmp_path):
    approval = tmp_path / "bad.json"
    approval.write_text('{"private-input-marker":"do-not-display"}')
    result = subprocess.run([sys.executable, str(ROOT / "scripts/trustee-resource-policy.py"),
                             "--approvals", str(approval)], capture_output=True, text=True)
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.strip() == "TrusteeMeasurementApprovalRejected"


@pytest.mark.parametrize("status,body,expected", [
    (401, b'{"type":"https://github.com/confidential-containers/kbs/errors/PolicyDeny","detail":"Access denied by policy"}', True),
    (401, b'{"type":"AuthenticationFailed"}', False),
    (401, b'{"error_type":"https://github.com/confidential-containers/kbs/errors/PolicyDeny"}', False),
    (403, b'{"type":"https://github.com/confidential-containers/kbs/errors/PolicyDeny"}', False),
    (200, b'{"type":"https://github.com/confidential-containers/kbs/errors/PolicyDeny"}', False),
    (401, b'not-json', False), (401, b'[]', False), (401, b'x' * 4097, False),
])
def test_protocol_denial_is_distinct_from_authentication_failure(status, body, expected):
    assert is_policy_denial(status, body) is expected
