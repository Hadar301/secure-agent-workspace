"""Render a default-deny Trustee policy from administrator-approved measurements.

This renderer accepts public approval records only. It does not read credentials,
verify measurement provenance, install policy, or enable confidential enrollment.
"""
import json
import re
import uuid
from datetime import datetime, timezone


class PolicyError(ValueError):
    """A fixed error reason that does not expose approval input."""


_POLICY = '''package policy

import rego.v1

default allow := false

approved_bindings := __BINDINGS__

# KBS supplies input from a verified attestation token, not request parameters.
allow if {
    data.plugin == "resource"
    count(input.submods) == 1
    cpu := input.submods.cpu0
    vector := cpu["ear.trustworthiness-vector"]
    vector.executables == 3
    vector.configuration == 2
    vector.hardware == 2
    evidence := cpu["ear.veraison.annotated-evidence"]
    platform := evidence["az-snp-vtpm"]
    disabled(platform.policy_debug_allowed)
    disabled(platform.policy_migrate_ma)
    measurement := platform.tpm.pcr08
    evidence.init_data == measurement
    some binding in approved_bindings
    binding.pcr08 == measurement
    time.now_ns() < time.parse_rfc3339_ns(binding.expiresAt)
    some resource in binding.resources
    data["resource-path"] == ["default", binding.repository, resource]
}

# Installed Trustee versions can encode these verifier fields as booleans or
# canonical strings. Missing, numeric, true, and noncanonical values fail closed.
disabled(value) if { value == false }
disabled(value) if { value == "false" }
'''


def render(approval, now=None):
    """Bind exact Azure SNP PCR08 values to registration-scoped KBS paths."""
    now = now or datetime.now(timezone.utc)
    try:
        if not isinstance(approval, dict) or set(approval) != {"schemaVersion", "bindings"}:
            raise ValueError()
        if type(approval["schemaVersion"]) is not int or approval["schemaVersion"] != 1:
            raise ValueError()
        bindings = approval["bindings"]
        if not isinstance(bindings, list):
            raise ValueError()
        output, seen = [], set()
        fields = {"owner", "registration", "installation", "slot", "role", "pcr08",
                  "initdataSHA256", "referenceSetSHA256", "expiresAt", "resources"}
        for item in bindings:
            if not isinstance(item, dict) or set(item) != fields:
                raise ValueError()
            if not isinstance(item["owner"], str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?", item["owner"]):
                raise ValueError()
            if not isinstance(item["registration"], str) or not re.fullmatch(r"[a-f0-9]{16}", item["registration"]):
                raise ValueError()
            if str(uuid.UUID(item["installation"])) != item["installation"]:
                raise ValueError()
            if not isinstance(item["slot"], str) or not re.fullmatch(r"[a-z0-9-]+/[a-z0-9-]+", item["slot"]):
                raise ValueError()
            if item["role"] not in {"supervisor", "workload"}:
                raise ValueError()
            for key in ["pcr08", "initdataSHA256", "referenceSetSHA256"]:
                if not isinstance(item[key], str) or not re.fullmatch(r"[a-f0-9]{64}", item[key]):
                    raise ValueError()
            if item["pcr08"] in seen:
                raise ValueError()
            seen.add(item["pcr08"])
            expiry = datetime.strptime(item["expiresAt"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if (expiry <= now or expiry.strftime("%Y-%m-%dT%H:%M:%SZ") != item["expiresAt"]):
                raise ValueError()
            resources = item["resources"]
            permitted = {"image-policy", "inference", "web-search"} if item["role"] == "supervisor" else {"image-policy"}
            if (not isinstance(resources, list) or not resources
                    or any(not isinstance(r, str) or r not in permitted for r in resources)
                    or len(set(resources)) != len(resources)):
                raise ValueError()
            result = dict(item)
            result["resources"] = sorted(resources)
            result["repository"] = "saw-" + item["owner"] + "-" + item["registration"]
            output.append(result)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise PolicyError("TrusteeMeasurementApprovalRejected") from None
    return _POLICY.replace("__BINDINGS__", json.dumps(sorted(output, key=lambda x: x["pcr08"]), sort_keys=True, separators=(",", ":")))


def is_policy_denial(status, body):
    """Identify KBS PolicyDeny without confusing authentication failure with denial.

    The KBS protocol serializes Rust error_type as JSON "type" and returns 401
    for PolicyDeny. No response values are returned to the caller or logged.
    """
    if status != 401 or not isinstance(body, bytes) or len(body) > 4096:
        return False
    try:
        value = json.loads(body)
    except (ValueError, TypeError):
        return False
    return (isinstance(value, dict) and value.get("type") ==
            "https://github.com/confidential-containers/kbs/errors/PolicyDeny")
