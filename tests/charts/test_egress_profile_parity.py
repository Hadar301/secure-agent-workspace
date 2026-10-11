"""Keep the shipped governance profiles and the VM's hostname allowlist aligned."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / "charts/governance-policy/profiles"
SAW_COPIES = ROOT / "charts/openshell-saw/files/provider-profiles"
SAW_VALUES = ROOT / "charts/openshell-saw/values.yaml"
POLICY_CHART = ROOT / "charts/governance-policy"
HELM = shutil.which("helm")

REGISTRY_HOSTS = {
    "quay.io", "cdn.quay.io", "registry.fedoraproject.org",
    *(f"cdn{i:02d}.quay.io" for i in range(1, 7)),
}
# The personal-assistant demo uses Gmail; its profile is not shipped here.
ALLOW_EXCEPTIONS = {"gmail.googleapis.com": "personal-assistant demo; its profile is not shipped here"}
UNEXPRESSIBLE_WILDCARDS = {"*-aiplatform.googleapis.com"}


def profile_endpoints():
    return {path.name: (yaml.safe_load(path.read_text()) or {}).get("endpoints") or []
            for path in sorted(PROFILES.glob("*.yaml"))}


def allowlist():
    return yaml.safe_load(SAW_VALUES.read_text())["egress"]["allow"]


def test_every_exact_profile_host_is_allowed():
    hosts = {endpoint["host"] for endpoints in profile_endpoints().values()
             for endpoint in endpoints if "*" not in endpoint["host"]}
    missing = hosts - set(allowlist())
    assert not missing, "add these profile hosts to charts/openshell-saw/values.yaml egress.allow: " + ", ".join(sorted(missing))


def test_profile_ports_match_firewall_and_network_policy():
    bad = [(name, endpoint["host"], endpoint.get("port"))
           for name, endpoints in profile_endpoints().items() for endpoint in endpoints
           if endpoint.get("port") != 443]
    assert not bad, ("profile endpoints must use TCP 443; update the EgressFirewall and "
                     "NetworkPolicy port rules before adding another port: " + repr(bad))


def test_wildcards_are_reviewed_explicitly():
    wild = {endpoint["host"] for endpoints in profile_endpoints().values()
            for endpoint in endpoints if "*" in endpoint["host"]}
    assert wild == UNEXPRESSIBLE_WILDCARDS, (
        "review wildcard profile hosts in tests/charts/test_egress_profile_parity.py and "
        "list each concrete hostname in charts/openshell-saw/values.yaml egress.extraAllow: "
        + repr(sorted(wild ^ UNEXPRESSIBLE_WILDCARDS)))
    assert not any("*" in host for host in allowlist())


def test_allowlist_has_no_unexplained_reverse_drift():
    hosts = {endpoint["host"] for endpoints in profile_endpoints().values()
             for endpoint in endpoints if "*" not in endpoint["host"]}
    allowed = allowlist()
    assert len(allowed) == len(set(allowed)), "remove duplicate hosts from charts/openshell-saw/values.yaml egress.allow"
    unexplained = set(allowed) - hosts - REGISTRY_HOSTS - ALLOW_EXCEPTIONS.keys()
    assert not unexplained, (
        "remove these hosts from charts/openshell-saw/values.yaml egress.allow or "
        "document why they are needed in ALLOW_EXCEPTIONS: " + ", ".join(sorted(unexplained)))


def test_installer_profile_copies_match_governance_policy():
    copies = sorted(SAW_COPIES.glob("*.yaml"))
    assert [p.name for p in copies] == ["brave.yaml", "nvidia.yaml", "openai.yaml"]
    for path in copies:
        twin = PROFILES / path.name
        assert path.read_text() == twin.read_text(), (
            f"copy charts/governance-policy/profiles/{path.name} to "
            f"charts/openshell-saw/files/provider-profiles/{path.name}")


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_profile_configmap_keys_match_files():
    result = subprocess.run([HELM, "template", "policy-test", str(POLICY_CHART)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    config = next(doc for doc in yaml.safe_load_all(result.stdout)
                  if doc and doc["kind"] == "ConfigMap"
                  and doc["metadata"]["name"] == "governance-interceptor-profiles")
    expected = {path.name for path in PROFILES.glob("*.yaml")}
    assert set(config["data"]) == expected, (
        "charts/governance-policy/templates/configmap.yaml must include exactly "
        f"charts/governance-policy/profiles/*.yaml: expected {sorted(expected)}, "
        f"got {sorted(config['data'])}")
