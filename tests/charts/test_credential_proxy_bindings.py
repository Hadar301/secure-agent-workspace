"""The proxy's bindings must follow the shipped profile catalog and metadata split."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SAW = ROOT / "charts/openshell-saw"
PROFILES = ROOT / "charts/governance-policy/profiles"
HELM = shutil.which("helm")


def render(chart, *args):
    result = subprocess.run([HELM, "template", "saw-test", str(chart), "-n", "saw-test", *args],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return [d for d in yaml.safe_load_all(result.stdout) if d]


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_proxy_policy_matches_all_keyed_profile_copies():
    docs = render(SAW, "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                  "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"))
    cm = next(d for d in docs if d["kind"] == "ConfigMap" and
              d["metadata"]["name"] == "saw-test-credential-proxy-config")
    policy = json.loads(cm["data"]["config.json"])
    assert policy["markerPrefix"] == "saw-cred"
    assert {(b["secret"], b["key"]) for b in policy["bindings"]} == {
        ("inference", "api_key"), ("web-search", "api_key")}
    copies = SAW / "files/provider-profiles"
    for path in sorted(PROFILES.glob("*.yaml")):
        profile = yaml.safe_load(path.read_text())
        if not profile.get("credentials"):
            continue
        assert (copies / path.name).read_bytes() == path.read_bytes()
        assert set(policy["profiles"][profile["id"]]) == {e["host"] for e in profile["endpoints"]}
    for binding in policy["bindings"]:
        for typ in binding["providers"]:
            for host in policy["profiles"].get(typ, []):
                if "*" not in host:
                    assert host in policy["allowHosts"], (typ, host)


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_proxy_image_requires_digest():
    for image in ("", "quay.io/example/proxy:latest"):
        result = subprocess.run([HELM, "template", "saw-test", str(SAW), "-n", "saw-test",
                                 "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                                 "--set-string", "credentialProxy.image=" + image],
                                capture_output=True, text=True)
        assert result.returncode != 0
        assert "credentialProxy.image must be a published repo@sha256" in result.stderr


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_provider_metadata_external_secrets_contain_no_key():
    docs = render(ROOT / "charts/pattern-secrets", "--set",
                  "secrets={inference,web-search,inference-openai,inference-anthropic}")
    names = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ExternalSecret"}
    for name, keys in (("inference-meta", {"provider", "model", "url"}),
                       ("web-search-meta", {"provider", "model", "url"}),
                       ("inference-openai-meta", {"provider", "model", "url"}),
                       ("inference-anthropic-meta", {"provider", "model", "url"})):
        assert name in names
        assert set(names[name]["spec"]["target"]["template"]["data"]) == keys
        assert "api_key" not in names[name]["spec"]["target"]["template"]["data"]


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_unattached_search_secret_has_no_proxy_binding_or_mount():
    docs = render(SAW, "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                  "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"),
                  "--set-json", "additionalProviderSecrets=[]")
    configmaps = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ConfigMap"}
    policy = json.loads(configmaps["saw-test-credential-proxy-config"]["data"]["config.json"])
    assert [b["secret"] for b in policy["bindings"]] == ["inference"]
    installer = json.loads(configmaps["saw-test-installer"]["data"]["config.json"])
    assert [b["name"] for b in installer["credentialProxy"]["secrets"]] == ["inference"]
    deployment = next(d for d in docs if d["kind"] == "Deployment")
    volumes = deployment["spec"]["template"]["spec"]["volumes"]
    assert not any(v.get("secret", {}).get("secretName") == "web-search" for v in volumes)


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_gitops_ca_hook_has_a_bounded_failure():
    docs = render(SAW, "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                  "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"),
                  "--set", "cleanupOnDelete=false")
    hook = next(d for d in docs if d["kind"] == "Pod"
                and d["metadata"]["name"] == "saw-credential-proxy-ca-hook")
    assert hook["spec"]["restartPolicy"] == "Never"
    assert hook["spec"]["activeDeadlineSeconds"] == 120


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_public_issuer_ca_stays_in_the_guest_mount_list():
    docs = render(SAW, "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
                  "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"),
                  "--set", "oidc.clusterCaSecret=saw-ingress-ca",
                  "--set-json", 'credentialProxy.secrets=[{"name":"inference","key":"api_key","providers":["build"]},{"name":"saw-ingress-ca","key":"api_key","providers":["openai"]}]')
    installer = next(d for d in docs if d["kind"] == "ConfigMap"
                     and d["metadata"]["name"] == "saw-test-installer")
    config = json.loads(installer["data"]["config.json"])
    assert config["secrets"] == ["inference", "web-search", "saw-ingress-ca"]
    assert config["caBundleSecret"] == "saw-ingress-ca"
    assert [b["name"] for b in config["credentialProxy"]["secrets"]] == ["inference"]
    proxy = next(d for d in docs if d["kind"] == "ConfigMap"
                 and d["metadata"]["name"] == "saw-test-credential-proxy-config")
    assert [b["secret"] for b in json.loads(proxy["data"]["config.json"])["bindings"]] == ["inference"]
