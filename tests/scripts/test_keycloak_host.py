"""scripts/keycloak-host.sh: find Keycloak's host for the OIDC issuer."""
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).parent


def host(tmp_path, kc, ns="keycloak"):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    if not (bin_dir / "oc").exists():
        (bin_dir / "oc").symlink_to(HERE / "fake_oc_keycloak")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_KC": json.dumps(kc)}
    return subprocess.run(["bash", str(ROOT / "scripts" / "keycloak-host.sh"), ns],
                          env=env, capture_output=True, text=True)


@pytest.mark.parametrize("kc", [
    {"externalURL": "https://kc.apps.example.com"},             # make keycloak (status set)
    {"externalURL": "https://kc.apps.example.com/"},
    {"hostname": "kc.apps.example.com"},                          # RHBK: spec.hostname only
    {"hostname": "https://kc.apps.example.com"},
    {"labelledRoute": "kc.apps.example.com"},
    {"route": "kc.apps.example.com"},                             # route without app=keycloak
])
def test_finds_the_host(tmp_path, kc):
    result = host(tmp_path, kc)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "kc.apps.example.com"


def test_live_cluster_shape(tmp_path):
    """Found live: RHBK CR without status.externalURL, hostname in
    spec.hostname.hostname, route named keycloak without the app label."""
    result = host(tmp_path, {"hostname": "sso.apps.cluster.example.com", "route": "sso.apps.cluster.example.com"})
    assert result.stdout.strip() == "sso.apps.cluster.example.com"


def test_the_repos_keycloak_wins_when_a_namespace_has_several(tmp_path):
    result = host(tmp_path, {"ownURL": "https://openshell-kc.example.com", "externalURL": "https://other.example.com"})
    assert result.stdout.strip() == "openshell-kc.example.com"


def test_status_url_wins(tmp_path):
    result = host(tmp_path, {"externalURL": "https://a.example.com", "hostname": "b.example.com"})
    assert result.stdout.strip() == "a.example.com"


def test_nothing_found(tmp_path):
    result = host(tmp_path, {}, ns="kc-missing")
    assert result.returncode == 1 and "no Keycloak found in namespace kc-missing" in result.stderr


def test_every_caller_uses_the_helper():
    for path in ("Makefile-quickstart", "scripts/oidc-login.sh", "scripts/openshell-saw-create.sh"):
        text = (ROOT / path).read_text()
        assert "keycloak-host.sh" in text, path
        assert "status.externalURL" not in text, path
