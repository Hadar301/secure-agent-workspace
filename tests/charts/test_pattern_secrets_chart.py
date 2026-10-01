"""Render charts/pattern-secrets: which Secrets a user's namespace syncs from Vault."""
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "pattern-secrets"
HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")


def keys(*args):
    result = subprocess.run([HELM, "template", "x", str(CHART), *args], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    out = {}
    for d in yaml.safe_load_all(result.stdout):
        if d:
            spec = d["spec"]
            out[d["metadata"]["name"]] = ({e["extract"]["key"] for e in spec.get("dataFrom", [])}
                                          | {e["remoteRef"]["key"] for e in spec.get("data", [])})
    return out


def test_defaults_sync_everything_from_the_hub():
    assert keys() == {"inference": {"secret/data/hub/inference"},
                      "web-search": {"secret/data/hub/web-search"},
                      "openshell-ssh-pubkey": {"secret/data/hub/ssh"},
                      "openshell-aap-ssh": {"secret/data/hub/ssh"}}


def test_a_user_prefix_keeps_the_shared_ssh_key(tmp_path):
    values = tmp_path / "v.yaml"
    values.write_text(yaml.safe_dump({"vaultPrefix": "secret/data/hub/saw-bob",
                                      "sshVaultPrefix": "secret/data/hub", "secrets": ["inference"]}))
    got = keys("-f", str(values))
    assert got == {"inference": {"secret/data/hub/saw-bob/inference"},
                   "openshell-ssh-pubkey": {"secret/data/hub/ssh"},
                   "openshell-aap-ssh": {"secret/data/hub/ssh"}}
