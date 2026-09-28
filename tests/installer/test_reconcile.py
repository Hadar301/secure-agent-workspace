"""Reconcile decides install vs apply from input hashes."""

import json
import os
import shutil
import sys

import yaml


def test_reconcile_actions(ab):
    current = {"installer": "a", "profiles": "b", "secrets": "c"}
    assert ab.reconcile_actions(current, {}, True, True) == []
    assert ab.reconcile_actions(current, {}, False, False) == ["install", "apply"]
    assert ab.reconcile_actions(current, current, True, True) == []
    changed_bom = {**current, "installer": "a2"}
    assert ab.reconcile_actions(changed_bom, current, True, True) == ["install"]
    changed_secret = {**current, "secrets": "c2"}
    assert ab.reconcile_actions(changed_secret, current, True, True) == ["apply"]
    changed_both = {**current, "installer": "a2", "profiles": "b2"}
    assert ab.reconcile_actions(changed_both, current, True, True) == ["install", "apply"]


def test_tree_hash_ignores_configmap_dot_dirs(ab, tmp_path):
    root = tmp_path / "secrets" / "inference"
    data = root / "..2026"
    data.mkdir(parents=True)
    (data / "api_key").write_text("new\n")
    link_data = root / "..data"
    link_data.symlink_to("..2026")
    (root / "api_key").symlink_to("..data/api_key")
    first = ab.tree_hash(root)
    (data / "api_key").write_text("rotated\n")
    assert ab.tree_hash(root) != first


def test_reconcile_after_boot_is_a_noop_until_a_secret_changes(tmp_path, inputs_dir, fake_env):
    bom = yaml.safe_load((inputs_dir / "installer" / "installer-bom.yaml").read_text())
    fake_env.images_for_bom(bom)
    state = tmp_path / "var-lib-saw"
    home = tmp_path / "home-cloud-user"
    (home / ".local" / "state").mkdir(parents=True)
    shutil.copytree(fake_env.home / ".local" / "state" / "openshell",
                    home / ".local" / "state" / "openshell")
    script = inputs_dir / "installer" / "apply_bom.py"
    base = ["--inputs", str(inputs_dir), "--state-dir", str(state), "--as-current-user"]
    install_flags = ["--bin-dir", str(tmp_path / "bin"), "--opt-dir", str(tmp_path / "opt"),
                     "--skip-gateway", "--etc-dir", str(tmp_path / "etc")]
    env = {**os.environ, "HOME": str(home)}

    def run(cmd):
        extra = install_flags if cmd in ("install", "reconcile") else []
        return __import__("subprocess").run(
            [sys.executable, str(script), cmd, *base, *extra],
            capture_output=True, text=True, env=env)

    assert run("install").returncode == 0
    assert run("apply").returncode == 0
    pulls = len(fake_env.podman_calls())
    assert run("reconcile").returncode == 0
    status = json.loads((state / "status.json").read_text())
    assert status["inputs"]["upToDate"] is True
    assert len(fake_env.podman_calls()) == pulls
    secret = inputs_dir / "secrets" / "inference" / "api_key"
    secret.write_text("rotated-key\n")
    changed = run("reconcile")
    assert changed.returncode == 0, changed.stdout + changed.stderr
    assert "running apply" in changed.stdout
    assert "running install" not in changed.stdout
    status = json.loads((state / "status.json").read_text())
    assert status["inputs"]["upToDate"] is True
    assert status["inputs"]["message"] == "applied changed inputs"
    updates = [c for c in fake_env.openshell_calls() if "update" in c and "provider" in c]
    assert updates
