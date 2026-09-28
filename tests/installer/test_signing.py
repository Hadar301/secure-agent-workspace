"""Signature checks: enforce stops before install, warn records unsigned."""

import json
import os
import stat
import subprocess

import pytest


def _installer(ab, tmp_path, mode):
    shell = ab.Shell()
    return ab.ComponentInstaller(shell, tmp_path / "bin", tmp_path / "state" / "installed.json",
                                 signing_mode=mode)


def test_warn_unsigned_image_installs_and_records_unsigned(ab, bom, fake_env, tmp_path):
    fake_env.images_for_bom(bom)
    image = bom["spec"]["openshell"]["gateway"]["image"]
    (fake_env.state / "unsigned.json").write_text(json.dumps([image]))
    bom["spec"]["openshell"]["gateway"]["signature"] = {"keyRef": "openshell"}
    installer = _installer(ab, tmp_path, "warn")
    assert "gateway" in installer.install(bom)
    assert installer.signatures["gateway"] == "unsigned"
    assert (installer.bin_dir / "openshell-gateway").is_file()


def test_enforce_unsigned_image_installs_nothing(ab, bom, fake_env, tmp_path):
    fake_env.images_for_bom(bom)
    image = bom["spec"]["openshell"]["gateway"]["image"]
    (fake_env.state / "unsigned.json").write_text(json.dumps([image]))
    for entry in bom["spec"]["openshell"].values():
        entry["signature"] = {"keyRef": "openshell"}
    installer = _installer(ab, tmp_path, "enforce")
    with pytest.raises(ab.InstallerError, match=f"image {image} is not signed by openshell"):
        installer.install(bom)
    assert not installer.bin_dir.exists() or not any(installer.bin_dir.iterdir())
    assert [c for c in fake_env.podman_calls() if c[0] == "create"] == []


def test_enforce_without_a_signer_fails_before_pull(ab, bom, fake_env, tmp_path):
    fake_env.images_for_bom(bom)
    installer = _installer(ab, tmp_path, "enforce")
    with pytest.raises(ab.InstallerError, match="is not signed by a configured signer"):
        installer.install(bom)
    assert fake_env.podman_calls() == []


def test_verified_signature_is_recorded(ab, bom, fake_env, tmp_path):
    fake_env.images_for_bom(bom)
    bom["spec"]["openshell"]["cli"]["signature"] = {"keyRef": "openshell"}
    installer = _installer(ab, tmp_path, "warn")
    installer.install(bom)
    assert installer.signatures["cli"] == "verified"
    assert installer.signatures["gateway"] == "unsigned"


def test_off_does_not_record_signatures(ab, bom, fake_env, tmp_path):
    fake_env.images_for_bom(bom)
    installer = _installer(ab, tmp_path, "off")
    installer.install(bom)
    assert installer.signatures == {}
    assert all("SAW_SIGNING_CHECK" not in json.dumps(c) for c in fake_env.podman_calls())


@pytest.mark.parametrize("signature, message", [
    ({"keyRef": "openshell", "identity": "https://example.com/id", "issuer": "https://example.com"},
     "not both"),
    ({}, "keyRef or both"),
    ({"keyRef": "../keys"}, "keyRef"),
    ({"identity": "https://example.com/id"}, "https URLs"),
    ({"issuer": "not-a-url", "identity": "also-not"}, "https URLs"),
])
def test_signature_shape_is_rejected(ab, bom, signature, message):
    bom["spec"]["openshell"]["cli"]["signature"] = signature
    with pytest.raises(ab.InstallerError, match=message):
        ab.validate_bom(bom)


def test_keyless_signature_is_accepted(ab, bom):
    bom["spec"]["openshell"]["cli"]["signature"] = {
        "identity": "https://github.com/example/openshell/.github/workflows/release.yml@refs/tags/v1",
        "issuer": "https://token.actions.githubusercontent.com",
    }
    ab.validate_bom(bom)


def test_verify_bundle_warn_allows_unsigned_and_enforce_stops(tmp_path):
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    script = root / "charts" / "openshell-saw" / "files" / "guest" / "verify-bundle"
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    installer = tmp_path / "installer"
    installer.mkdir()
    for name in ("installer-bom.yaml", "apply_bom.py", "setup-dashboard.sh"):
        (installer / name).write_text(name + "\n")
    status = tmp_path / "status.json"
    env = {**os.environ, "SAW_INSTALLER_DIR": str(installer), "SAW_TRUST_DIR": str(tmp_path / "trust"),
           "SAW_STATUS_FILE": str(status)}

    def run(mode):
        (installer / "config.json").write_text(json.dumps({"signing": {"mode": mode}}))
        return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)

    warned = run("warn")
    assert warned.returncode == 0
    assert "unsigned" in warned.stderr
    assert json.loads(status.read_text())["bundle"]["signature"] == "unsigned"
    enforced = run("enforce")
    assert enforced.returncode == 1
    assert json.loads(status.read_text())["bundle"]["signature"] == "unsigned"


def test_unit_runs_verifier_before_apply_bom():
    from pathlib import Path
    unit = (Path(__file__).resolve().parents[2] / "charts" / "openshell-saw" / "files" /
            "guest" / "saw-install.service").read_text()
    pre = [line for line in unit.splitlines() if line.startswith("ExecStartPre=")]
    start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
    assert any("verify-bundle" in line for line in pre)
    assert pre.index(next(line for line in pre if "verify-bundle" in line)) < len(pre)
    assert unit.index("verify-bundle") < unit.index(start)
    assert "apply_bom.py install" in start
