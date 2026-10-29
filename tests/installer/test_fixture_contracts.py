"""Guard the isolation and strict command contracts used by installer tests."""
import subprocess

from conftest import copy_pki


def test_pki_copies_do_not_share_mutable_files(gateway_pki, tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    copy_pki(gateway_pki, first)
    (first / "client-ca.pem").write_text("changed trust")
    (first / "client/tls.key").unlink()
    copy_pki(gateway_pki, second)
    assert (second / "client-ca.pem").read_bytes() == dict(gateway_pki)["client-ca.pem"]
    assert (second / "client/tls.key").read_bytes() == dict(gateway_pki)["client/tls.key"]
    assert (second / "client/tls.key").stat().st_mode & 0o777 == 0o600
    assert not (second / "ca.key").exists()


def test_command_fixture_has_no_pki_and_rejects_retired_routes(fake_commands):
    assert not (fake_commands.home / ".local/state/openshell/tls").exists()
    for operation in ("set", "delete"):
        result = subprocess.run(["openshell", "inference", operation], capture_output=True, text=True)
        assert result.returncode == 2, operation
        assert "unsupported" in result.stderr, operation
    assert "inference" not in fake_commands.openshell_state()
    assert "system_inference" not in fake_commands.openshell_state()
