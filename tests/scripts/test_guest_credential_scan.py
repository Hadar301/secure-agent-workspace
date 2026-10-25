"""The live root scan must find credentials without reading special files."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "scripts/scan-guest-credentials.py"
spec = importlib.util.spec_from_file_location("guest_scan", SOURCE)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


def test_finds_credentials_across_read_boundaries_and_ca_keys(tmp_path):
    (tmp_path / "ordinary").write_bytes(b"safe")
    target = tmp_path / "credential"
    target.write_bytes(b"x" * (1024 * 1024 - 3) + b"test-key-123" + b"tail")
    ca_key = tmp_path / "ca.key"
    ca_key.write_bytes(b"private signing material")
    assert scan.credential_hits(b"test-key-123", str(tmp_path)) == sorted([str(target), str(ca_key)])


def test_skips_live_control_fifos_and_symlinks(tmp_path):
    os.mkfifo(tmp_path / "podman-ctl")
    (tmp_path / "fifo-link").symlink_to(tmp_path / "podman-ctl")
    result = subprocess.run(
        [sys.executable, "-c", SOURCE.read_text() +
         "\nimport sys; assert credential_hits(b'absent-key', sys.argv[1]) == []", str(tmp_path)],
        capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
