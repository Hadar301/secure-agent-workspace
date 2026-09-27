"""Installing BOM components from pinned images (fake podman, real files)."""

import json
import os
import socket
import threading

import pytest


@pytest.fixture
def installer(ab, tmp_path, fake_env):
    shell = ab.Shell()
    bin_dir = tmp_path / "usr-local-bin"
    return ab.ComponentInstaller(shell, bin_dir, tmp_path / "state" / "installed.json",
                                 podman="podman", opt_dir=tmp_path / "opt")


def pulls(fake_env):
    return [c[-1] for c in fake_env.podman_calls() if c[0] == "pull"]


def run_version(path):
    import subprocess
    return subprocess.run([str(path), "--version"], capture_output=True, text=True).stdout.strip()


def test_fresh_install_places_all_binaries(ab, installer, bom, fake_env):
    fake_env.images_for_bom(bom)
    changed = installer.install(bom)
    assert changed == ["cli", "gateway", "supervisor"]
    for name in ("openshell", "openshell-gateway", "openshell-supervisor"):
        path = installer.bin_dir / name
        assert path.is_file() and os.access(path, os.X_OK)
        assert run_version(path).endswith("0.0.116-rhaiv.0")
    state = json.loads(installer.state_file.read_text())
    assert state["bom"] == bom["metadata"]["name"]
    assert state["components"]["gateway"]["image"] == bom["spec"]["openshell"]["gateway"]["image"]
    assert len(state["components"]["gateway"]["sha256"]) == 64
    # Every container created for extraction is removed again.
    created = [c for c in fake_env.podman_calls() if c[0] == "create"]
    removed = [c for c in fake_env.podman_calls() if c[0] == "rm"]
    assert len(created) == len(removed) == 3
    # No staging leftovers next to the binaries.
    assert not [p for p in installer.bin_dir.iterdir() if p.name.startswith(".saw-")]


def test_second_run_pulls_nothing(installer, bom, fake_env):
    fake_env.images_for_bom(bom)
    installer.install(bom)
    before = len(fake_env.podman_calls())
    assert installer.install(bom) == []
    assert len(fake_env.podman_calls()) == before


def test_changed_digest_reinstalls_only_that_component(installer, bom, fake_env):
    fake_env.images_for_bom(bom)
    installer.install(bom)
    new_image = "quay.io/opendatahub/odh-openshell-gateway@sha256:" + "1" * 64
    bom["spec"]["openshell"]["gateway"]["image"] = new_image
    fake_env.images_for_bom(bom)
    assert installer.install(bom) == ["gateway"]
    assert pulls(fake_env)[-1] == new_image


def test_tampered_binary_is_reinstalled(installer, bom, fake_env):
    fake_env.images_for_bom(bom)
    installer.install(bom)
    (installer.bin_dir / "openshell").write_text("#!/bin/sh\necho tampered\n")
    assert installer.install(bom) == ["cli"]


def test_deleted_binary_is_reinstalled(installer, bom, fake_env):
    fake_env.images_for_bom(bom)
    installer.install(bom)
    (installer.bin_dir / "openshell-supervisor").unlink()
    assert installer.install(bom) == ["supervisor"]


def test_version_mismatch_fails_and_keeps_old_binary(ab, installer, bom, fake_env):
    fake_env.images_for_bom(bom)
    installer.install(bom)
    old = (installer.bin_dir / "openshell-gateway").read_text()
    state_before = installer.state_file.read_text()
    bom["spec"]["openshell"]["gateway"]["image"] = "quay.io/x/gateway@sha256:" + "2" * 64
    bom["spec"]["openshell"]["gateway"]["version"] = "0.0.117-rhaiv.0"
    fake_env.images_for_bom(bom, version=None)
    images = json.loads((fake_env.state / "images.json").read_text())
    images[bom["spec"]["openshell"]["gateway"]["image"]]["/usr/local/bin/openshell-gateway"]["version"] = "0.0.999"
    fake_env.set_images(images)
    with pytest.raises(ab.InstallerError, match="reports version 0.0.999, BOM expects 0.0.117-rhaiv.0"):
        installer.install(bom)
    assert (installer.bin_dir / "openshell-gateway").read_text() == old
    assert installer.state_file.read_text() == state_before


def test_pull_failure_is_reported(ab, installer, bom, fake_env):
    fake_env.set_images({})
    with pytest.raises(ab.InstallerError, match="command failed .* podman pull"):
        installer.install(bom)
    assert not installer.state_file.exists()


def test_image_without_the_binary_is_reported(ab, installer, bom, fake_env):
    images = fake_env.images_for_bom(bom)
    images[bom["spec"]["openshell"]["cli"]["image"]] = {"/somewhere/else": {"type": "binary", "version": "x"}}
    fake_env.set_images(images)
    with pytest.raises(ab.InstallerError, match="podman cp"):
        installer.install(bom)
    # The container is still cleaned up after a failed copy.
    assert [c for c in fake_env.podman_calls() if c[0] == "rm"]


def test_path_override_is_used(installer, bom, fake_env):
    bom["spec"]["openshell"]["supervisor"]["path"] = "/usr/bin/supervisor"
    images = fake_env.images_for_bom(bom)
    image = bom["spec"]["openshell"]["supervisor"]["image"]
    images[image] = {"/usr/bin/supervisor": {"type": "binary", "version": "0.0.116-rhaiv.0"}}
    fake_env.set_images(images)
    installer.install(bom)
    assert (installer.bin_dir / "openshell-supervisor").is_file()


def test_nemoclaw_is_installed_once(installer, bom, fake_env):
    bom["spec"]["nemoclaw"] = {"cliImage": "quay.io/x/nemoclaw-cli@sha256:" + "3" * 64}
    fake_env.images_for_bom(bom)
    assert "nemoclaw" in installer.install(bom)
    wrapper = installer.bin_dir / "nemoclaw"
    assert (installer.opt_dir / "nemoclaw" / "bin" / "nemoclaw.js").is_file()
    assert "nemoclaw.js" in wrapper.read_text() and os.access(wrapper, os.X_OK)
    assert installer.install(bom) == []


def test_nemoclaw_image_without_cli_fails(ab, installer, bom, fake_env):
    bom["spec"]["nemoclaw"] = {"cliImage": "quay.io/x/nemoclaw-cli@sha256:" + "3" * 64}
    images = fake_env.images_for_bom(bom)
    images[bom["spec"]["nemoclaw"]["cliImage"]] = {"/opt/nemoclaw": {"type": "binary", "version": "1"}}
    fake_env.set_images(images)
    with pytest.raises(ab.InstallerError):
        installer.install(bom)


def test_dry_run_changes_nothing(ab, tmp_path, bom, fake_env):
    fake_env.images_for_bom(bom)
    installer = ab.ComponentInstaller(ab.Shell(dry_run=True), tmp_path / "bin",
                                      tmp_path / "state" / "installed.json")
    assert installer.install(bom) == ["cli", "gateway", "supervisor"]
    assert fake_env.podman_calls() == []
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "bin").exists()


# -- gateway service ---------------------------------------------------------

class RecordingShell:
    dry_run = False

    def __init__(self):
        self.commands = []

    def run(self, cmd, **kwargs):
        self.commands.append(cmd)
        from conftest import _load_module
        return _load_module().Result(0)


def test_as_user_uses_a_clean_environment(ab):
    cmd = ab.as_user("cloud-user", {"HOME": "/home/cloud-user", "XDG_RUNTIME_DIR": "/run/user/1000"},
                     ["systemctl", "--user", "start", "x"])
    assert cmd[:6] == ["runuser", "-u", "cloud-user", "--", "env", "-i"]
    assert "XDG_RUNTIME_DIR=/run/user/1000" in cmd
    assert cmd[-4:] == ["systemctl", "--user", "start", "x"]


@pytest.fixture
def listening_port(monkeypatch, ab):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    monkeypatch.setattr(ab, "GATEWAY_PORT", port)
    stop = threading.Event()

    def accept():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                pass
    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield port
    stop.set()
    server.close()


@pytest.mark.parametrize("restart, verb", [(False, "start"), (True, "restart")])
def test_ensure_gateway_starts_or_restarts(ab, listening_port, restart, verb):
    shell = RecordingShell()
    ab.ensure_gateway(shell, "cloud-user", {"HOME": "/h"}, restart=restart, timeout=5)
    tails = [c[c.index("--user") + 1:] for c in shell.commands]
    assert tails == [["daemon-reload"], ["enable", "openshell-gateway.service"],
                     [verb, "openshell-gateway.service"]]


def test_ensure_gateway_fails_when_port_never_opens(ab, monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]
    monkeypatch.setattr(ab, "GATEWAY_PORT", free_port)
    monkeypatch.setattr(ab.time, "sleep", lambda _: None)
    shell = RecordingShell()
    with pytest.raises(ab.InstallerError, match="did not listen"):
        ab.ensure_gateway(shell, "cloud-user", {}, restart=False, timeout=0.5)
    assert any("journalctl" in c for c in shell.commands)


# -- status ------------------------------------------------------------------

def test_ready_only_when_both_steps_done_for_same_bom(ab, tmp_path):
    install = ab.Status(tmp_path, "install")
    apply = ab.Status(tmp_path, "apply")
    ready = tmp_path / "ready"
    install.set("Done", "bom-a")
    assert not ready.exists()
    apply.set("Done", "bom-a")
    assert ready.read_text().strip() == "bom-a"
    install.set("Running")
    assert not ready.exists()
    install.set("Done", "bom-b")
    assert not ready.exists()            # apply still for bom-a
    apply.set("Done", "bom-b")
    assert ready.exists()
    apply.set("Failed", "bom-b", "boom")
    assert not ready.exists()
    data = json.loads((tmp_path / "status.json").read_text())
    assert data["apply"]["phase"] == "Failed" and data["apply"]["message"] == "boom"
    assert data["install"]["phase"] == "Done"


def test_shell_masks_secrets_in_logs(ab, capsys, fake_env):
    shell = ab.Shell()
    shell.add_secret("super-secret-value")
    shell.run(["echo", "token=super-secret-value"])
    out = capsys.readouterr().out
    assert "super-secret-value" not in out and "token=***" in out


def test_shell_check_and_already_exists(ab, fake_env):
    shell = ab.Shell()
    with pytest.raises(ab.InstallerError, match="exit 3"):
        shell.run(["sh", "-c", "exit 3"])
    assert shell.run(["sh", "-c", "exit 3"], check=False).rc == 3
    assert shell.run(["sh", "-c", "echo 'x already exists' >&2; exit 1"], ok_if_exists=True).ok
    assert shell.run(["does-not-exist-xyz"], check=False).rc == 127


def test_shell_timeout(ab):
    assert ab.Shell().run(["sleep", "5"], check=False, timeout=0.2).rc == 124


def test_user_manager_is_started_and_awaited(ab, tmp_path):
    runtime = tmp_path / "run-user" / "1000"
    runtime.mkdir(parents=True)
    (runtime / "bus").touch()
    shell = RecordingShell()
    ab.ensure_user_manager(shell, {"XDG_RUNTIME_DIR": str(runtime)}, timeout=1)
    assert shell.commands == [["systemctl", "start", "user@1000.service"]]


def test_user_manager_timeout_is_an_error(ab, tmp_path, monkeypatch):
    monkeypatch.setattr(ab.time, "sleep", lambda _: None)
    runtime = tmp_path / "run-user" / "1000"
    runtime.mkdir(parents=True)
    with pytest.raises(ab.InstallerError, match="uid 1000 did not start"):
        ab.ensure_user_manager(RecordingShell(), {"XDG_RUNTIME_DIR": str(runtime)}, timeout=0.05)
