"""Offline checks for the minimal deployment controller."""

import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("saw_tp_e2e", ROOT / "scripts/saw-tp-e2e.py")
e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e2e)
config_spec = importlib.util.spec_from_file_location(
    "saw_tp_e2e_ci_config", ROOT / "scripts/saw-tp-e2e-ci-config.py"
)
ci_config = importlib.util.module_from_spec(config_spec)
config_spec.loader.exec_module(ci_config)


def test_minimal_render(tmp_path):
    e2e.checked_in_selection()
    assert "openclaw" in e2e.pinned_image_digests()
    runner = e2e.CommandRunner(dict(os.environ))
    values = e2e.render_children(
        runner, ROOT / "tests/fixtures/saw-e2e-runtime.json", "a" * 40
    )
    e2e.render_charts(runner, values, tmp_path)
    assert set(values) == e2e.EXPECTED_CHILD_APPS


def test_invalid_private_config(tmp_path):
    config = tmp_path / "test.yaml"
    config.write_text("cluster: {}\ninference: {}\n")
    config.chmod(0o600)
    with pytest.raises(e2e.E2EError, match="kubeconfig"):
        e2e.load_config(config, require_key=True)
    config.chmod(0o644)
    with pytest.raises(e2e.E2EError, match="readable only"):
        e2e.load_config(config, require_key=True)


def test_single_private_config_and_temporary_login(tmp_path):
    config_file = tmp_path / "test.yaml"
    config_file.write_text(
        "cluster:\n  apiURL: https://api.example.test:6443\n"
        "  username: test-admin\n  password: private-password\n"
        "inference:\n  provider: nvidia\n"
        "  model: nvidia/nemotron-3-super-120b-a12b\n"
        "  apiKey: private-nvidia-key\n"
    )
    config_file.chmod(0o600)
    config = e2e.load_config(config_file, require_key=True)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_oc = fake_bin / "oc"
    fake_oc.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = login ]; then\n"
        "  printf 'Password: '\n"
        "  IFS= read -r supplied\n"
        "  [ \"$supplied\" = private-password ]\n"
        "elif [ \"$1\" = config ] && [ \"$2\" = current-context ]; then\n"
        "  printf 'test-context\\n'\n"
        "elif [ \"$1\" = config ] && [ \"$2\" = view ]; then\n"
        "  printf 'apiVersion: v1\\nkind: Config\\n'\n"
        "else exit 1; fi\n"
    )
    fake_oc.chmod(0o700)
    kubeconfig = tmp_path / "kubeconfig"
    e2e.private_write(kubeconfig, b"")
    runner = e2e.CommandRunner({**os.environ, "PATH": str(fake_bin) + ":" + os.environ["PATH"],
                                "KUBECONFIG": str(kubeconfig), "SAW_E2E_CONTEXT": ""},
                               ["private-password", "private-nvidia-key"])
    assert e2e.login_cluster(runner, config) == "test-context"
    assert runner.env["SAW_E2E_CONTEXT"] == "test-context"
    assert "private-password" not in kubeconfig.read_text()


def test_ci_config_requires_inputs_and_writes_private_file(tmp_path):
    path = tmp_path / "private" / "config.yaml"
    with pytest.raises(ValueError, match="cluster_password"):
        ci_config.write_config(path, {"cluster_api_url": "https://api.example.test:6443"})
    inputs = {
        "cluster_api_url": "https://api.example.test:6443",
        "cluster_username": "test-admin",
        "cluster_password": "private-password",
        "nvidia_api_key": "private-nvidia-key",
    }
    ci_config.write_config(path, inputs)
    assert path.stat().st_mode & 0o077 == 0
    assert path.parent.stat().st_mode & 0o077 == 0
    assert e2e.load_config(path, require_key=True)["cluster"]["username"] == "test-admin"


def test_virtctl_download_uses_cluster_link(tmp_path, monkeypatch):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as bundle:
        payload = b"#!/bin/sh\nexit 0\n"
        info = tarfile.TarInfo("virtctl")
        info.size = len(payload)
        bundle.addfile(info, io.BytesIO(payload))
    archive.seek(0)

    class Runner:
        def __init__(self):
            self.env = {"PATH": "/usr/bin"}

        def oc_json(self, *args):
            return {"spec": {"links": [{"text": "Linux x86_64",
                                         "href": "https://example.test/virtctl.tar.gz"}]}}

    monkeypatch.setattr(e2e.shutil, "which", lambda *args, **kwargs: None)
    monkeypatch.setattr(e2e, "ingress_context", lambda *args: None)
    monkeypatch.setattr(e2e.urllib.request, "urlopen",
                        lambda *args, **kwargs: io.BytesIO(archive.getvalue()))
    runner = Runner()
    e2e.ensure_virtctl(runner, {}, tmp_path)
    assert (tmp_path / "bin/virtctl").read_bytes() == payload
    assert runner.env["PATH"].startswith(str(tmp_path / "bin"))


def test_atomic_lock_refuses_concurrent_run():
    class Runner:
        def run(self, label, args, **kwargs):
            assert args == ["oc", "create", "-f", "-"]
            raise e2e.E2EError("already exists")

    with pytest.raises(e2e.E2EError, match="already exists"):
        e2e.create_lock(Runner(), {"run_id": "second"})


def test_failed_secret_sync_cannot_pass(monkeypatch):
    class Runner:
        def oc_json(self, *args, **kwargs):
            return {"status": {"conditions": [{"type": "Ready", "status": "False"}]}}

    clock = iter((0, 1, 2))
    monkeypatch.setattr(e2e.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(e2e.time, "sleep", lambda seconds: None)
    with pytest.raises(e2e.E2EError, match="timed out"):
        e2e.secret_ready(Runner(), "saw-e2e-owner", "inference", 2)


def test_inference_failure_cannot_pass():
    class Runner:
        def run(self, *args, **kwargs):
            return json.dumps({"status": "failed", "payloads": []})

    with pytest.raises(e2e.E2EError, match="incomplete"):
        e2e.openclaw_request(Runner(), Path("/tmp"), 999999999)


def test_identity_failure_cannot_pass(monkeypatch):
    class Runner:
        def __init__(self):
            self.sensitive = []

    monkeypatch.setattr(e2e, "oidc_host", lambda runner: "keycloak.example.test")
    monkeypatch.setattr(e2e, "ingress_context", lambda runner, config: None)

    def reject(request, **kwargs):
        raise e2e.urllib.error.URLError("connection refused")

    monkeypatch.setattr(e2e.urllib.request, "urlopen", reject)
    with pytest.raises(e2e.E2EError, match="Keycloak token request failed"):
        e2e.obtain_token(Runner(), {}, "test-password")


def test_reports_redact_stage_error(tmp_path):
    secret = "private-sentinel-value"
    inventory = {"run_id": "test", "started_at": e2e.now(), "stages": []}

    def fail():
        raise e2e.E2EError("request failed: " + secret)

    with pytest.raises(e2e.E2EError):
        e2e.stage(inventory, tmp_path, "failure", fail, [secret])
    for path in tmp_path.iterdir():
        assert secret not in path.read_text()
