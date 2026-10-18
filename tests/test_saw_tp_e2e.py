"""Offline checks for the minimal deployment controller."""

import importlib.util
import json
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("saw_tp_e2e", ROOT / "scripts/saw-tp-e2e.py")
e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e2e)


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
