"""Check API dry-run and identity handling without a cluster or credentials."""
import importlib.util
import io
import json
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

PATH = Path(__file__).resolve().parents[1] / "scripts/check-peerpod-storage-admission.py"
SPEC = importlib.util.spec_from_file_location("peerpod_storage_admission", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Response(io.BytesIO):
    status = 201


@pytest.mark.parametrize("path", [
    "/api/v1/namespaces/lab/secrets", "/api/v1/namespaces/lab/%73ecrets",
    "/apis/../secrets", "https://foreign.example.test/apis/v1/x",
    "/apis/v1/x#fragment", "/healthz",
])
def test_never_sends_secret_or_untrusted_paths(monkeypatch, path):
    def unexpected(*args, **kwargs):
        pytest.fail("An unsafe API request was sent")
    monkeypatch.setattr(MODULE, "urlopen", unexpected)
    with pytest.raises(MODULE.CheckError, match="^LabApiPathRejected$"):
        MODULE.Api("test-context").request("GET", path)


def test_dry_run_and_bound_identity_are_explicit(monkeypatch):
    calls = []
    def send(request, timeout):
        calls.append(request)
        assert timeout == 20
        return Response(b'{"kind":"PersistentVolume"}')
    monkeypatch.setattr(MODULE, "urlopen", send)
    api = MODULE.Api("test-context")
    api.base = "http://127.0.0.1:12345"
    assert api.request("POST", "/api/v1/persistentvolumes", {"kind": "PersistentVolume"}, dry_run=True, actor="test-user", pod_uid="test-uid")[0] == 201
    request = calls[0]
    assert request.full_url == "http://127.0.0.1:12345/api/v1/persistentvolumes?dryRun=All"
    headers = {k.lower(): v for k, v in request.header_items()}
    assert headers["impersonate-user"] == "test-user"
    assert headers["impersonate-extra-authentication.kubernetes.io%2fpod-uid"] == "test-uid"
    assert "authorization" not in headers
    assert json.loads(request.data) == {"kind": "PersistentVolume"}


def test_network_error_does_not_expose_response(monkeypatch):
    def unavailable(*args, **kwargs):
        raise URLError("private-value-not-for-output")
    monkeypatch.setattr(MODULE, "urlopen", unavailable)
    api = MODULE.Api("test-context")
    api.base = "http://127.0.0.1:12345"
    with pytest.raises(MODULE.CheckError, match="^LabApiUnavailable$") as error:
        api.get("/api/v1/namespaces/lab")
    assert "private-value" not in str(error.value)


def test_api_status_message_is_not_used_in_safe_error(monkeypatch):
    def denied(*args, **kwargs):
        raise HTTPError("http://127.0.0.1/x", 403, "denied", {}, io.BytesIO(b'{"message":"private-value-not-for-output"}'))
    monkeypatch.setattr(MODULE, "urlopen", denied)
    api = MODULE.Api("test-context")
    api.base = "http://127.0.0.1:12345"
    with pytest.raises(MODULE.CheckError, match="^LabRequiredResourceUnavailable$"):
        api.get("/api/v1/namespaces/lab")


class InactiveApi:
    def __init__(self, scheduled=0, warnings=None):
        self.scheduled = scheduled
        self.warnings = warnings or []
    def get(self, path):
        if "/namespaces/" in path and "/deployments/" not in path and "/daemonsets/" not in path:
            return {"metadata": {"labels": {"saw.redhat.com/peerpod-storage-lab": "0123456789abcdef"}}}
        if "/deployments/" in path:
            return {"spec": {"replicas": 0}}
        if "/daemonsets/" in path:
            return {"status": {"currentNumberScheduled": self.scheduled}}
        return {"metadata": {"generation": 1}, "status": {"observedGeneration": 1, "typeChecking": {"expressionWarnings": self.warnings}}}


def test_refuses_to_exercise_a_running_plugin():
    with pytest.raises(MODULE.CheckError, match="^LabMustBeInactive$"):
        MODULE.verify_inactive(InactiveApi(scheduled=1), "saw-ppvc-0123456789abcdef")


def test_refuses_unverified_admission_expressions():
    with pytest.raises(MODULE.CheckError, match="^LabAdmissionPolicyNotVerified$"):
        MODULE.verify_inactive(InactiveApi(warnings=[{"warning": "type error"}]), "saw-ppvc-0123456789abcdef")


def test_accepts_only_the_checked_inactive_stage():
    MODULE.verify_inactive(InactiveApi(), "saw-ppvc-0123456789abcdef")
