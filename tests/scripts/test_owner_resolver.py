"""The central resolver accepts one enabled exact Keycloak account."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "charts/openshell-keycloak/files/owner-resolver.py"
SPEC = importlib.util.spec_from_file_location("owner_resolver", SCRIPT)
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)


def test_exact_enabled_account_only():
    cases = [
        ([{"username": "alice", "enabled": True, "id": "subject-a"}], ("subject-a", "resolved")),
        ([], ("", "unknown")),
        ([{"username": "alice", "enabled": False, "id": "subject-a"}], ("", "disabled")),
        ([{"username": "bob", "enabled": True, "id": "subject-b"}], ("", "mismatch")),
        ([{"username": "alice", "enabled": True, "id": "subject-a"},
          {"username": "alice", "enabled": True, "id": "subject-b"}], ("", "ambiguous")),
    ]
    for users, expected in cases:
        assert resolver.subject_for(lambda _: users, "alice") == expected


class FakeKube:
    def __init__(self, subject=""):
        self.subject = subject
        self.patches = []

    def call(self, path, method="GET", body=None):
        if path.startswith("/api/v1/namespaces?"):
            return {"items": [{"metadata": {"name": "saw-alice", "labels": {
                "openshell.pattern/owner": "alice"}}},
                              {"metadata": {"name": "saw-other", "labels": {
                                  "openshell.pattern/owner": "alice"}}}]}
        if method == "PATCH":
            self.patches.append((path, body))
            if "data" in body:
                self.subject = body["data"]["subject"]
            return {}
        return {"data": {"subject": self.subject}, "metadata": {"annotations": {}}}


def test_reconcile_updates_only_the_matching_namespace():
    kube = FakeKube()
    resolver.reconcile(kube, lambda _: [{"username": "alice", "enabled": True, "id": "subject-a"}])
    assert len(kube.patches) == 1
    path, body = kube.patches[0]
    assert path == "/api/v1/namespaces/saw-alice/configmaps/saw-owner-subject"
    assert body["data"] == {"subject": "subject-a"}


def test_disabled_account_clears_a_prior_subject():
    kube = FakeKube("subject-old")
    resolver.reconcile(kube, lambda _: [{"username": "alice", "enabled": False, "id": "subject-old"}])
    assert kube.subject == ""


def test_lookup_outage_grants_no_new_subject():
    kube = FakeKube()
    def unavailable(_):
        raise resolver.ApiError(503, "/users")
    resolver.reconcile(kube, unavailable)
    assert len(kube.patches) == 1
    assert "data" not in kube.patches[0][1]
    assert kube.patches[0][1]["metadata"]["annotations"]["saw.redhat.com/owner-resolution"] == "lookup-error"
