"""Verify temporary-object cleanup when real identity validation fails."""
import copy
import importlib.util
from pathlib import Path
import pytest

PATH = Path(__file__).resolve().parents[1] / "scripts/check-peerpod-storage-identity.py"
SPEC = importlib.util.spec_from_file_location("lab_identity", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FailedIdentityApi:
    def __init__(self, token_error=False):
        self.token_error = token_error
        self.deleted = []
    def get(self, path):
        return {"metadata": {"labels": {"saw.redhat.com/peerpod-storage-lab": "0123456789abcdef"}}}
    def request(self, method, path, body=None, **kwargs):
        if method == "DELETE":
            self.deleted.append((path, body))
            return 200, {}
        if path.endswith("/pods"):
            pod = copy.deepcopy(body)
            pod["metadata"]["uid"] = "test-pod-uid"
            return 201, pod
        if path.endswith("/token"):
            assert body["spec"]["boundObjectRef"]["uid"] == "test-pod-uid"
            return (403, {}) if self.token_error else (201, {"status": {"token": "not-a-real-token"}})
        if path.endswith("/selfsubjectreviews"):
            assert kwargs["bearer"] == "not-a-real-token"
            return 201, {"status": {"userInfo": {"username": "unexpected-admin"}}}
        pytest.fail("Unexpected API operation")


@pytest.mark.parametrize("token_error,reason", [(True, "LabBoundTokenUnavailable"), (False, "LabActualBoundIdentityRejected")])
def test_failed_identity_removes_only_owned_unscheduled_pod(token_error, reason):
    api = FailedIdentityApi(token_error)
    with pytest.raises(MODULE.Error, match="^" + reason + "$") as error:
        MODULE.check(api, "0123456789abcdef")
    assert "not-a-real-token" not in str(error.value)
    assert len(api.deleted) == 1
    path, options = api.deleted[0]
    assert "/namespaces/saw-ppvc-probe-0123456789abcdef/pods/bound-identity-" in path
    assert options["preconditions"] == {"uid": "test-pod-uid"}
