"""No cluster names, credentials, or permissive qualification fixtures."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

from saw_kubernetes import attestation, rotation

REG = "a" * 16
INSTALLATION = "11111111-1111-4111-8111-111111111111"
NS = "trustee"
BASE = f"/api/v1/namespaces/{NS}"
ES = f"/apis/external-secrets.io/v1/namespaces/{NS}/externalsecrets/saw-alice-{REG}"
DEP = f"/apis/apps/v1/namespaces/{NS}/deployments/kbs"
RS = f"/apis/apps/v1/namespaces/{NS}/replicasets/kbs-rs"
READY = {"conditions": [{"type": "Ready", "status": "True"}]}


def meta(name, uid=None, **kwargs):
    return dict(name=name, uid=uid or name + "-uid", resourceVersion="opaque-v1", **kwargs)


def external():
    obj = {"metadata": meta("saw-alice-" + REG, generation=1, labels={
        "saw.redhat.com/portal-owner": "alice", "saw.redhat.com/registration": REG}),
        "spec": {"secretStoreRef": {"kind": "ClusterSecretStore", "name": "owner-store"},
                 "target": {"name": "saw-alice-" + REG, "creationPolicy": "Owner"},
                 "data": [{"secretKey": "field0", "remoteRef": {
                     "key": f"secret/data/hub/saw-alice/{REG}/inference", "property": "api_key"}}]},
        "status": dict(READY, refreshTime="2026-01-01T00:00:00Z")}
    obj["status"]["syncedResourceVersion"] = rotation.eso_version(obj["metadata"])
    return obj


class Api:
    def __init__(self):
        self.events = []
        self.objects = {ES: external()}
        spec = {"replicas": 1, "selector": {"matchLabels": {"app": "kbs"}},
                "template": {"spec": {"containers": [{"name": "kbs", "image": "example.test/kbs@sha256:" + "b" * 64}]}}}
        self.objects[DEP] = {"metadata": meta("kbs", generation=1), "spec": spec,
                             "status": {"observedGeneration": 1, "readyReplicas": 1, "updatedReplicas": 1}}
        self.objects[RS] = {"metadata": meta("kbs-rs", ownerReferences=[{
            "kind": "Deployment", "uid": "kbs-uid", "controller": True}])}
        self.pod = {"metadata": meta("kbs-old", labels={"app": "kbs"}, ownerReferences=[{
            "kind": "ReplicaSet", "name": "kbs-rs", "uid": "kbs-rs-uid", "controller": True}]),
                    "status": READY}
        self.objects[BASE + "/pods"] = {"items": [self.pod]}
        self.ref = {"path": DEP, "uid": "kbs-uid", "sha256": attestation.trustee_deployment_digest(spec)}
        self.refresh = True
        self.evict = True
        self.patch_hook = lambda: None

    def __call__(self, method, path, body=None):
        assert "/secrets/" not in path
        self.events.append((method, path, copy.deepcopy(body)))
        if method == "GET":
            if path not in self.objects:
                raise rotation.RotationError("RotationObjectUnavailable")
            return copy.deepcopy(self.objects[path])
        if method == "PATCH":
            obj = self.objects[path]
            for op in body:
                key = op["path"].split("/")[-1]
                area = obj[op["path"].split("/")[1]]
                if op["op"] == "test":
                    assert area[key] == op["value"]
                else:
                    area[key] = op["value"]
            if path == ES and self.refresh:
                obj["status"].update(refreshTime="2026-01-01T00:01:00Z",
                    syncedResourceVersion=rotation.eso_version(obj["metadata"]))
            self.patch_hook()
            return copy.deepcopy(obj)
        if path.endswith("/eviction"):
            if not self.evict:
                raise rotation.RotationError("RotationDisruptionBudgetBlocked")
            assert body["deleteOptions"]["preconditions"] == {
                "uid": "kbs-old-uid", "resourceVersion": "opaque-v1"}
            new = copy.deepcopy(self.pod)
            new["metadata"].update(name="kbs-new", uid="kbs-new-uid")
            self.objects[BASE + "/pods"] = {"items": [new]}
            return {"status": "Success"}
        if path.endswith("/leases"):
            obj = copy.deepcopy(body)
            obj["metadata"].update(uid="lease-uid", resourceVersion="v1")
            self.objects[path + "/" + obj["metadata"]["name"]] = obj
            return copy.deepcopy(obj)
        raise AssertionError((method, path))


def test_eso_version_matches_go_format_and_is_order_independent():
    # Golden produced by Go fmt.Sprintf("%+v", HashMeta), sha3.Sum224.
    metadata = {"generation": 3, "annotations": {"z": "2", "a": "1"}, "labels": {"owner": "alice"}}
    expected = "3-ab19100cd4e19e66643a5c958016eed2944c0e6faee641052f1fbb8b"
    assert rotation.eso_version(metadata) == expected
    assert rotation.eso_version(dict(metadata, annotations={"a": "1", "z": "2"})) == expected


def test_refresh_acknowledgement_and_guarded_reload():
    api = Api()
    rotation.refresh_resource(api, ES, "alice", REG, "owner-store", 10, clock=lambda: 0)
    checks = []
    rotation.reload_trustee(api, api.ref, lambda: checks.append(True), 10, clock=lambda: 0)
    assert checks
    writes = [(m, p) for m, p, _ in api.events if m != "GET"]
    assert writes == [("PATCH", ES), ("POST", BASE + "/pods/kbs-old/eviction")]
    assert attestation.trustee_deployment_digest(api.objects[DEP]["spec"]) == api.ref["sha256"]


@pytest.mark.parametrize("case", ["foreign-owner", "foreign-registration", "foreign-vault", "store", "datafrom", "target", "not-ready", "unknown-eso"])
def test_bad_resource_stops_before_mutation(case):
    api = Api()
    obj = api.objects[ES]
    if case == "foreign-owner": obj["metadata"]["labels"]["saw.redhat.com/portal-owner"] = "bob"
    if case == "foreign-registration": obj["metadata"]["labels"]["saw.redhat.com/registration"] = "b" * 16
    if case == "foreign-vault": obj["spec"]["data"][0]["remoteRef"]["key"] = f"secret/data/hub/saw-bob/{REG}/inference"
    if case == "store": obj["spec"]["secretStoreRef"]["name"] = "foreign"
    if case == "datafrom": obj["spec"]["dataFrom"] = [{"extract": {"key": "foreign"}}]
    if case == "target": obj["spec"]["target"]["name"] = "foreign"
    if case == "not-ready": obj["status"]["conditions"] = []
    if case == "unknown-eso": obj["status"]["syncedResourceVersion"] = "unsupported-version"
    with pytest.raises(rotation.RotationError):
        rotation.refresh_resource(api, ES, "alice", REG, "owner-store", 10, clock=lambda: 0)
    assert all(m == "GET" for m, _, _ in api.events)


def test_refresh_timeout_stops_before_trustee_reload():
    api = Api()
    api.refresh = False
    with pytest.raises(rotation.RotationError, match="RotationTimedOut"):
        rotation.refresh_resource(api, ES, "alice", REG, "owner-store", 0, clock=lambda: 0)
    assert not any(p.endswith("/eviction") for _, p, _ in api.events)


def test_refresh_change_is_rejected():
    api = Api()
    api.patch_hook = lambda: api.objects[ES]["metadata"].update(uid="replacement")
    with pytest.raises(rotation.RotationError, match="InputsChanged"):
        rotation.refresh_resource(api, ES, "alice", REG, "owner-store", 10, clock=lambda: 0)


@pytest.mark.parametrize("case", ["uid", "digest", "replicas", "owner", "pending", "partial-list", "pdb"])
def test_trustee_rejects_changed_approval_and_unsafe_eviction(case):
    api = Api()
    if case == "uid": api.objects[DEP]["metadata"]["uid"] = "replacement"
    if case == "digest": api.objects[DEP]["spec"]["template"]["spec"]["containers"][0]["image"] = "foreign"
    if case == "replicas": api.objects[DEP]["spec"]["replicas"] = 2
    if case == "owner": api.objects[RS]["metadata"]["ownerReferences"][0]["uid"] = "foreign"
    if case == "pending": api.pod["status"] = {}
    if case == "partial-list": api.objects[BASE + "/pods"]["metadata"] = {"continue": "next"}
    if case == "pdb": api.evict = False
    with pytest.raises(rotation.RotationError):
        rotation.reload_trustee(api, api.ref, lambda: None, 10, clock=lambda: 0)
    assert not any(m == "PATCH" for m, _, _ in api.events)


def lifecycle(api):
    cm = {"metadata": meta("saw-ws-alice"), "data": {"user.json": json.dumps({
        "name": "alice", "vaultPrefix": f"secret/data/hub/saw-alice/{REG}",
        "values": {"deployment": {"mode": "kata"}}, "lifecycleVersion": 1,
        "intentGeneration": 1, "desiredState": "Running", "modelInputs": {"inference.model": "test-model"}})}}
    st = {"metadata": meta("status", labels={"saw.redhat.com/runtime-owner": INSTALLATION,
           "saw.redhat.com/managed-by": "kubernetes-runtime-controller"}), "data": {"status.json": json.dumps({
           "observedGeneration": 1, "phase": "GenericReady"})}}
    life = rotation.ManagedLifecycle(api, "alice", REG, INSTALLATION, "portal", "saw-alice", "status")
    api.objects[life.path] = cm
    api.objects[life.status_path] = st
    return life


def test_managed_stop_start_preserves_model_and_approval_inputs():
    api = Api()
    life = lifecycle(api)
    life.preflight()
    original = copy.deepcopy(life.initial)
    def acknowledge():
        entry = json.loads(api.objects[life.path]["data"]["user.json"])
        api.objects[life.status_path]["data"]["status.json"] = json.dumps({
            "observedGeneration": entry["intentGeneration"],
            "phase": "Stopped" if entry["desiredState"] == "Stopped" else "GenericReady"})
    api.patch_hook = acknowledge
    life.change("Stopped", 10, clock=lambda: 0)
    life.change("Running", 10, clock=lambda: 0)
    result = json.loads(api.objects[life.path]["data"]["user.json"])
    assert result == dict(original, intentGeneration=3)
    assert all(p == life.path for m, p, _ in api.events if m != "GET")


@pytest.mark.parametrize("case", ["legacy", "deleting", "writer", "foreign", "blocked", "stale", "status-owner"])
def test_lifecycle_refuses_unsupported_or_changed_registration(case):
    api = Api()
    life = lifecycle(api)
    entry = json.loads(api.objects[life.path]["data"]["user.json"])
    if case == "legacy": del entry["lifecycleVersion"]
    if case == "foreign": entry["vaultPrefix"] = f"secret/data/hub/saw-bob/{REG}"
    if case == "deleting": api.objects[life.path]["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
    if case == "writer": api.objects[life.path]["metadata"]["annotations"] = {"saw.redhat.com/credential-writer": "busy"}
    if case == "blocked": api.objects[life.status_path]["data"]["status.json"] = json.dumps({"phase": "Blocked", "observedGeneration": 1})
    if case == "stale": api.objects[life.status_path]["data"]["status.json"] = json.dumps({"phase": "GenericReady", "observedGeneration": 2})
    if case == "status-owner": api.objects[life.status_path]["metadata"]["labels"]["saw.redhat.com/runtime-owner"] = "foreign"
    api.objects[life.path]["data"]["user.json"] = json.dumps(entry)
    with pytest.raises(rotation.RotationError): life.preflight()
    assert all(m == "GET" for m, _, _ in api.events)


def test_shared_maintenance_lock_never_steals_and_releases_on_failure():
    api = Api()
    with pytest.raises(ValueError, match="test-failure"):
        with rotation.maintenance_lock(api, NS):
            with pytest.raises(rotation.RotationError, match="MaintenanceLocked"):
                with rotation.maintenance_lock(api, NS): pass
            raise ValueError("test-failure")
    with rotation.maintenance_lock(api, NS): pass
    assert api.objects[f"/apis/coordination.k8s.io/v1/namespaces/{NS}/leases/saw-credential-rotation"]["spec"]["holderIdentity"] == ""


def test_cli_safe_errors_never_display_api_stderr(monkeypatch, capsys):
    path = Path(__file__).resolve().parents[2] / "scripts/confidential-rotate.py"
    spec = importlib.util.spec_from_file_location("rotation_cli", path)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    class Result:
        returncode = 1
        stderr = "Forbidden: private-manifest-canary"
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **kw: Result())
    with pytest.raises(rotation.RotationError, match="^RotationPermissionDenied$"):
        cli.Cluster("context")("GET", BASE + "/pods")
    with pytest.raises(rotation.RotationError, match="ApiScopeRejected"):
        cli.Cluster("context")("GET", BASE + "/secrets/credential")
    monkeypatch.setattr(cli.sys, "argv", ["rotate", "--context", "context", "--owner", "alice", "--registration", REG, "--secret-store", "store"])
    assert cli.main() == 1
    out = capsys.readouterr()
    assert "private-manifest-canary" not in out.out + out.err


def test_complete_rotation_orders_refresh_reload_and_restart(monkeypatch):
    api = Api()
    scope = dict(owner="alice", registration="a" * 16, installation=INSTALLATION,
                 externalSecretPath=ES, secretStore="store", trustee=api.ref)
    events = []
    life = type("Life", (), {"preflight": lambda self: events.append("preflight"),
                           "change": lambda self, state, *a, **kw: events.append(state)})()
    identifiers = iter([{"old"}, {"new"}])
    monkeypatch.setattr(rotation, "supervisors", lambda *a: next(identifiers))
    monkeypatch.setattr(rotation, "refresh_resource", lambda *a, **kw: events.append("refresh"))
    monkeypatch.setattr(rotation, "reload_trustee", lambda *a, **kw: events.append("reload"))
    rotation.rotate(api, scope, life, lambda: events.append("verify"), clock=lambda: 0)
    assert [e for e in events if e != "verify"] == ["preflight", "refresh", "reload", "Stopped", "Running"]


@pytest.mark.parametrize("stage", ["refresh_resource", "reload_trustee"])
def test_failed_credential_refresh_never_restarts_workspaces(monkeypatch, stage):
    api = Api()
    scope = dict(owner="alice", registration="a" * 16, installation=INSTALLATION,
                 externalSecretPath=ES, secretStore="store", trustee=api.ref)
    life = type("Life", (), {"preflight": lambda self: None,
                           "change": lambda *a, **kw: pytest.fail("must not restart")})()
    monkeypatch.setattr(rotation, "supervisors", lambda *a: {"old"})
    monkeypatch.setattr(rotation, "refresh_resource", lambda *a, **kw: None)
    monkeypatch.setattr(rotation, "reload_trustee", lambda *a, **kw: None)
    def fail(*a, **kw): raise rotation.RotationError("RotationTestStopped")
    monkeypatch.setattr(rotation, stage, fail)
    with pytest.raises(rotation.RotationError, match="RotationTestStopped"):
        rotation.rotate(api, scope, life, lambda: None, clock=lambda: 0)




def supervisor_fixture(api):
    scope = dict(runtimeNamespace="saw-alice", runtimeNamespaceUID="namespace-uid",
                 installation=INSTALLATION, runtimeClass="confidential-runtime",
                 supervisorImage="example.test/supervisor@sha256:" + "c" * 64,
                 supervisorInitData={"measured-init-data"})
    api.objects["/api/v1/namespaces/saw-alice"] = {"metadata": dict(
        name="saw-alice", uid="namespace-uid", resourceVersion="v1",
        labels={"saw.redhat.com/runtime-owner": INSTALLATION})}
    pod = {"metadata": dict(name="supervisor", uid="supervisor-uid", resourceVersion="v1",
                            labels={"openshell.ai/boundary-role": "supervisor"},
                            annotations={"io.katacontainers.config.hypervisor.cc_init_data": "measured-init-data"}),
           "spec": {"runtimeClassName": scope["runtimeClass"],
                    "containers": [{"name": "supervisor", "image": scope["supervisorImage"]}]},
           "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
    api.objects["/api/v1/namespaces/saw-alice/pods"] = {"items": [pod]}
    return scope, pod


@pytest.mark.parametrize("case", ["valid", "runtime", "image", "init-data", "namespace", "duplicate", "missing"])
def test_supervisor_inventory_binds_the_enrolled_placement(case):
    api = Api()
    scope, pod = supervisor_fixture(api)
    if case == "runtime": pod["spec"]["runtimeClassName"] = "runc"
    if case == "image": pod["spec"]["containers"][0]["image"] = "foreign-image"
    if case == "init-data": pod["metadata"]["annotations"].clear()
    if case == "namespace": api.objects["/api/v1/namespaces/saw-alice"]["metadata"]["uid"] = "replaced"
    if case == "duplicate": api.objects["/api/v1/namespaces/saw-alice/pods"]["items"].append(pod)
    if case == "missing": api.objects["/api/v1/namespaces/saw-alice/pods"]["items"] = []
    if case == "valid":
        assert rotation.supervisors(api, scope) == {"supervisor-uid"}
    elif case == "missing":
        assert rotation.supervisors(api, scope) is None
    else:
        with pytest.raises(rotation.RotationError): rotation.supervisors(api, scope)


def test_running_old_supervisor_cannot_count_as_success(monkeypatch):
    api = Api()
    scope = dict(owner="alice", registration="a" * 16, installation=INSTALLATION,
                 externalSecretPath=ES, secretStore="store", trustee=api.ref)
    life = type("Life", (), {"preflight": lambda self: None, "change": lambda *a, **kw: None})()
    monkeypatch.setattr(rotation, "supervisors", lambda *a: {"old"})
    monkeypatch.setattr(rotation, "refresh_resource", lambda *a, **kw: None)
    monkeypatch.setattr(rotation, "reload_trustee", lambda *a, **kw: None)
    now = iter([0, 60])
    with pytest.raises(rotation.RotationError, match="RotationTimedOut"):
        rotation.rotate(api, scope, life, lambda: None, timeout=60, clock=lambda: next(now))


@pytest.fixture
def prepared(monkeypatch):
    from saw_kubernetes import boundary, compiler, preflight
    api = Api()
    life = lifecycle(api)
    api.objects[ES]["spec"]["secretStoreRef"]["name"] = "store"
    placement, _ = supervisor_fixture(api)
    config = dict(namespace="saw-alice", namespaceUID="namespace-uid", ownerID=INSTALLATION,
                  gateway="alice", mode="kata", workloadRuntimeClass="confidential-runtime",
                  trustedNamespace="saw-ctl-" + "a" * 16, intent="intent", profile="profile", status="status")
    context = dict(owner="alice", registration="a" * 16, installation=INSTALLATION,
                   settings={"references": {"trustee": api.ref}, "driver": {"supervisorImage": placement["supervisorImage"]}})
    files = {"bom.yaml": "public profile"}
    profile = {"metadata": dict(name="profile", uid="profile-uid", resourceVersion="v1",
               labels={"saw.redhat.com/runtime-owner": INSTALLATION}), "data": files}
    intent = {"schemaVersion": 1, "generation": 1, "desiredState": "Running", "bindings": {},
              "profileRef": {"name": "profile", "uid": "profile-uid", "sha256": compiler.digest(files), "planSHA256": "compiled"}}
    api.objects["/api/v1/namespaces/saw-ctl-" + "a" * 16 + "/configmaps/alice-reconciler"] = {
        "metadata": dict(name="alice-reconciler", uid="config-uid", resourceVersion="v1"),
        "data": {"controller.json": json.dumps(config)}}
    api.objects["/api/v1/namespaces/saw-alice/configmaps/profile"] = profile
    api.objects["/api/v1/namespaces/saw-alice/configmaps/intent"] = {
        "metadata": dict(name="intent", uid="intent-uid", resourceVersion="v1",
                         labels={"saw.redhat.com/runtime-owner": INSTALLATION}), "data": {"intent.json": json.dumps(intent)}}
    api.objects["/apis/external-secrets.io/v1/clustersecretstores/store"] = {
        "metadata": dict(name="store", uid="store-uid", resourceVersion="v1"),
        "spec": {"conditions": [{"namespaces": ["trustee"]}], "provider": {"vault": {
            "version": "v2", "server": "https://vault.example.test", "caBundle": "public-ca",
            "auth": {"kubernetes": {"serviceAccountRef": {"namespace": "trustee"}}}}}},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
    monkeypatch.setattr(boundary, "_confidential_context", lambda c: context)
    monkeypatch.setattr(boundary, "verify", lambda *a: None)
    monkeypatch.setattr(boundary, "objects", lambda c: {})
    monkeypatch.setattr(compiler, "compile_profile_files", lambda *a: {
        "revision": "compiled", "attestation": {"placements": {"default/notebook": {"supervisor": {"init_data": "measured-init-data"}}}}})
    runtime_class = {"metadata": meta("confidential-runtime", labels={"openshell.ai/sandbox-attachable": "true"}),
                     "handler": "kata-remote", "scheduling": {"nodeSelector": {"dedicated": "confidential"}}}
    api.objects["/apis/node.k8s.io/v1/runtimeclasses/confidential-runtime"] = runtime_class
    runtime_ref = {"name": "confidential-runtime", "uid": runtime_class["metadata"]["uid"],
                   "sha256": preflight.runtime_placement_digest(runtime_class)}
    monkeypatch.setattr(compiler, "compile_profile_files", lambda *a: {
        "revision": "compiled", "runtimeClass": runtime_ref,
        "attestation": {"placements": {"default/notebook": {"supervisor": {"init_data": "measured-init-data"}}}}})
    allowed = [True]
    def request(method, path, body=None):
        if path.endswith("/selfsubjectaccessreviews"):
            return {"status": {"allowed": allowed[0]}}
        return api(method, path, body)
    return api, request, allowed, life


def test_prepare_is_read_only_and_rechecks_config_identity(prepared):
    api, request, _, _ = prepared
    scope, _, verify = rotation.prepare(request, "alice", "a" * 16, "store", "portal")
    assert scope["runtimeNamespaceUID"] == "namespace-uid"
    assert all(m == "GET" for m, _, _ in api.events)
    path = next(p for p in api.objects if p.endswith("/configmaps/alice-reconciler"))
    api.objects[path]["metadata"]["uid"] = "foreign"
    with pytest.raises(rotation.RotationError, match="InputsChanged"): verify()


@pytest.mark.parametrize("case", ["permission", "store-scope", "vault-tls", "foreign-source", "profile", "legacy"])
def test_prepare_failure_never_changes_resources(prepared, case):
    api, request, allowed, life = prepared
    if case == "permission": allowed[0] = False
    store = api.objects["/apis/external-secrets.io/v1/clustersecretstores/store"]
    if case == "store-scope": store["spec"]["conditions"] = []
    if case == "vault-tls": store["spec"]["provider"]["vault"]["server"] = "http://vault.example.test"
    if case == "foreign-source": api.objects[ES]["spec"]["data"][0]["remoteRef"]["key"] = "secret/data/hub/saw-bob/" + "a" * 16 + "/inference"
    if case == "profile": api.objects["/api/v1/namespaces/saw-alice/configmaps/profile"]["data"]["bom.yaml"] = "changed"
    if case == "legacy":
        entry = json.loads(api.objects[life.path]["data"]["user.json"])
        entry.pop("lifecycleVersion")
        api.objects[life.path]["data"]["user.json"] = json.dumps(entry)
    with pytest.raises(rotation.RotationError): rotation.prepare(request, "alice", "a" * 16, "store", "portal")
    assert all(m == "GET" for m, _, _ in api.events)


@pytest.mark.parametrize("case", ["runtime-class", "credential-source", "registry"])
def test_approval_changes_after_prepare_stop_the_next_step(prepared, case):
    api, request, _, life = prepared
    _, _, verify = rotation.prepare(request, "alice", REG, "store", "portal")
    if case == "runtime-class":
        api.objects["/apis/node.k8s.io/v1/runtimeclasses/confidential-runtime"]["scheduling"] = {"nodeSelector": {"foreign": "true"}}
    if case == "credential-source":
        api.objects[ES]["spec"]["data"][0]["remoteRef"]["key"] = f"secret/data/hub/saw-bob/{REG}/inference"
    if case == "registry":
        entry = json.loads(api.objects[life.path]["data"]["user.json"])
        entry["intentGeneration"] += 1
        api.objects[life.path]["data"]["user.json"] = json.dumps(entry)
    with pytest.raises(rotation.RotationError): verify()
    assert all(m == "GET" for m, _, _ in api.events)
