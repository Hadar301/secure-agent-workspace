"""Preparation reserves real IDs without opening the credential or runtime gate."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("confidential_prepare", ROOT / "scripts/confidential-prepare.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_MODE", "kata")
    user = {"name": "alice", "ownerSubject": "11111111-1111-4111-8111-111111111111",
            "registration": "a" * 16, "installationID": "22222222-2222-4222-8222-222222222222",
            "profiles": ["kata-data-science"], "intentGeneration": 1, "pruneOnRemove": True,
            "values": {"deployment": {"mode": "kata"}}}
    runtime = {"metadata": {"name": "confidential-runtime", "uid": "runtime-id",
                            "labels": {"openshell.ai/sandbox-attachable": "true"}},
               "handler": "kata-remote", "scheduling": {"nodeSelector": {"dedicated": "confidential"}}}
    site = {"subject": user["ownerSubject"], "attestation": {"enabled": True},
            "automaticEnrollment": {"enabled": False},
            "kataRuntimeClass": {"name": runtime["metadata"]["name"], "uid": "runtime-id",
                                 "sha256": prepare.install.preflight_checks.runtime_placement_digest(runtime)},
            "stack": {"audit": {"values": {"storageClass": "private-rwo", "exchangeStorageClass": "shared-rwx"}}}}
    config, selected = prepare.install.select({"users": [user], "containerSites": {"alice": site},
                                               "global": {"clusterDomain": "cluster.example.test"}}, "alice")
    return config, selected, runtime


def render(release, namespace, values):
    result = subprocess.run(["helm", "template", release, str(ROOT / "charts/saw-audit-writer"),
                             "-n", namespace, "-f", "-"], input=json.dumps(values),
                            text=True, capture_output=True, check=True)
    return [r for r in yaml.safe_load_all(result.stdout) if r]


class Cluster:
    def __init__(self, runtime, resources=()):
        self.objects = {
            ("ingress.config.openshift.io", "cluster", None): {"spec": {"domain": "apps.cluster.example.test"}},
            ("runtimeclass", "confidential-runtime", None): runtime,
            ("storageclass", "private-rwo", None): {"provisioner": "example.test/disk"},
            ("storageclass", "shared-rwx", None): {"provisioner": "example.test/file"},
        }
        self.creates = []
        self.reads = []
        for obj in resources:
            self.put(obj)

    def put(self, obj):
        obj = copy.deepcopy(obj)
        m = obj["metadata"]
        m.setdefault("uid", "uid-" + m["name"])
        self.objects[(obj["kind"], m["name"], m.get("namespace"))] = obj
        return obj

    def get(self, *key):
        if len(key) == 2: key += (None,)
        self.reads.append(key)
        return self.objects.get(key)

    def command(self, *args):
        assert args[:2] == ("auth", "can-i")

    def create(self, obj, dry_run=False):
        self.creates.append((copy.deepcopy(obj), dry_run))
        return obj if dry_run else self.put(obj)


@pytest.mark.parametrize(("profile", "count"), [("kata-data-science", 4), ("data-science", 8)])
def test_real_chart_prepare_emits_only_the_production_claims(setup, profile, count):
    config, user, _ = setup
    user["profiles"] = [profile]
    resources = prepare.plan(config, user, render)
    assert {r["kind"] for r in resources} == {"Namespace", "NetworkPolicy", "PersistentVolumeClaim"}
    claims = [r for r in resources if r["kind"] == "PersistentVolumeClaim"]
    assert len(claims) == count
    for claim in claims:
        assert claim["metadata"]["annotations"][prepare.MARKER] == user["registration"]
        assert claim["spec"]["resources"]["requests"]["storage"] == "1Gi"
    assert not any(r["kind"] in {"Secret", "ExternalSecret", "Pod", "Deployment", "Job", "Application"}
                   for r in resources)


@pytest.mark.parametrize("fault", ["container", "disabled", "placeholder", "enrollment", "enabled", "storage", "profile"])
def test_invalid_preparation_fails_before_any_cluster_operation(setup, fault):
    config, user, _ = setup
    site = config["containerSites"]["alice"]
    if fault == "container": user["values"]["deployment"]["mode"] = "container"
    if fault == "disabled": site["attestation"]["enabled"] = False
    if fault == "placeholder": site["attestation"] = "unreviewed"
    if fault == "enrollment": site["enrollment"] = {"intent": {}}
    if fault == "enabled": site["automaticEnrollment"]["enabled"] = True
    if fault == "storage": del site["stack"]["audit"]["values"]["exchangeStorageClass"]
    if fault == "profile": user["profiles"] = ["unknown"]
    with pytest.raises(prepare.Error):
        prepare.plan(config, user, render)


def test_unexpected_rendered_resource_is_rejected(setup):
    config, user, _ = setup
    with pytest.raises(prepare.Error, match="RenderRejected"):
        prepare.plan(config, user, lambda *args: [{"kind": "Secret", "data": {"token": "not-real"}}])


def test_read_only_first_stage_reports_admission_not_yet_checked(setup):
    config, user, runtime = setup
    resources = prepare.plan(config, user, render)
    cluster = Cluster(runtime)
    before = copy.deepcopy(cluster.objects)
    result = prepare.prepare(cluster, config, user, resources)
    assert cluster.objects == before
    assert all(dry_run for _, dry_run in cluster.creates)
    assert result["admissionPending"]  # An absent namespace prevents child admission.
    assert result["qualified"] is False and result["enrolled"] is False
    assert not any("secret" in kind.lower() for kind, _, _ in cluster.reads)


def test_apply_and_repeat_preserve_real_object_ids(setup):
    config, user, runtime = setup
    resources = prepare.plan(config, user, render)
    cluster = Cluster(runtime)
    result = prepare.prepare(cluster, config, user, resources, apply=True)
    assert result["phase"] == "StorageReserved"
    assert result["admissionPending"] == []
    assert all(r["uid"] for r in result["resources"])
    assert len([r for r, dry_run in cluster.creates if not dry_run]) == len(resources)
    cluster.creates.clear()
    again = prepare.prepare(cluster, config, user, resources, apply=True)
    assert cluster.creates == []
    assert again["resources"] == result["resources"]


@pytest.mark.parametrize("fault", ["registration", "helm", "argo", "deleting", "class", "size", "network"])
def test_foreign_or_changed_resource_stops_before_writes(setup, fault):
    config, user, runtime = setup
    resources = prepare.plan(config, user, render)
    cluster = Cluster(runtime, resources)
    claim = next(o for k, o in cluster.objects.items() if k[0] == "PersistentVolumeClaim")
    if fault == "registration": claim["metadata"]["annotations"][prepare.MARKER] = "b" * 16
    if fault == "helm": claim["metadata"]["annotations"]["meta.helm.sh/release-name"] = "foreign"
    if fault == "argo": claim["metadata"]["annotations"]["argocd.argoproj.io/tracking-id"] = "foreign"
    if fault == "deleting": claim["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
    if fault == "class": claim["spec"]["storageClassName"] = "foreign"
    if fault == "size": claim["spec"]["resources"]["requests"]["storage"] = "2Gi"
    if fault == "network":
        policy = next(o for k, o in cluster.objects.items() if k[0] == "NetworkPolicy")
        policy["spec"]["egress"] = [{}]
    with pytest.raises(prepare.Error):
        prepare.prepare(cluster, config, user, resources, apply=True)
    assert cluster.creates == []


@pytest.mark.parametrize("fault", ["cluster", "runtime", "storage", "permission"])
def test_platform_failure_stops_before_writes(setup, fault):
    config, user, runtime = setup
    resources = prepare.plan(config, user, render)
    cluster = Cluster(runtime)
    if fault == "cluster": config["global"]["clusterDomain"] = "other.example.test"
    if fault == "runtime": runtime["metadata"]["uid"] = "changed"
    if fault == "storage": del cluster.objects[("storageclass", "shared-rwx", None)]
    if fault == "permission":
        def forbidden(*args): raise prepare.Error("ConfidentialPreparationPermissionDenied")
        cluster.command = forbidden
    with pytest.raises((prepare.Error, prepare.install.preflight_checks.PreflightError)):
        prepare.prepare(cluster, config, user, resources, apply=True)
    assert cluster.creates == []


def test_admission_failure_is_not_converted_to_success(setup):
    config, user, runtime = setup
    resources = prepare.plan(config, user, render)
    cluster = Cluster(runtime, [r for r in resources if r["kind"] == "Namespace"])
    def denied(*args, **kwargs): raise prepare.Error("ConfidentialPreparationAdmissionDenied")
    cluster.create = denied
    with pytest.raises(prepare.Error, match="AdmissionDenied"):
        prepare.prepare(cluster, config, user, resources, apply=True)


def test_api_error_does_not_expose_stderr_or_input(monkeypatch):
    marker = "private-input-must-not-appear"
    monkeypatch.setattr(prepare.subprocess, "run", lambda *a, **kw:
                        subprocess.CompletedProcess(a, 1, "", "admission denied " + marker))
    with pytest.raises(prepare.Error, match="AdmissionDenied") as error:
        prepare.Cluster("test-context").create({"kind": "Pod", "data": marker}, dry_run=True)
    assert marker not in str(error.value)


def test_cli_writes_private_public_record_and_refuses_overwrite(setup, monkeypatch, tmp_path, capsys):
    config, user, runtime = setup
    values = tmp_path / "public-values.yaml"
    values.write_text(yaml.safe_dump(config))
    output = tmp_path / "record.json"
    cluster = Cluster(runtime)
    monkeypatch.setattr(prepare, "Cluster", lambda context: cluster)
    monkeypatch.setattr(prepare.sys, "argv", ["confidential-prepare.py", "--values", str(values),
                        "--name", "alice", "--context", "test-context", "--apply", "--output", str(output)])
    prepare.main()
    assert json.loads(output.read_text())["phase"] == "StorageReserved"
    assert output.stat().st_mode & 0o777 == 0o600
    previous = output.read_bytes()
    cluster.creates.clear()
    with pytest.raises(SystemExit) as stopped:
        prepare.main()
    assert stopped.value.code == 1
    assert output.read_bytes() == previous and cluster.creates == []
    assert "OutputExists" in capsys.readouterr().err


def test_malformed_yaml_does_not_expose_input(monkeypatch, tmp_path, capsys):
    values = tmp_path / "bad-values.yaml"
    marker = "private-input-must-not-appear"
    values.write_text("unclosed: [" + marker)
    monkeypatch.setattr(prepare.sys, "argv", ["confidential-prepare.py", "--values", str(values),
                        "--name", "alice", "--context", "test-context"])
    with pytest.raises(SystemExit) as stopped:
        prepare.main()
    assert stopped.value.code == 1
    assert marker not in capsys.readouterr().err
