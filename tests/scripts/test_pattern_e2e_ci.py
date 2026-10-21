"""Failure paths for the manual cluster workflow."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.ci import e2e_control, pattern_e2e


@pytest.fixture
def runner(monkeypatch, tmp_path):
    variables = {
        "CI_HEAD_SHA": "a" * 40,
        "GITHUB_RUN_ID": "123",
        "CI_RUN_URL": "https://github.com/example/repo/actions/runs/123",
        "GITHUB_REPOSITORY": "example/repo",
        "CI_TARGET_BRANCH": "ci/pattern-e2e/123-1",
        "CI_PR_NUMBER": "42",
        "CI_ARTIFACT_DIR": str(tmp_path),
    }
    for key, value in variables.items():
        monkeypatch.setenv(key, value)
    return pattern_e2e.Runner()


def test_parent_argo_drift_is_ready_when_child_apps_are_healthy(runner):
    child = {
        "metadata": {"name": "saw-ciowner"},
        "status": {"sync": {"status": "Synced", "revision": runner.sha},
                   "health": {"status": "Healthy"}},
    }
    parent = {
        "metadata": {"name": "saw-users"},
        "status": {"sync": {"status": "OutOfSync", "revision": runner.sha},
                   "health": {"status": "Healthy"},
                   "resources": [{"kind": "Application", "name": "saw-ciowner",
                                  "status": "OutOfSync"}]},
    }
    assert runner.application_ready(parent, {"saw-ciowner": child})


def test_parent_argo_drift_fails_when_child_is_not_at_tested_sha(runner):
    child = {
        "metadata": {"name": "saw-ciowner"},
        "status": {"sync": {"status": "Synced", "revision": "b" * 40},
                   "health": {"status": "Healthy"}},
    }
    parent = {
        "metadata": {"name": "saw-users"},
        "status": {"sync": {"status": "OutOfSync", "revision": runner.sha},
                   "health": {"status": "Healthy"},
                   "resources": [{"kind": "Application", "name": "saw-ciowner",
                                  "status": "OutOfSync"}]},
    }
    assert not runner.application_ready(parent, {"saw-ciowner": child})


def test_parent_argo_drift_does_not_ignore_non_application_resources(runner):
    parent = {
        "status": {"sync": {"status": "OutOfSync", "revision": runner.sha},
                   "health": {"status": "Healthy"},
                   "resources": [{"kind": "Deployment", "name": "unexpected",
                                  "status": "OutOfSync"}]},
    }
    assert not runner.application_ready(parent, {})


@pytest.mark.parametrize(("system", "machine", "expected"), [
    ("Linux", "x86_64", ("linux", "x86_64", "tar.gz")),
    ("Darwin", "arm64", ("mac", "arm 64", "zip")),
])
def test_virtctl_download_target_matches_host(runner, monkeypatch, system, machine, expected):
    monkeypatch.setattr(pattern_e2e.platform, "system", lambda: system)
    monkeypatch.setattr(pattern_e2e.platform, "machine", lambda: machine)
    assert runner.virtctl_download_target() == expected


def test_busy_lock_reports_owner_without_replacing_it(runner, monkeypatch):
    calls = []

    def fake_call(args, **_kwargs):
        calls.append(args)
        if args[:2] == ["oc", "create"]:
            return SimpleNamespace(returncode=1, stderr="already exists", stdout="")
        return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({
            "metadata": {"annotations": {"saw.redhat.com/run-url":
                                         "https://github.com/example/repo/actions/runs/12"}}}))

    monkeypatch.setattr(runner, "call", fake_call)
    with pytest.raises(pattern_e2e.E2EError, match="cluster is busy:.*runs/12"):
        runner.acquire_lock()
    assert runner.locked is False
    assert all(args[:2] != ["oc", "delete"] for args in calls)


def test_lock_owner_change_prevents_release(runner, monkeypatch):
    runner.locked = True
    monkeypatch.setattr(runner, "oc_json", lambda *_args: {
        "metadata": {"annotations": {"saw.redhat.com/run-id": "other",
                                     "saw.redhat.com/sha": "a" * 40}}})
    with pytest.raises(pattern_e2e.E2EError, match="owner changed"):
        runner.release_lock()
    assert runner.locked


def test_release_removes_run_created_lock_namespace(runner, monkeypatch):
    runner.locked = True
    runner.lock_namespace_created = True
    calls = []
    monkeypatch.setattr(runner, "oc_json", lambda *_args: {"metadata": {
        "annotations": {"saw.redhat.com/run-id": runner.run_id,
                        "saw.redhat.com/sha": runner.sha}}})
    monkeypatch.setattr(runner, "call", lambda args, **_kwargs:
                        calls.append(args))
    runner.release_lock()
    assert calls[0][:4] == ["oc", "delete", "configmap", pattern_e2e.LOCK_NAME]
    assert calls[1][:4] == ["oc", "delete", "namespace", runner.lock_ns]
    assert runner.locked is False


def test_failed_command_keeps_stdout_cause_and_stderr_status(runner, monkeypatch):
    monkeypatch.setattr(pattern_e2e.subprocess, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=1, stdout="build root cause",
                                        stderr="build terminal status"))
    with pytest.raises(pattern_e2e.E2EError) as error:
        runner.call(["make", "sandbox-build"])
    assert "build root cause" in str(error.value)
    assert "build terminal status" in str(error.value)


def test_install_patches_pattern_api_port_for_operator(runner, monkeypatch):
    topology = {"cleanupApi": {"serviceIP": "172.30.0.1", "endpoints": [
        {"ip": "192.0.2.10", "port": 6443}]}, "networkPolicy": {
        "clusterNetworkCIDRs": ["10.128.0.0/14"],
        "serviceNetworkCIDRs": ["172.30.0.0/16"]}}
    calls = []

    def fake_call(args, **_kwargs):
        calls.append(args)
        if args[1] == "get":
            return SimpleNamespace(returncode=0, stdout=json.dumps({"spec": {
                "extraParameters": [{"name":
                    "defaults.openshellSaw.cleanupApi.endpoints[0].port",
                    "value": "6443"}]}}), stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(runner, "call", fake_call)
    assert runner.quote_pattern_api_ports(topology)
    patch = json.loads(calls[-1][-1])
    assert patch[-1] == {"op": "replace", "path":
                         "/spec/extraParameters/0/value", "value": '"6443"'}


def test_build_waits_for_terminal_phase_before_digest(runner, monkeypatch):
    digest = "sha256:" + "a" * 64
    waited = []
    monkeypatch.setattr(runner, "call", lambda *_args, **_kwargs: None)

    def fake_oc_json(*args):
        if args[1] == "builds":
            name = args[-1].split("=", 1)[1]
            phase = "Running" if name == "governance-interceptor" else "Complete"
            return {"items": [{"metadata": {"name": name + "-1",
                                            "creationTimestamp": "2026-10-20T00:00:00Z"},
                               "status": {"phase": phase,
                                          "output": {"to": {"imageDigest": digest}}}}]}
        return {"status": {"phase": "Complete",
                           "output": {"to": {"imageDigest": digest}}}}

    def fake_wait(label, predicate, **_kwargs):
        waited.append(label)
        assert predicate()

    monkeypatch.setattr(runner, "oc_json", fake_oc_json)
    monkeypatch.setattr(runner, "wait_for", fake_wait)
    runner.build()
    assert waited == ["governance-interceptor build terminal phase"]
    assert runner.report["image_digests"]["governance-interceptor"] == digest


def test_install_options_use_guest_registry_and_public_ca_file(runner):
    digest = "sha256:" + "a" * 64
    runner.report["image_digests"] = {name: digest for name in (
        "nemoclaw-sandbox", "nemoclaw-cli", "openshell-gateway",
        "governance-interceptor")}
    topology = {"cleanupApi": {"serviceIP": "172.30.0.1", "endpoints": [
        {"ip": "192.0.2.10", "port": 6443}]}, "networkPolicy": {
        "clusterNetworkCIDRs": ["10.128.0.0/14"],
        "serviceNetworkCIDRs": ["172.30.0.0/16"]}}
    options = runner.install_options(topology)
    assert f"{pattern_e2e.REGISTRY_HOST}/{pattern_e2e.NAMESPACE}/nemoclaw-cli@{digest}" in options
    assert f"{pattern_e2e.REGISTRY_HOST}/{pattern_e2e.NAMESPACE}/nemoclaw-sandbox@{digest}" in options
    assert "defaults.openshellSaw.registry.authSecret" in options
    assert "--set-file main.extraParameters[" in options
    assert "/pattern-home/cluster-service-ca.crt" in options


def test_cleanup_failure_cannot_report_success(runner, monkeypatch):
    runner.locked = True
    monkeypatch.setattr(runner, "setup_files", lambda: None)
    monkeypatch.setattr(runner, "preflight", lambda: None)
    monkeypatch.setattr(runner, "build", lambda: None)
    monkeypatch.setattr(runner, "install", lambda: None)
    monkeypatch.setattr(runner, "verify_install", lambda: None)
    monkeypatch.setattr(runner, "live_behavior", lambda: None)
    monkeypatch.setattr(runner, "diagnostics", lambda: None)
    monkeypatch.setattr(runner, "cleanup", lambda: (_ for _ in ()).throw(
        pattern_e2e.E2EError("namespace remains")))
    assert runner.run() == 1
    assert runner.report["cleanup_verified"] is False
    assert "cleanup_error" in runner.report
    assert runner.locked


def test_cleanup_removes_only_run_created_pattern_infrastructure(runner, monkeypatch):
    runner.baseline_namespaces = {"vp-gitops"}
    namespaces = {"vp-gitops", "patterns-operator"}
    deleted = []

    def fake_call(args, **_kwargs):
        if args[:3] == ["oc", "delete", "namespace"]:
            deleted.append(args[3])
            namespaces.remove(args[3])
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[:3] == ["oc", "get", "namespace"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="NotFound")
        return SimpleNamespace(returncode=0, stdout='{"items": []}', stderr="")

    monkeypatch.setattr(runner, "call", fake_call)
    monkeypatch.setattr(runner, "oc_json", lambda *_args: {"items": [
        {"metadata": {"name": name}} for name in namespaces]})
    monkeypatch.setattr(runner, "release_lock", lambda: None)
    runner.cleanup()
    assert deleted == ["patterns-operator"]
    assert runner.report["cleanup_verified"] is True


def test_changed_pr_sha_is_rejected(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "example/repo")
    monkeypatch.setenv("CI_PR_NUMBER", "42")
    monkeypatch.setenv("CI_HEAD_SHA", "a" * 40)
    monkeypatch.setattr(e2e_control, "api", lambda *_args: {
        "state": "open", "head": {"sha": "b" * 40,
                                   "repo": {"full_name": "example/repo"}}})
    with pytest.raises(RuntimeError, match="SHA changed"):
        e2e_control.prepare()


def test_current_approval_and_merge_check_allow_fixed_ref(monkeypatch, tmp_path):
    sha = "a" * 40
    merge = "b" * 40
    output = tmp_path / "output"
    for key, value in {
        "GITHUB_REPOSITORY": "example/repo", "CI_PR_NUMBER": "42",
        "CI_HEAD_SHA": sha, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
        "CI_RUN_URL": "https://github.com/example/repo/actions/runs/123",
        "GITHUB_OUTPUT": str(output),
    }.items():
        monkeypatch.setenv(key, value)
    calls = []

    def fake_api(method, path, payload=None):
        calls.append((method, path, payload))
        if path.endswith("/pulls/42"):
            return {"state": "open", "head": {"sha": sha,
                    "repo": {"full_name": "example/repo"}},
                    "merge_commit_sha": merge}
        if path.endswith("/reviews?per_page=100"):
            return [{"state": "APPROVED", "commit_id": sha,
                     "user": {"login": "reviewer"}}]
        if f"/{merge}/check-runs" in path:
            return {"check_runs": [{"name": "Deployment validation",
                    "conclusion": "success", "app": {"slug": "github-actions"}}]}
        return {"check_runs": []}

    monkeypatch.setattr(e2e_control, "api", fake_api)
    e2e_control.prepare()
    assert output.read_text() == f"sha={sha}\nbranch=ci/pattern-e2e/123-1\n"
    assert any(method == "POST" and path.endswith("/git/refs") for method, path, _ in calls)
    assert any(method == "POST" and path.endswith("/statuses/" + sha)
               and payload["context"] == "Pattern E2E" for method, path, payload in calls)
