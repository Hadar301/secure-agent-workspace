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


def test_failed_command_keeps_stdout_cause_and_stderr_status(runner, monkeypatch):
    monkeypatch.setattr(pattern_e2e.subprocess, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=1, stdout="build root cause",
                                        stderr="build terminal status"))
    with pytest.raises(pattern_e2e.E2EError) as error:
        runner.call(["make", "sandbox-build"])
    assert "build root cause" in str(error.value)
    assert "build terminal status" in str(error.value)


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
