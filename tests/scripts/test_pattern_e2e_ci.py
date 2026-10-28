"""Failure paths for the manual cluster workflow."""

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.ci import e2e_control, pattern_e2e, pattern_e2e_cleanup


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


@pytest.mark.parametrize(("output", "expected"), [
    ('{"result":"denied","protocol":"grpc","grpc_code":7}', True),
    ('{"result":"denied","protocol":"grpc","grpc_code":"7"}', False),
    ('{"result":"denied","protocol":"grpc","grpc_code":0}', False),
    ('{"result":"allowed","protocol":"grpc","grpc_code":7}', False),
    ('{"result":"denied","protocol":"http","status_code":403}', False),
    ("not json", False),
])
def test_second_user_denial_requires_grpc_permission_denied(output, expected):
    assert pattern_e2e.second_user_denial_passed(output) is expected


def test_openshell_uses_private_config_without_changing_podman_env(runner, monkeypatch):
    runner.env["XDG_CONFIG_HOME"] = "/host/podman-config"
    runner.openshell_env = dict(runner.env, XDG_CONFIG_HOME="/private/openshell-config")
    captured_envs = []

    class FakeProcess:
        returncode = 0

        def communicate(self, **_kwargs):
            return "", ""

    def fake_popen(_args, **kwargs):
        captured_envs.append(kwargs["env"])
        return FakeProcess()

    monkeypatch.setattr(pattern_e2e.subprocess, "Popen", fake_popen)

    runner.call(["openshell", "gateway", "select", "ciowner"])
    runner.call(["podman", "info"])

    assert captured_envs[0]["XDG_CONFIG_HOME"] == "/private/openshell-config"
    assert captured_envs[1]["XDG_CONFIG_HOME"] == "/host/podman-config"


def test_runner_keeps_podman_config_when_home_is_private(runner, monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", "/host-home")
    configured = pattern_e2e.Runner()
    configured.env["HOME"] = "/private/ci-home"

    assert configured.env["XDG_CONFIG_HOME"] == "/host-home/.config"


def test_read_kubeconfig_file_reads_runtime_login_file(runner, tmp_path, monkeypatch):
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\n", encoding="utf-8")
    monkeypatch.setenv("CI_KUBECONFIG_FILE", str(kubeconfig))

    assert runner.read_kubeconfig_file() == b"apiVersion: v1\nkind: Config\n"


def test_read_kubeconfig_file_rejects_empty_file(runner, tmp_path, monkeypatch):
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.touch()
    monkeypatch.setenv("CI_KUBECONFIG_FILE", str(kubeconfig))

    with pytest.raises(pattern_e2e.E2EError, match="CI_KUBECONFIG_FILE is empty"):
        runner.read_kubeconfig_file()


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


def test_lock_state_update_preserves_run_ownership(runner, monkeypatch):
    lock = {"metadata": {"annotations": {
        "saw.redhat.com/run-id": runner.run_id,
        "saw.redhat.com/sha": runner.sha,
    }}, "data": {"state": "active", "baseline-namespaces": "[]"}}
    calls = []
    monkeypatch.setattr(runner, "oc_json", lambda *_args: lock)

    def fake_call(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(runner, "call", fake_call)
    runner.update_lock_data({"state": "cleanup-required"})

    assert lock["data"] == {"state": "cleanup-required", "baseline-namespaces": "[]"}
    assert calls[0][0] == ["oc", "replace", "-f", "-"]
    assert json.loads(calls[0][1]["input_text"])["metadata"]["annotations"][
        "saw.redhat.com/run-id"] == runner.run_id


def test_release_keeps_lock_namespace_and_deletes_only_configmap(runner, monkeypatch):
    runner.locked = True
    calls = []
    monkeypatch.setattr(runner, "oc_json", lambda *_args: {"metadata": {
        "annotations": {"saw.redhat.com/run-id": runner.run_id,
                        "saw.redhat.com/sha": runner.sha}}})
    monkeypatch.setattr(runner, "call", lambda args, **_kwargs:
                        calls.append(args))
    runner.release_lock()
    assert calls == [["oc", "delete", "configmap", pattern_e2e.LOCK_NAME,
                      "-n", runner.lock_ns, "--wait=true"]]
    assert runner.locked is False


def test_stop_run_utility_containers_by_run_label(runner, monkeypatch):
    calls = []
    all_queries = 0

    def fake_call(args, **_kwargs):
        nonlocal all_queries
        calls.append(args)
        if args[:2] == ["podman", "ps"] and "--all" in args:
            all_queries += 1
            output = "container-1\n" if all_queries == 1 else ""
            return SimpleNamespace(returncode=0, stdout=output, stderr="")
        if args[:2] == ["podman", "ps"]:
            return SimpleNamespace(returncode=0, stdout="container-1\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(runner, "call", fake_call)
    runner.stop_run_utility_containers()

    label_filter = f"label={pattern_e2e.UTILITY_CONTAINER_LABEL}={runner.run_id}"
    assert calls == [
        ["podman", "ps", "--quiet", "--filter", label_filter],
        ["podman", "stop", "--ignore", "--time", "10", "container-1"],
        ["podman", "ps", "--all", "--quiet", "--filter", label_filter],
        ["podman", "rm", "--force", "--ignore", "container-1"],
        ["podman", "ps", "--all", "--quiet", "--filter", label_filter],
    ]


def test_cnv_preflight_allows_absent_crd_on_fresh_cluster(runner, monkeypatch):
    calls = []

    def fake_call(args, **_kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=1, stderr="NotFound", stdout="")

    monkeypatch.setattr(runner, "call", fake_call)
    runner.check_cnv_webhook()
    assert len(calls) == 1


def test_cnv_preflight_rejects_orphaned_crd(runner, monkeypatch):
    crd = {"spec": {"conversion": {"strategy": "Webhook", "webhook": {
        "clientConfig": {"service": {"name": "hco-webhook-service",
                                     "namespace": "openshift-cnv"}}}}}}

    def fake_call(args, **_kwargs):
        if args[2] == "crd":
            return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(crd))
        return SimpleNamespace(returncode=1, stderr="NotFound", stdout="")

    monkeypatch.setattr(runner, "call", fake_call)
    with pytest.raises(pattern_e2e.E2EError, match="stale CNV CRD"):
        runner.check_cnv_webhook()


def test_cnv_preflight_rejects_missing_webhook_service(runner, monkeypatch):
    crd = {"spec": {"conversion": {"strategy": "Webhook", "webhook": {
        "clientConfig": {"service": {"name": "hco-webhook-service",
                                     "namespace": "openshift-cnv"}}}}}}

    def fake_call(args, **_kwargs):
        if args[2] == "crd":
            return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(crd))
        if args[2] == "namespace":
            return SimpleNamespace(returncode=0, stderr="", stdout="openshift-cnv")
        return SimpleNamespace(returncode=1, stderr="NotFound", stdout="")

    monkeypatch.setattr(runner, "call", fake_call)
    with pytest.raises(pattern_e2e.E2EError, match="conversion webhook service"):
        runner.check_cnv_webhook()


def test_failed_command_keeps_stdout_cause_and_stderr_status(runner, monkeypatch):
    class FakeProcess:
        returncode = 1

        def communicate(self, **_kwargs):
            return "build root cause", "build terminal status"

    monkeypatch.setattr(pattern_e2e.subprocess, "Popen",
                        lambda *_args, **_kwargs: FakeProcess())
    with pytest.raises(pattern_e2e.E2EError) as error:
        runner.call(["make", "sandbox-build"])
    assert "build root cause" in str(error.value)
    assert "build terminal status" in str(error.value)


def test_timed_out_command_keeps_redacted_partial_output(runner, monkeypatch):
    runner.sensitive.append("private-token")
    events = []

    class FakeProcess:
        pid = 987
        returncode = -9
        communicate_calls = 0

        def communicate(self, **kwargs):
            self.communicate_calls += 1
            if self.communicate_calls <= 2:
                raise pattern_e2e.subprocess.TimeoutExpired(
                    ["./pattern.sh", "make"], kwargs["timeout"],
                    output=b"partial private-token", stderr=b"ssh wait"
                )
            return "partial private-token", "ssh wait"

    process = FakeProcess()

    def fake_popen(*_args, **kwargs):
        assert kwargs["start_new_session"] is True
        return process

    monkeypatch.setattr(pattern_e2e.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(pattern_e2e.os, "killpg",
                        lambda pid, sig: events.append(("signal", pid, sig)))
    monkeypatch.setattr(runner, "stop_run_utility_containers",
                        lambda: events.append(("stop-containers",)))
    with pytest.raises(pattern_e2e.E2ECommandTimeout) as error:
        runner.call(["./pattern.sh", "make", "install"], timeout=90,
                    allow_failure=True)
    message = str(error.value)
    assert "./pattern.sh make timed out after 90s" in message
    assert "partial [redacted]" in message
    assert "ssh wait" in message
    assert "private-token" not in message
    assert events == [
        ("signal", process.pid, pattern_e2e.signal.SIGTERM),
        ("signal", process.pid, pattern_e2e.signal.SIGKILL),
        ("stop-containers",),
    ]


@pytest.mark.parametrize("run_id", ["123", None])
def test_pattern_script_labels_only_ci_utility_containers(tmp_path, run_id):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    capture = tmp_path / "podman-args"
    podman = fake_bin / "podman"
    podman.write_text(
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        "case \"$1\" in\n"
        "  --version) printf 'podman version 5.4.0\\n' ;;\n"
        "  system) printf 'Name URI Identity Default\\n' ;;\n"
        "  run) printf '%s\\n' \"$@\" > \"$PODMAN_ARGS_CAPTURE\" ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    podman.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    env["HOME"] = str(tmp_path / "home")
    env["PODMAN_ARGS_CAPTURE"] = str(capture)
    env.pop("SAW_CI_RUN_ID", None)
    if run_id is not None:
        env["SAW_CI_RUN_ID"] = run_id

    completed = subprocess.run(
        ["bash", str(pattern_e2e.ROOT / "pattern.sh"), "make", "install"],
        env=env, capture_output=True, text=True, check=False,
    )

    assert completed.returncode == 0, completed.stderr
    args = capture.read_text(encoding="utf-8").splitlines()
    if run_id is None:
        assert "--label" not in args
    else:
        label_index = args.index("--label")
        assert args[label_index + 1] == (
            f"{pattern_e2e.UTILITY_CONTAINER_LABEL}={run_id}")


def test_wait_for_retries_a_timed_out_status_check(runner):
    attempts = 0

    def ready():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise pattern_e2e.E2ECommandTimeout("make timed out")
        return True

    runner.wait_for("installer status", ready, seconds=1, interval=0)
    assert attempts == 2


def test_target_ref_must_point_at_tested_sha(runner, monkeypatch):
    monkeypatch.setattr(runner, "valid_git_branch", lambda _branch: True)
    monkeypatch.setattr(runner, "call", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=0,
                                        stdout=f"{'b' * 40}\trefs/heads/{runner.branch}\n",
                                        stderr=""))

    with pytest.raises(pattern_e2e.E2EError, match="does not point to CI_HEAD_SHA"):
        runner.verify_target_ref()


def test_target_ref_accepts_the_tested_sha(runner, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "valid_git_branch", lambda _branch: True)

    def fake_call(args, **_kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0,
                               stdout=f"{runner.sha}\trefs/heads/{runner.branch}\n",
                               stderr="")

    monkeypatch.setattr(runner, "call", fake_call)
    runner.verify_target_ref()
    assert calls == [["git", "ls-remote", "--heads", "origin",
                      f"refs/heads/{runner.branch}"]]


def test_argo_check_fails_fast_when_all_apps_are_healthy_at_another_sha(
        runner, monkeypatch):
    other_sha = "b" * 40
    applications = [{
        "metadata": {"name": f"app-{index}"},
        "spec": {"source": {"repoURL": f"https://github.com/{runner.repo}.git",
                             "targetRevision": runner.branch}},
        "status": {"sync": {"status": "Synced", "revision": other_sha},
                   "health": {"status": "Healthy"}},
    } for index in range(6)]
    monkeypatch.setattr(runner, "call", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps({
                            "items": applications}), stderr=""))
    monkeypatch.setattr(runner, "wait_for",
                        lambda _label, predicate, **_kwargs: predicate())

    with pytest.raises(pattern_e2e.E2EError, match="not tested SHA"):
        runner.check_argo()


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


def test_pattern_api_port_patch_retries_when_webhook_has_no_endpoints(runner, monkeypatch):
    topology = {"cleanupApi": {"endpoints": [{"ip": "192.0.2.10", "port": 6443}]}}
    patch_attempts = 0

    def fake_call(args, **_kwargs):
        nonlocal patch_attempts
        if args[1] == "get":
            return SimpleNamespace(returncode=0, stdout=json.dumps({"spec": {
                "extraParameters": [{"name":
                    "defaults.openshellSaw.cleanupApi.endpoints[0].port",
                    "value": "6443"}]}}), stderr="")
        patch_attempts += 1
        if patch_attempts == 1:
            return SimpleNamespace(
                returncode=1,
                stdout="",
                stderr=("failed calling webhook: no endpoints available for service "
                        "patterns-operator-controller-manager-service"),
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(runner, "call", fake_call)
    assert not runner.quote_pattern_api_ports(topology)
    assert runner.quote_pattern_api_ports(topology)
    assert patch_attempts == 2


def test_install_checks_pattern_ports_after_make_finishes(runner, monkeypatch):
    topology = {"cleanupApi": {"endpoints": []}}
    monkeypatch.setattr(runner, "topology", lambda: topology)
    monkeypatch.setattr(runner, "install_options", lambda _topology: "options")
    monkeypatch.setattr(runner, "update_lock_data", lambda _updates: None)

    class CompletedFuture:
        @staticmethod
        def done():
            return True

        @staticmethod
        def result():
            return None

    class CompletedPool:
        def __enter__(self):
            return self

        @staticmethod
        def __exit__(self, *_args):
            return False

        @staticmethod
        def submit(*_args, **_kwargs):
            return CompletedFuture()

    monkeypatch.setattr(pattern_e2e, "ThreadPoolExecutor",
                        lambda max_workers: CompletedPool())
    quoted = iter((False, True))
    monkeypatch.setattr(runner, "quote_pattern_api_ports",
                        lambda _topology: next(quoted))
    waits = []

    def fake_wait_for(label, predicate, *, seconds, interval):
        waits.append((label, seconds, interval))
        assert not predicate()
        assert predicate()

    monkeypatch.setattr(runner, "wait_for", fake_wait_for)
    runner.install()
    assert waits == [("Pattern API ports to be quoted", 600, 10)]


def test_build_waits_for_terminal_phase_before_digest(runner, monkeypatch):
    digest = "sha256:" + "a" * 64
    waited = []
    monkeypatch.setattr(runner, "call", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runner, "update_lock_data", lambda _updates: None)

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
    assert runner.report["image_digests"]["saw-credential-proxy"] == digest


def test_install_options_use_guest_registry_and_base64_public_ca(runner, tmp_path):
    digest = "sha256:" + "a" * 64
    runner.report["image_digests"] = {name: digest for name in (
        "nemoclaw-sandbox", "nemoclaw-cli", "openshell-gateway",
        "governance-interceptor", "saw-credential-proxy")}
    runner.home = tmp_path / "home"
    runner.home.mkdir()
    pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    (runner.home / "cluster-service-ca.crt").write_bytes(pem)
    topology = {"cleanupApi": {"serviceIP": "172.30.0.1", "endpoints": [
        {"ip": "192.0.2.10", "port": 6443}]}, "networkPolicy": {
        "clusterNetworkCIDRs": ["10.128.0.0/14"],
        "serviceNetworkCIDRs": ["172.30.0.0/16"]}}
    options = runner.install_options(topology)
    assert f"{pattern_e2e.REGISTRY_HOST}/{pattern_e2e.NAMESPACE}/nemoclaw-cli@{digest}" in options
    assert f"{pattern_e2e.REGISTRY_HOST}/{pattern_e2e.NAMESPACE}/nemoclaw-sandbox@{digest}" in options
    assert "defaults.openshellSaw.credentialProxy.image" in options
    assert f"/saw-credential-proxy@{digest}" in options
    assert "defaults.openshellSaw.registry.authSecret" in options
    assert "defaults.openshellSaw.registry.caBundleBase64" in options
    assert base64.b64encode(pem).decode("ascii") in options
    assert "--set-file" not in options
    assert "/pattern-home/cluster-service-ca.crt" not in options


def test_e2e_script_does_not_start_cleanup(runner, monkeypatch):
    runner.locked = True
    monkeypatch.setattr(runner, "setup_files", lambda: None)
    monkeypatch.setattr(runner, "preflight", lambda: None)
    monkeypatch.setattr(runner, "build", lambda: None)
    monkeypatch.setattr(runner, "prepare_registry_pull", lambda: None)
    monkeypatch.setattr(runner, "install", lambda: None)
    monkeypatch.setattr(runner, "verify_deployment_smoke", lambda: None)
    monkeypatch.setattr(runner, "verify_guest_install", lambda: None)
    monkeypatch.setattr(runner, "live_behavior", lambda: None)
    monkeypatch.setattr(runner, "diagnostics", lambda: None)
    cleanup_calls = []
    lock_updates = []
    monkeypatch.setattr(runner, "cleanup", lambda: cleanup_calls.append(True))
    monkeypatch.setattr(runner, "update_lock_data", lambda updates: lock_updates.append(updates))
    assert runner.run() == 0
    assert cleanup_calls == []
    assert lock_updates == [{"state": "cleanup-required", "test-outcome": "success"}]
    assert runner.report["cleanup_verified"] is False
    assert runner.locked


def test_e2e_runs_guest_and_live_checks(runner, monkeypatch):
    stages = []
    monkeypatch.setattr(runner, "stage", lambda name, _action: stages.append(name))
    assert runner.run() == 0
    assert stages[-3:] == ["deployment-readiness-and-digest-checks",
                           "guest-installer", "live-behavior"]


def test_install_phase_keeps_cluster_ready_for_live_checks(runner, monkeypatch, tmp_path):
    install_runner = pattern_e2e.Runner(phase="install")
    install_runner.locked = True
    install_runner.home = tmp_path / "saw-ci-install"
    install_runner.home.mkdir()
    stages = []
    lock_updates = []

    for name in ("setup_files", "preflight", "build", "prepare_registry_pull",
                 "install", "verify_deployment_smoke", "verify_guest_install"):
        monkeypatch.setattr(install_runner, name, lambda: None)

    def stage(name, action):
        stages.append(name)
        action()

    monkeypatch.setattr(install_runner, "stage", stage)
    monkeypatch.setattr(install_runner, "update_lock_data",
                        lambda data: lock_updates.append(data))
    monkeypatch.setattr(install_runner, "diagnostics", lambda: None)

    assert install_runner.run() == 0
    assert "live-behavior" not in stages
    assert stages[-1] == "guest-installer"
    assert lock_updates == [{"state": "live-pending", "test-outcome": "live-pending"}]
    assert install_runner.home.is_dir()
    assert install_runner.report["installation_ready"] is True


def test_live_phase_runs_without_reinstalling(runner, monkeypatch, tmp_path):
    runner.phase = "live"
    runner.locked = True
    runner.home = tmp_path / "saw-ci-123"
    runner.home.mkdir()
    stages = []
    lock_updates = []
    monkeypatch.setattr(runner, "load_install_result", lambda: None)

    def stage(name, action):
        stages.append(name)
        action()

    monkeypatch.setattr(runner, "stage", stage)
    monkeypatch.setattr(runner, "live_behavior", lambda: None)
    monkeypatch.setattr(runner, "update_lock_data",
                        lambda data: lock_updates.append(data))

    assert runner.run() == 0
    assert stages == ["resume-installed-run", "live-behavior"]
    assert lock_updates == [{"state": "live-pending", "test-outcome": "success",
                             "live-outcome": "success"}]
    assert runner.home.is_dir()


def test_live_phase_restores_only_the_matching_install_run(runner, monkeypatch, tmp_path):
    private_home = tmp_path / "saw-ci-123"
    private_home.mkdir()
    (private_home / ".run-id").write_text("123\n")
    required_files = (
        ".kube/config", "cluster-ca.pem", "cluster-service-ca.crt",
        "ssh/sandbox-ssh", "ssh/sandbox-ssh.pub", "ciowner-password",
        "cisecond-password", "inference-key", "bin/virtctl",
    )
    for name in required_files:
        file = private_home / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("private test value")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    previous = {
        **runner.report,
        "installation_ready": True,
        "private_home": str(private_home),
        "stages": [{"name": name, "result": "passed"} for name in (
            "prepare-files", "cluster-preflight-and-lock", "build-and-record-digests",
            "prepare-registry-pull", "pattern-install",
            "deployment-readiness-and-digest-checks", "guest-installer")],
    }
    (runner.artifacts / "results.json").write_text(json.dumps(previous))
    lock = {"metadata": {"annotations": {
        "saw.redhat.com/repository": runner.repo,
        "saw.redhat.com/run-id": runner.run_id,
        "saw.redhat.com/sha": runner.sha,
        "saw.redhat.com/target-branch": runner.branch,
    }}, "data": {"state": "live-pending", "baseline-namespaces": "[]",
                 "build-attempted": "true", "install-attempted": "true"}}
    monkeypatch.setattr(runner, "verify_target_ref", lambda: None)
    monkeypatch.setattr(runner, "cluster_identity", lambda **_kwargs: None)
    monkeypatch.setattr(runner, "oc_json", lambda *_args: lock)

    runner.load_install_result()

    assert runner.locked is True
    assert runner.home == private_home
    assert runner.env["KUBECONFIG"] == str(private_home / ".kube/config")
    assert runner.report["phase"] == "live"


def test_guest_failure_names_the_failed_phase(runner, monkeypatch):
    monkeypatch.setattr(runner, "install_virtctl", lambda: None)
    monkeypatch.setattr(runner, "call", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps({
                            "install": {"phase": "Done"},
                            "apply": {"phase": "Failed"}})))
    monkeypatch.setattr(runner, "wait_for", lambda _label, predicate, **_kwargs:
                        predicate())
    with pytest.raises(pattern_e2e.E2EError, match="ciowner apply phase failed"):
        runner.verify_guest_install()


def test_guest_status_uses_user_namespace_despite_outer_make_value(runner, monkeypatch):
    runner.env["SAW_NS"] = "saw-"
    calls = []
    monkeypatch.setattr(runner, "install_virtctl", lambda: None)

    def fake_call(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "install": {"phase": "Done"},
            "apply": {"phase": "Done"}}))

    monkeypatch.setattr(runner, "call", fake_call)
    monkeypatch.setattr(runner, "wait_for", lambda _label, predicate, **_kwargs:
                        predicate())

    runner.verify_guest_install()

    assert [call[1]["env"]["SAW_NS"] for call in calls] == [
        "saw-ciowner", "saw-cisecond"]


def test_cleanup_removes_only_run_created_pattern_infrastructure(runner, monkeypatch):
    runner.baseline_namespaces = {"vp-gitops"}
    namespaces = {"vp-gitops", "patterns-operator"}
    deleted = []
    updates = []

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
    monkeypatch.setattr(runner, "stop_run_utility_containers", lambda: None)
    monkeypatch.setattr(runner, "update_lock_data", lambda data: updates.append(data))
    monkeypatch.setattr(runner, "release_lock", lambda: None)
    runner.cleanup()
    assert deleted == ["patterns-operator"]
    assert runner.report["cleanup_verified"] is True
    assert updates == [
        {"state": "cleanup-in-progress"},
        {"state": "cleanup-verified", "cleanup-verified": "true"},
    ]


def test_recovery_loads_only_the_requested_run_lock(monkeypatch, tmp_path):
    run_id = "123"
    sha = "b" * 40
    monkeypatch.setenv("CI_RECOVERY_RUN_ID", run_id)
    monkeypatch.setenv("GITHUB_REPOSITORY", "example/repo")
    monkeypatch.setenv("CI_ARTIFACT_DIR", str(tmp_path))
    runner = pattern_e2e.Runner(recovery=True)
    lock = {"metadata": {"annotations": {
        "saw.redhat.com/repository": "example/repo",
        "saw.redhat.com/run-id": run_id,
        "saw.redhat.com/sha": sha,
        "saw.redhat.com/run-url": "https://github.com/example/repo/actions/runs/123",
        "saw.redhat.com/target-branch": "codex/ci-deployment-validation",
    }}, "data": {
        "state": "cleanup-required",
        "baseline-namespaces": json.dumps(["default", "vp-gitops"]),
        "build-attempted": "true", "install-attempted": "true",
    }}
    monkeypatch.setattr(runner, "oc_json", lambda *_args: lock)

    runner.load_recovery_state()

    assert runner.run_id == run_id
    assert runner.sha == sha
    assert runner.branch == "codex/ci-deployment-validation"
    assert runner.baseline_namespaces == {"default", "vp-gitops"}
    assert runner.build_attempted is True
    assert runner.install_attempted is True
    assert runner.locked is True
    assert runner.env["SAW_CI_RUN_ID"] == run_id


def test_recovery_preserves_test_report_and_appends_cleanup_stage(monkeypatch, tmp_path):
    run_id = "123"
    sha = "b" * 40
    monkeypatch.setenv("CI_RECOVERY_RUN_ID", run_id)
    monkeypatch.setenv("GITHUB_REPOSITORY", "example/repo")
    monkeypatch.setenv("CI_ARTIFACT_DIR", str(tmp_path))
    results = {
        "source_sha": sha,
        "repository": "example/repo",
        "run_id": run_id,
        "started_at": "2026-10-25T08:00:00Z",
        "finished_at": "2026-10-25T09:00:00Z",
        "stages": [{"name": "live-behavior", "result": "passed"}],
        "cleanup_verified": False,
    }
    (tmp_path / "results.json").write_text(json.dumps(results), encoding="utf-8")
    runner = pattern_e2e.Runner(recovery=True)
    lock = {"metadata": {"annotations": {
        "saw.redhat.com/repository": "example/repo",
        "saw.redhat.com/run-id": run_id,
        "saw.redhat.com/sha": sha,
        "saw.redhat.com/run-url": "https://github.com/example/repo/actions/runs/123",
        "saw.redhat.com/target-branch": "codex/ci-deployment-validation",
    }}, "data": {
        "state": "cleanup-required",
        "baseline-namespaces": json.dumps(["default"]),
        "build-attempted": "true", "install-attempted": "true",
    }}
    monkeypatch.setattr(runner, "oc_json", lambda *_args: lock)

    runner.load_recovery_state()
    runner.stage("recovery-cleanup", lambda: None)

    assert runner.report["started_at"] == "2026-10-25T08:00:00Z"
    assert runner.report["test_finished_at"] == "2026-10-25T09:00:00Z"
    assert [stage["name"] for stage in runner.report["stages"]] == [
        "live-behavior", "recovery-cleanup"]


def test_recovery_prerequisite_failure_keeps_test_report(monkeypatch, tmp_path):
    monkeypatch.setenv("CI_RECOVERY_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_REPOSITORY", "example/repo")
    monkeypatch.setenv("CI_ARTIFACT_DIR", str(tmp_path))
    report_path = tmp_path / "results.json"
    original = '{"run_id":"123","stages":[{"name":"live-behavior"}]}\n'
    report_path.write_text(original, encoding="utf-8")
    runner = pattern_e2e.Runner(recovery=True)
    monkeypatch.setattr(runner, "setup_recovery_files", lambda: (_ for _ in ()).throw(
        pattern_e2e.E2EError("Podman is unavailable")))

    assert runner.recover_cleanup() == 1
    assert report_path.read_text(encoding="utf-8") == original


def test_recovery_refuses_a_different_run_id(runner, monkeypatch):
    monkeypatch.setenv("CI_RECOVERY_RUN_ID", "123")
    runner.recovery_run_id = "123"
    runner.repo = "example/repo"
    lock = {"metadata": {"annotations": {
        "saw.redhat.com/repository": "example/repo",
        "saw.redhat.com/run-id": "456",
        "saw.redhat.com/sha": "b" * 40,
    }}, "data": {}}
    monkeypatch.setattr(runner, "oc_json", lambda *_args: lock)
    with pytest.raises(pattern_e2e.E2EError, match="does not match"):
        runner.load_recovery_state()


def test_recovery_refuses_to_clean_without_saved_namespace_snapshot(
    runner, monkeypatch,
):
    runner.recovery_run_id = "123"
    runner.repo = "example/repo"
    lock = {"metadata": {"annotations": {
        "saw.redhat.com/repository": "example/repo",
        "saw.redhat.com/run-id": "123",
        "saw.redhat.com/sha": "b" * 40,
    }}, "data": {"state": "live-pending"}}
    monkeypatch.setattr(runner, "oc_json", lambda *_args: lock)
    with pytest.raises(pattern_e2e.E2EError, match="namespace snapshot"):
        runner.load_recovery_state()


def test_cleanup_failure_keeps_cluster_lock_for_recovery(runner, monkeypatch):
    runner.locked = True
    monkeypatch.setattr(runner, "setup_recovery_files", lambda: None)
    monkeypatch.setattr(runner, "cluster_identity", lambda **_kwargs: None)
    monkeypatch.setattr(runner, "load_recovery_state", lambda: None)
    monkeypatch.setattr(runner, "diagnostics", lambda: None)
    monkeypatch.setattr(runner, "stage", lambda _name, action: action())
    monkeypatch.setattr(runner, "cleanup", lambda: (_ for _ in ()).throw(
        pattern_e2e.E2EError("namespace remains")))
    required = []
    monkeypatch.setattr(runner, "mark_cleanup_required", lambda: required.append(True))

    assert runner.recover_cleanup() == 1
    assert required == [True]
    assert runner.report["cleanup_verified"] is False


def test_cleanup_script_uses_recovery_mode(monkeypatch):
    instances = []

    class FakeRunner:
        def __init__(self, *, recovery):
            instances.append(recovery)
            self.cancelled = False

        def recover_cleanup(self):
            return 7

    monkeypatch.setattr(pattern_e2e_cleanup, "Runner", FakeRunner)
    monkeypatch.setattr(pattern_e2e_cleanup.signal, "signal", lambda *_args: None)
    assert pattern_e2e_cleanup.main() == 7
    assert instances == [True]


def test_workflow_finish_retains_source_ref_until_cleanup_is_verified(
    monkeypatch, tmp_path,
):
    sha = "a" * 40
    branch = "ci/pattern-e2e/123-1"
    result_path = tmp_path / "results.json"
    result_path.write_text(json.dumps({"cleanup_verified": False}))
    for key, value in {
        "GITHUB_REPOSITORY": "example/repo", "CI_HEAD_SHA": sha,
        "CI_TARGET_BRANCH": branch, "CI_E2E_OUTCOME": "success",
        "CI_E2E_RESULTS_PATH": str(result_path),
        "CI_RUN_URL": "https://github.com/example/repo/actions/runs/123",
    }.items():
        monkeypatch.setenv(key, value)
    calls = []
    monkeypatch.setattr(e2e_control, "api", lambda method, path, payload=None:
                        calls.append((method, path, payload)) or {})

    e2e_control.finish()

    assert not any(method == "DELETE" for method, _, _ in calls)
    assert any(method == "POST" and path.endswith("/statuses/" + sha)
               and payload["state"] == "failure" for method, path, payload in calls)


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
        if path.endswith("/reviews?per_page=100&page=1"):
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


def test_later_review_page_can_revoke_an_older_approval(monkeypatch, tmp_path):
    sha = "a" * 40
    for key, value in {
        "GITHUB_REPOSITORY": "example/repo", "CI_PR_NUMBER": "42",
        "CI_HEAD_SHA": sha, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
        "CI_RUN_URL": "https://github.com/example/repo/actions/runs/123",
        "GITHUB_OUTPUT": str(tmp_path / "output"),
    }.items():
        monkeypatch.setenv(key, value)
    page_one = [
        {"state": "COMMENTED", "user": {"login": f"reviewer-{index}"}}
        for index in range(99)
    ]
    page_one.append({"state": "APPROVED", "commit_id": sha,
                     "user": {"login": "reviewer"}})
    calls = []

    def fake_api(method, path, payload=None):
        calls.append((method, path, payload))
        if path.endswith("/pulls/42"):
            return {"state": "open", "head": {"sha": sha,
                    "repo": {"full_name": "example/repo"}},
                    "merge_commit_sha": "b" * 40}
        if path.endswith("/reviews?per_page=100&page=1"):
            return page_one
        if path.endswith("/reviews?per_page=100&page=2"):
            return [{"state": "CHANGES_REQUESTED", "commit_id": sha,
                     "user": {"login": "reviewer"}}]
        return {"check_runs": []}

    monkeypatch.setattr(e2e_control, "api", fake_api)

    with pytest.raises(RuntimeError, match="no active approval"):
        e2e_control.prepare()

    assert any(path.endswith("/reviews?per_page=100&page=2")
               for _method, path, _payload in calls)


def test_verify_images_refuses_a_stale_credential_proxy(runner, monkeypatch):
    digest = "sha256:" + "a" * 64
    runner.report["image_digests"] = {name: digest for name in (
        "governance-interceptor", "saw-credential-proxy")}
    registry = f"image-registry.openshift-image-registry.svc:5000/{pattern_e2e.NAMESPACE}"
    def fake_oc_json(*args):
        image = (f"{registry}/governance-interceptor@{digest}" if args[2] == "governance-interceptor"
                 else f"{registry}/saw-credential-proxy:old")
        return {"spec": {"template": {"spec": {"containers": [{"image": image}]}}}}
    monkeypatch.setattr(runner, "oc_json", fake_oc_json)
    with pytest.raises(pattern_e2e.E2EError, match="credential proxy does not use the new build digest"):
        runner.verify_images()
