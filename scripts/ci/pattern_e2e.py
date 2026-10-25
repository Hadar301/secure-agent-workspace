#!/usr/bin/env python3
"""Run Pattern deployment and live E2E checks on one fresh OpenShift cluster."""

from __future__ import annotations

import base64
import io
import json
import os
import platform
import re
import secrets
import shutil
import signal
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
LOCK_NAME = "saw-pattern-e2e"
NAMESPACE = "openshell-agents"
REGISTRY_PULLER = "saw-ci-registry-puller"
REGISTRY_HOST = "image-registry.openshift-image-registry.svc.cluster.local:5000"
USERS = ("ciowner", "cisecond")
PATTERN_NAMESPACES = (
    "external-secrets", "external-secrets-operator", "openshift-cnv",
    "openshell-agents", "saw-keycloak", "vault", "vp-gitops",
    "patterns-operator", "saw-ciowner", "saw-cisecond",
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class E2EError(Exception):
    pass


class E2ECommandTimeout(E2EError):
    """A command in a readiness poll timed out and can be retried."""


class Runner:
    def __init__(self, *, recovery: bool = False) -> None:
        self.recovery = recovery
        if recovery:
            self.sha = ""
            self.run_id = ""
            self.run_url = ""
            self.repo = self.required("GITHUB_REPOSITORY")
            self.branch = ""
            self.recovery_run_id = self.required("CI_RECOVERY_RUN_ID")
            if not self.recovery_run_id.isdigit():
                raise E2EError("CI_RECOVERY_RUN_ID must be a numeric run ID")
        else:
            self.sha = self.required("CI_HEAD_SHA")
            if not SHA.fullmatch(self.sha):
                raise E2EError("CI_HEAD_SHA must be a full commit SHA")
            self.run_id = self.required("GITHUB_RUN_ID")
            self.run_url = self.required("CI_RUN_URL")
            self.repo = self.required("GITHUB_REPOSITORY")
            self.branch = self.required("CI_TARGET_BRANCH")
            self.recovery_run_id = ""
        self.lock_ns = os.environ.get("CI_LOCK_NAMESPACE", "saw-ci-lock")
        self.artifacts = Path(os.environ.get("CI_ARTIFACT_DIR", "pattern-e2e-results"))
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.report: dict[str, Any] = {
            "source_sha": self.sha, "repository": self.repo, "run_id": self.run_id,
            "run_url": self.run_url, "started_at": now(), "stages": [],
            "image_digests": {}, "cleanup_verified": False,
        }
        self.home: Path | None = None
        self.openshell_env: dict[str, str] | None = None
        self.env = dict(os.environ)
        for key in ("CI_KUBECONFIG_B64", "CI_CA_B64", "CI_INFERENCE_KEY"):
            self.env.pop(key, None)
        self.locked = False
        self.lock_namespace_created = False
        self.install_attempted = False
        self.build_attempted = False
        self.cancelled = False
        self.baseline_namespaces: set[str] = set()
        self.sensitive = [value for key, value in os.environ.items()
                          if key.startswith("CI_") and
                          any(term in key for term in ("KEY", "PASSWORD", "TOKEN", "B64")) and value]

    @staticmethod
    def required(key: str) -> str:
        value = os.environ.get(key, "")
        if not value:
            raise E2EError(f"{key} is required")
        return value

    def redact(self, text: str) -> str:
        for value in self.sensitive:
            text = text.replace(value, "[redacted]")
        return text

    def call(self, args: list[str], *, timeout: int = 120,
             input_text: str | None = None, allow_failure: bool = False,
             env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        command_env = env if env is not None else self.env
        if env is None and args[0] == "openshell" and self.openshell_env is not None:
            command_env = self.openshell_env
        try:
            completed = subprocess.run(
                args, cwd=ROOT, env=command_env, input=input_text,
                text=True, capture_output=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            partial_output = "\n".join(
                part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part
                for part in (exc.stdout, exc.stderr) if part
            )
            detail = self.redact(partial_output.strip()[-500:])
            command = " ".join(str(part) for part in args[:2])
            message = f"{command} timed out after {timeout}s"
            if detail:
                message = f"{message}: {detail}"
            raise E2ECommandTimeout(message) from exc
        except OSError as exc:
            raise E2EError(f"{args[0]} failed: OSError") from exc
        if completed.returncode and not allow_failure:
            output = "\n".join(part for part in (completed.stdout.strip()[-1400:],
                                                  completed.stderr.strip()[-500:]) if part)
            detail = self.redact(output)
            raise E2EError(f"{args[0]} {args[1] if len(args) > 1 else ''} "
                           f"failed ({completed.returncode}): {detail}")
        return completed

    def oc_json(self, *args: str) -> dict[str, Any]:
        output = self.call(["oc", *args, "-o", "json"]).stdout
        try:
            data = json.loads(output)
        except json.JSONDecodeError as exc:
            raise E2EError(f"oc {args[0]} returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise E2EError(f"oc {args[0]} returned no JSON object")
        return data

    def stage(self, name: str, action) -> None:
        print(f"{now()} {name}: started", flush=True)
        entry = {"name": name, "started_at": now(), "result": "failed"}
        self.report["stages"].append(entry)
        self.save_report()
        try:
            action()
        except Exception as exc:
            entry["error"] = self.redact(str(exc))
            raise
        else:
            entry["result"] = "passed"
        finally:
            entry["finished_at"] = now()
            self.save_report()
            print(f"{now()} {name}: {entry['result']}", flush=True)

    def save_report(self) -> None:
        path = self.artifacts / "results.json"
        path.write_text(json.dumps(self.report, indent=2) + "\n", encoding="utf-8")

    def setup_files(self) -> None:
        for name in ("oc", "helm", "podman", "uv", "openshell", "jq", "curl",
                     "openssl", "git", "make"):
            if shutil.which(name) is None:
                raise E2EError(f"required tool {name} is unavailable")
        self.verify_target_ref()
        # Check the container runtime before spending time on cluster builds.
        self.call(["podman", "info", "--format", "{{.Host.Arch}}"], timeout=30)
        bom = yaml.safe_load((ROOT / "charts/openshell-saw/values.yaml").read_text())
        api_version = bom["bom"]["spec"]["openshell"]["cli"]["version"].split("-", 1)[0]
        version = self.call(["openshell", "--version"]).stdout.strip()
        if not re.fullmatch(rf"openshell\s+{re.escape(api_version)}(?:[-+][^\s]+)?", version):
            raise E2EError("OpenShell CLI version does not match the installer BOM")
        if self.required("CI_PROVIDER") != "build":
            raise E2EError("CI_PROVIDER must be build for the CI profile")
        provider_profile = yaml.safe_load((ROOT / "charts/saw-bom/profiles/ci-nvidia/"
                                           "default/providers.yaml").read_text())
        expected_model = next(item["model"] for item in
                              provider_profile["spec"]["providers"]
                              if item.get("nemoclawProvider") == "build")
        if self.required("CI_MODEL") != expected_model:
            raise E2EError("CI_MODEL must match the CI profile model")
        secret_home = Path(tempfile.mkdtemp(prefix="saw-ci-", dir=os.environ.get("RUNNER_TEMP")))
        secret_home.chmod(0o700)
        self.home = secret_home
        self.env["HOME"] = str(secret_home)
        self.openshell_env = dict(self.env)
        self.openshell_env["XDG_CONFIG_HOME"] = str(secret_home / ".config")
        self.env["KUBECONFIG"] = str(secret_home / ".kube/config")
        self.env["SSH_KEY_PATH"] = str(secret_home / "ssh/sandbox-ssh")
        self.env["VALUES_SECRET"] = str(secret_home / "values-secret-secure-agent-workspace.yaml")
        self.env["TARGET_BRANCH"] = self.branch
        self.env["TARGET_ORIGIN"] = "origin"
        self.env["BUILD_NS"] = NAMESPACE
        self.env["NS"] = NAMESPACE
        self.env["PUSH_IMAGE_REPO"] = ""
        kubeconfig = base64.b64decode(self.required("CI_KUBECONFIG_B64"), validate=True)
        ca = base64.b64decode(self.required("CI_CA_B64"), validate=True)
        self.private_file(".kube/config", kubeconfig)
        self.private_file("cluster-ca.pem", ca)
        service_ca = self.oc_json("get", "configmap", "openshift-service-ca.crt",
                                  "-n", "openshift-service-ca")["data"]["service-ca.crt"]
        if "BEGIN CERTIFICATE" not in service_ca or "PRIVATE KEY" in service_ca:
            raise E2EError("cluster registry service CA is invalid")
        self.private_file("cluster-service-ca.crt", service_ca.encode())
        # Route TLS uses this CA. Keep the system trust store for public hosts.
        self.env["OIDC_CA_BUNDLE"] = str(secret_home / "cluster-ca.pem")
        self.env["TEST_SECOND_TOKEN_DIR"] = str(secret_home / "second-oidc")
        self.env["TEST_ACTIVE_SAW_NAME"] = USERS[0]
        self.env["TEST_ACTIVE_SAW_NS"] = f"saw-{USERS[0]}"
        self.private_file("inference-key", self.required("CI_INFERENCE_KEY").encode())
        for user in USERS:
            password = "aA9!" + secrets.token_urlsafe(32)
            self.sensitive.append(password)
            self.private_file(f"{user}-password", password.encode())
        # The Pattern utility container reads this file from HOME. It holds
        # paths to private files; no secret value enters the repository.
        values = {
            "version": "2.0", "backingStore": "vault",
            "secrets": [
                {"name": "ssh", "fields": [
                    {"name": "private_key", "path": str(secret_home / "ssh/sandbox-ssh")},
                    {"name": "public_key", "path": str(secret_home / "ssh/sandbox-ssh.pub")}]},
                {"name": "inference", "fields": [
                    {"name": "provider", "value": self.required("CI_PROVIDER")},
                    {"name": "model", "value": self.required("CI_MODEL")},
                    {"name": "api_key", "path": str(secret_home / "inference-key")}]},
                {"name": "keycloak-users", "fields": [
                    {"name": user, "path": str(secret_home / f"{user}-password")}
                    for user in USERS]},
            ],
        }
        self.private_file("values-secret-secure-agent-workspace.yaml",
                          yaml.safe_dump(values, sort_keys=False).encode())
        self.call(["make", "ssh-key-generate"], timeout=30)

    def private_file(self, relative: str, content: bytes) -> None:
        if self.home is None:
            raise E2EError("private HOME is not ready")
        target = self.home / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes(content)
        target.chmod(0o600)

    def cluster_identity(self, *, create_lock_namespace: bool = True) -> None:
        expected_api = self.required("CI_CLUSTER_API")
        expected_uid = self.required("CI_CLUSTER_UID")
        actual_api = self.call(["oc", "whoami", "--show-server"]).stdout.strip()
        if actual_api != expected_api:
            raise E2EError("cluster API does not match CI_CLUSTER_API")
        actual_uid = self.oc_json("get", "namespace", "kube-system")["metadata"]["uid"]
        if actual_uid != expected_uid:
            raise E2EError("cluster UID does not match CI_CLUSTER_UID")
        existing = self.call(["oc", "get", "namespace", self.lock_ns],
                             allow_failure=True)
        if existing.returncode:
            if not self.is_not_found(existing.stderr):
                raise E2EError("cannot inspect CI lock namespace")
            if not create_lock_namespace:
                raise E2EError("CI lock namespace is missing; recovery stopped")
            self.lock_namespace_created = True
            namespace_doc = {"apiVersion": "v1", "kind": "Namespace",
                             "metadata": {"name": self.lock_ns,
                                          "labels": {"openshell.pattern/ci-lock": "true"}}}
            self.call(["oc", "apply", "-f", "-"], input_text=json.dumps(namespace_doc))
        else:
            self.lock_namespace_created = False
        namespace = self.oc_json("get", "namespace", self.lock_ns)
        if namespace["metadata"]["name"] != self.lock_ns:
            raise E2EError("CI lock namespace is unavailable")
        labels = namespace.get("metadata", {}).get("labels", {})
        if labels.get("openshell.pattern/ci-lock") != "true":
            raise E2EError("CI lock namespace is not marked for Pattern E2E")

    def acquire_lock(self) -> None:
        document = {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": LOCK_NAME, "namespace": self.lock_ns,
                         "annotations": {
                             "saw.redhat.com/repository": self.repo,
                             "saw.redhat.com/pr": self.required("CI_PR_NUMBER"),
                             "saw.redhat.com/sha": self.sha,
                             "saw.redhat.com/run-id": self.run_id,
                             "saw.redhat.com/run-url": self.run_url,
                             "saw.redhat.com/target-branch": self.branch,
                             "saw.redhat.com/created-at": now()}},
            "data": {"state": "active", "baseline-namespaces": "",
                     "build-attempted": "false", "install-attempted": "false",
                     "cleanup-verified": "false",
                     "lock-namespace-created": str(self.lock_namespace_created).lower()},
        }
        created = self.call(["oc", "create", "-f", "-"],
                            input_text=json.dumps(document), allow_failure=True)
        if created.returncode:
            existing = self.call(["oc", "get", "configmap", LOCK_NAME, "-n", self.lock_ns,
                                  "-o", "json"], allow_failure=True)
            if existing.returncode:
                raise E2EError("cannot acquire or inspect cluster lock")
            lock = json.loads(existing.stdout)
            run_url = lock.get("metadata", {}).get("annotations", {}).get(
                "saw.redhat.com/run-url", "unknown run")
            raise E2EError(f"cluster is busy: {run_url}")
        self.locked = True

    def load_recovery_state(self) -> None:
        lock = self.oc_json("get", "configmap", LOCK_NAME, "-n", self.lock_ns)
        metadata = lock.get("metadata") or {}
        annotations = metadata.get("annotations") or {}
        data = lock.get("data") or {}
        owner_id = annotations.get("saw.redhat.com/run-id", "")
        if owner_id != self.recovery_run_id:
            raise E2EError("CI_RECOVERY_RUN_ID does not match the active cluster lock")
        if annotations.get("saw.redhat.com/repository") != self.repo:
            raise E2EError("cluster lock belongs to a different repository")
        owner_sha = annotations.get("saw.redhat.com/sha", "")
        if not SHA.fullmatch(owner_sha):
            raise E2EError("cluster lock has no valid source SHA; recovery stopped")
        if data.get("state") not in {
                "active", "cleanup-in-progress", "cleanup-required", "cleanup-verified"}:
            raise E2EError("cluster lock has an unknown state; recovery stopped")
        try:
            baseline = json.loads(data.get("baseline-namespaces", ""))
        except json.JSONDecodeError as exc:
            raise E2EError("cluster lock has no valid namespace snapshot; recovery stopped") from exc
        if (not isinstance(baseline, list) or
                any(not isinstance(item, str) for item in baseline)):
            raise E2EError("cluster lock has no valid namespace snapshot; recovery stopped")
        self.sha = owner_sha
        self.run_id = owner_id
        self.run_url = annotations.get("saw.redhat.com/run-url", "unknown run")
        self.branch = annotations.get("saw.redhat.com/target-branch", "")
        self.env["TARGET_BRANCH"] = self.branch
        self.baseline_namespaces = set(baseline)
        self.build_attempted = data.get("build-attempted") == "true"
        self.install_attempted = data.get("install-attempted") == "true"
        if self.install_attempted and not self.valid_git_branch(self.branch):
            raise E2EError("cluster lock has no valid source branch; recovery stopped")
        self.lock_namespace_created = data.get("lock-namespace-created") == "true"
        self.locked = True
        self.report.update({
            "source_sha": self.sha,
            "repository": self.repo,
            "run_id": self.run_id,
            "run_url": self.run_url,
            "recovery": True,
            "recovery_started_at": now(),
        })
        report_path = self.artifacts / "results.json"
        if report_path.is_file():
            try:
                previous = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self.report["previous_report_error"] = "could not read the test result report"
            else:
                if (isinstance(previous, dict) and previous.get("source_sha") == self.sha and
                        previous.get("run_id") == self.run_id and
                        previous.get("repository") == self.repo):
                    if previous.get("finished_at") and not previous.get("test_finished_at"):
                        previous["test_finished_at"] = previous["finished_at"]
                    previous.setdefault("stages", [])
                    previous["recovery"] = True
                    previous["recovery_started_at"] = self.report["recovery_started_at"]
                    self.report = previous
                else:
                    self.report["previous_report_error"] = "test result report owner did not match"

    def valid_git_branch(self, branch: str) -> bool:
        if not branch:
            return False
        response = self.call(["git", "check-ref-format", "--branch", branch],
                             timeout=10, allow_failure=True)
        return response.returncode == 0

    def verify_target_ref(self) -> None:
        if not self.valid_git_branch(self.branch):
            raise E2EError("CI_TARGET_BRANCH is not a valid Git branch")
        response = self.call(["git", "ls-remote", "--heads", "origin",
                              f"refs/heads/{self.branch}"], timeout=30)
        matches = [line.split() for line in response.stdout.splitlines() if line.strip()]
        matches = [parts for parts in matches
                   if len(parts) == 2 and parts[1] == f"refs/heads/{self.branch}"]
        if len(matches) != 1:
            raise E2EError("CI_TARGET_BRANCH was not found on origin")
        if matches[0][0] != self.sha:
            raise E2EError("CI_TARGET_BRANCH does not point to CI_HEAD_SHA; "
                           "use a run-specific ref pinned to the tested commit")

    def setup_recovery_files(self) -> None:
        for name in ("oc", "helm", "podman", "make"):
            if shutil.which(name) is None:
                raise E2EError(f"required tool {name} is unavailable")
        secret_home = Path(tempfile.mkdtemp(prefix="saw-ci-cleanup-",
                                            dir=os.environ.get("RUNNER_TEMP")))
        secret_home.chmod(0o700)
        self.home = secret_home
        self.env["HOME"] = str(secret_home)
        self.env["KUBECONFIG"] = str(secret_home / ".kube/config")
        self.env["TARGET_BRANCH"] = self.branch
        self.env["TARGET_ORIGIN"] = "origin"
        self.env["BUILD_NS"] = NAMESPACE
        self.env["NS"] = NAMESPACE
        kubeconfig = base64.b64decode(self.required("CI_KUBECONFIG_B64"), validate=True)
        self.private_file(".kube/config", kubeconfig)
        self.call(["podman", "info", "--format", "{{.Host.Arch}}"], timeout=30)

    def mark_cleanup_required(self) -> None:
        if self.locked:
            self.update_lock_data({"state": "cleanup-required"})

    def update_lock_data(self, updates: dict[str, str]) -> None:
        lock = self.oc_json("get", "configmap", LOCK_NAME, "-n", self.lock_ns)
        annotations = lock.get("metadata", {}).get("annotations", {})
        if (annotations.get("saw.redhat.com/run-id") != self.run_id or
                annotations.get("saw.redhat.com/sha") != self.sha):
            raise E2EError("cluster lock owner changed; refusing to update it")
        data = lock.get("data") or {}
        data.update(updates)
        lock["data"] = data
        self.call(["oc", "replace", "-f", "-"], input_text=json.dumps(lock))

    def release_lock(self) -> None:
        lock = self.oc_json("get", "configmap", LOCK_NAME, "-n", self.lock_ns)
        annotations = lock.get("metadata", {}).get("annotations", {})
        if (annotations.get("saw.redhat.com/run-id") != self.run_id or
                annotations.get("saw.redhat.com/sha") != self.sha):
            raise E2EError("cluster lock owner changed; manual recovery is required")
        self.call(["oc", "delete", "configmap", LOCK_NAME, "-n", self.lock_ns,
                   "--wait=true"], timeout=90)
        if self.lock_namespace_created:
            self.call(["oc", "delete", "namespace", self.lock_ns, "--wait=true",
                       "--timeout=20m"], timeout=1300)
        self.locked = False

    def preflight(self) -> None:
        self.cluster_identity()
        self.acquire_lock()
        self.baseline_namespaces = {
            item["metadata"]["name"] for item in self.oc_json("get", "namespaces")["items"]
        }
        self.update_lock_data({
            "baseline-namespaces": json.dumps(sorted(self.baseline_namespaces)),
        })
        # This run requires a fresh cluster. Do not remove existing resources.
        resources = (
            ("patterns.gitops.hybrid-cloud-patterns.io", None),
            ("virtualmachines.kubevirt.io", None),
            ("builds.build.openshift.io", None),
        )
        for kind, namespace in resources:
            command = ["oc", "get", kind, "-A", "-o", "json"]
            if namespace:
                command[3:3] = ["-n", namespace]
            output = self.call(command, allow_failure=True)
            if output.returncode:
                # A missing CRD is valid on a fresh cluster. An access error is not.
                if "the server doesn't have a resource type" in output.stderr:
                    continue
                raise E2EError(f"cannot inspect existing {kind}: "
                               + self.redact(output.stderr.strip())[-300:])
            if json.loads(output.stdout).get("items"):
                raise E2EError(f"fresh cluster preflight found existing {kind}")
        for namespace in (NAMESPACE, "saw-keycloak", *[f"saw-{u}" for u in USERS]):
            if namespace in self.baseline_namespaces:
                raise E2EError(f"fresh cluster preflight found namespace {namespace}")
        self.check_cnv_webhook()
        storage = self.oc_json("get", "storageclass")
        if not any((item.get("metadata", {}).get("annotations") or {}).get(
                "storageclass.kubernetes.io/is-default-class") == "true"
                for item in storage.get("items", [])):
            raise E2EError("no default StorageClass is available")
        nodes = self.oc_json("get", "nodes")
        if not any(self.node_has_capacity(item) for item in nodes.get("items", [])):
            raise E2EError("no Ready node has at least 4 CPU and 8 GiB memory")

    def check_cnv_webhook(self) -> None:
        crd = self.call(["oc", "get", "crd", "hyperconvergeds.hco.kubevirt.io",
                         "-o", "json"], allow_failure=True)
        if crd.returncode:
            if self.is_not_found(crd.stderr):
                return
            raise E2EError("cannot inspect CNV CRD: "
                           + self.redact(crd.stderr.strip())[-300:])
        document = json.loads(crd.stdout)
        service = (document.get("spec", {}).get("conversion", {}).get("webhook", {})
                   .get("clientConfig", {}).get("service", {}))
        namespace = service.get("namespace", "openshift-cnv")
        namespace_result = self.call(["oc", "get", "namespace", namespace, "-o", "name"],
                                     allow_failure=True)
        if namespace_result.returncode:
            if not self.is_not_found(namespace_result.stderr):
                raise E2EError("cannot inspect CNV namespace: "
                               + self.redact(namespace_result.stderr.strip())[-300:])
            raise E2EError(f"stale CNV CRD: namespace {namespace} is missing")
        if document.get("spec", {}).get("conversion", {}).get("strategy") == "Webhook":
            name = service.get("name")
            if not name:
                raise E2EError("CNV CRD has no conversion webhook service")
            result = self.call(["oc", "get", "service", name, "-n", namespace,
                                "-o", "name"], allow_failure=True)
            if result.returncode:
                if not self.is_not_found(result.stderr):
                    raise E2EError("cannot inspect CNV webhook service: "
                                   + self.redact(result.stderr.strip())[-300:])
                raise E2EError(f"CNV conversion webhook service {namespace}/{name} "
                               "is missing")

    @staticmethod
    def is_not_found(message: str) -> bool:
        lowered = message.lower()
        return "not found" in lowered or "notfound" in lowered

    @staticmethod
    def node_has_capacity(node: dict[str, Any]) -> bool:
        if node.get("spec", {}).get("unschedulable"):
            return False
        status = node.get("status", {})
        ready = any(condition.get("type") == "Ready" and condition.get("status") == "True"
                    for condition in status.get("conditions", []))
        alloc = status.get("allocatable") or {}
        cpu = str(alloc.get("cpu", "0"))
        memory = str(alloc.get("memory", "0"))
        cores = float(cpu[:-1]) / 1000 if cpu.endswith("m") else float(cpu)
        if memory.endswith("Ki"):
            gib = float(memory[:-2]) / (1024 * 1024)
        elif memory.endswith("Mi"):
            gib = float(memory[:-2]) / 1024
        elif memory.endswith("Gi"):
            gib = float(memory[:-2])
        else:
            gib = float(memory) / (1024 ** 3)
        return ready and cores >= 4 and gib >= 8

    def build(self) -> None:
        self.build_attempted = True
        self.update_lock_data({"build-attempted": "true"})
        for target in ("sandbox-build", "cli-build", "gateway-build-podman",
                       "governance-interceptor-build"):
            print(f"{now()} build {target}", flush=True)
            self.call(["make", target], timeout=7200)
        names = ("nemoclaw-discovery-runtime", "nemoclaw-sandbox", "nemoclaw-cli",
                 "openshell-gateway", "governance-interceptor")
        for name in names:
            builds = self.oc_json("get", "builds", "-n", NAMESPACE,
                                  "-l", f"buildconfig={name}")
            entries = builds.get("items") or []
            if not entries:
                raise E2EError(f"{name} has no build")
            latest = sorted(entries, key=lambda b: b["metadata"]["creationTimestamp"])[-1]
            build_name = latest["metadata"]["name"]
            terminal = {"Complete", "Failed", "Cancelled", "Error"}
            if latest.get("status", {}).get("phase") not in terminal:
                self.wait_for(
                    f"{name} build terminal phase",
                    lambda: self.oc_json("get", "build", build_name, "-n", NAMESPACE)
                    .get("status", {}).get("phase") in terminal,
                    seconds=7200,
                )
                latest = self.oc_json("get", "build", build_name, "-n", NAMESPACE)
            if latest.get("status", {}).get("phase") != "Complete":
                phase = latest.get("status", {}).get("phase", "unknown")
                raise E2EError(f"{name} build finished in {phase}")
            digest = latest.get("status", {}).get("output", {}).get("to", {}).get("imageDigest", "")
            if not DIGEST.fullmatch(digest):
                raise E2EError(f"{name} build has no output digest")
            self.report["image_digests"][name] = digest
        self.save_report()

    def topology(self) -> dict[str, Any]:
        # The established topology helper checks the API Service and ready
        # EndpointSlice backends. It prints only public network data.
        output = self.call(["uv", "run", "--locked", "scripts/network-topology.py",
                            "print-json"], timeout=60).stdout
        return json.loads(output)

    def prepare_registry_pull(self) -> None:
        """Give the VMs a short-lived token for the built images only."""
        if self.home is None:
            raise E2EError("private HOME is not ready")
        self.call(["oc", "create", "serviceaccount", REGISTRY_PULLER, "-n", NAMESPACE])
        self.call(["oc", "adm", "policy", "add-role-to-user", "registry-viewer",
                   "-z", REGISTRY_PULLER, "-n", NAMESPACE])
        token = self.call(["oc", "create", "token", REGISTRY_PULLER, "-n", NAMESPACE,
                           "--duration=4h"]).stdout.strip()
        if not token or any(char.isspace() for char in token):
            raise E2EError("registry pull service account returned no valid token")
        self.sensitive.append(token)
        self.private_file("registry-pull-token", token.encode())
        values_path = self.home / "values-secret-secure-agent-workspace.yaml"
        values = yaml.safe_load(values_path.read_text(encoding="utf-8"))
        values["secrets"].append({"name": "registry-pull", "fields": [
            {"name": "token", "path": str(self.home / "registry-pull-token")}]})
        self.private_file(values_path.name, yaml.safe_dump(values, sort_keys=False).encode())

    def install_options(self, topology: dict[str, Any]) -> str:
        if self.home is None:
            raise E2EError("private HOME is not ready")
        digests = self.report["image_digests"]
        registry = f"image-registry.openshift-image-registry.svc:5000/{NAMESPACE}"
        guest_registry = f"{REGISTRY_HOST}/{NAMESPACE}"
        try:
            registry_ca = base64.b64encode(
                (self.home / "cluster-service-ca.crt").read_bytes()).decode("ascii")
        except OSError as exc:
            raise E2EError("cluster registry CA is unavailable") from exc
        parameters: list[tuple[str, str]] = [
            ("global.ci.governanceImage", f"{registry}/governance-interceptor@{digests['governance-interceptor']}"),
            ("defaults.imageOverrides.cuda-sandbox", f"{guest_registry}/nemoclaw-sandbox@{digests['nemoclaw-sandbox']}"),
            ("defaults.openshellSaw.bom.spec.nemoclaw.cliImage",
             f"{guest_registry}/nemoclaw-cli@{digests['nemoclaw-cli']}"),
            ("defaults.openshellSaw.source.registryURL",
             f"docker://{registry}/openshell-gateway@{digests['openshell-gateway']}"),
            ("defaults.openshellSaw.registry.host", REGISTRY_HOST),
            ("defaults.openshellSaw.registry.caBundleBase64", registry_ca),
            ("defaults.openshellSaw.registry.authSecret", "registry-pull"),
            ("defaults.openshellSaw.networkPolicy.enabled", "true"),
            ("defaults.openshellSaw.cleanupApi.serviceIP", topology["cleanupApi"]["serviceIP"]),
        ]
        for key in ("clusterNetworkCIDRs", "serviceNetworkCIDRs"):
            for index, cidr in enumerate(topology["networkPolicy"][key]):
                parameters.append((f"defaults.openshellSaw.networkPolicy.{key}[{index}]", cidr))
        for index, endpoint in enumerate(topology["cleanupApi"]["endpoints"]):
            parameters.extend((
                (f"defaults.openshellSaw.cleanupApi.endpoints[{index}].ip", endpoint["ip"]),
                (f"defaults.openshellSaw.cleanupApi.endpoints[{index}].port",
                 str(endpoint["port"])),
            ))
        # These arguments contain public network data, image digests, and the
        # public service CA in base64 so no multiline value enters the Pattern.
        # The Pattern install chart stores them in spec.extraParameters.
        options = ["--set", "global.extraValueFiles[0]=/values-ci.yaml"]
        for index, (name, value) in enumerate(parameters):
            if not re.fullmatch(r"[A-Za-z0-9./:@_+=\[\]-]+", value):
                raise E2EError(f"invalid runtime override for {name}")
            options.extend(("--set-string", f"main.extraParameters[{index}].name={name}"))
            options.extend(("--set-string", f"main.extraParameters[{index}].value={value}"))
        return " ".join(options)

    def quote_pattern_api_ports(self, topology: dict[str, Any]) -> bool:
        response = self.call(["oc", "get", "pattern", "secure-agent-workspace",
                              "-n", "patterns-operator", "-o", "json"],
                             allow_failure=True)
        if response.returncode:
            missing = ("NotFound", "not found", "doesn't have a resource type")
            if any(marker in response.stderr for marker in missing):
                return False
            raise E2EError("cannot read Pattern resource while installing")
        pattern = json.loads(response.stdout)
        parameters = pattern.get("spec", {}).get("extraParameters") or []
        patches = []
        for index, endpoint in enumerate(topology["cleanupApi"]["endpoints"]):
            name = f"defaults.openshellSaw.cleanupApi.endpoints[{index}].port"
            matches = [(position, item) for position, item in enumerate(parameters)
                       if item.get("name") == name]
            if len(matches) != 1:
                raise E2EError(f"Pattern resource has no unique {name} parameter")
            position, item = matches[0]
            plain = str(endpoint["port"])
            quoted = f'"{plain}"'
            if item.get("value") == quoted:
                continue
            if item.get("value") != plain:
                raise E2EError(f"Pattern resource has unexpected {name} value")
            path = f"/spec/extraParameters/{position}/value"
            patches.extend(({"op": "test", "path": path, "value": plain},
                            {"op": "replace", "path": path, "value": quoted}))
        if patches:
            # The Pattern operator renders plain numeric values as
            # %!s(float64=6443) in child Argo CD Helm parameters.
            try:
                response = self.call(["oc", "patch", "pattern", "secure-agent-workspace",
                                      "-n", "patterns-operator", "--type=json", "-p",
                                      json.dumps(patches)], allow_failure=True)
            except E2ECommandTimeout:
                return False
            if response.returncode:
                webhook_unavailable = (
                    "failed calling webhook" in response.stderr and
                    "no endpoints available for service" in response.stderr
                )
                if webhook_unavailable:
                    return False
                raise E2EError("cannot patch Pattern API ports")
        return True

    def install(self) -> None:
        topology = self.topology()
        self.env["EXTRA_HELM_OPTS"] = self.install_options(topology)
        self.install_attempted = True
        self.update_lock_data({"install-attempted": "true"})
        ports_quoted = False
        with ThreadPoolExecutor(max_workers=1) as pool:
            install = pool.submit(self.call, ["./pattern.sh", "make", "install"],
                                  timeout=7200)
            while not install.done():
                if self.quote_pattern_api_ports(topology):
                    ports_quoted = True
                    break
                time.sleep(10)
            install.result()
        if not ports_quoted:
            self.wait_for(
                "Pattern API ports to be quoted",
                lambda: self.quote_pattern_api_ports(topology),
                seconds=600,
                interval=10,
            )

    def wait_for(self, label: str, predicate, *, seconds: int, interval: int = 20) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except E2ECommandTimeout:
                pass
            time.sleep(interval)
        raise E2EError(f"timed out waiting for {label}")

    def check_argo(self) -> None:
        def ready() -> bool:
            response = self.call(["oc", "get", "applications.argoproj.io", "-n", "vp-gitops",
                                  "-o", "json"], allow_failure=True)
            if response.returncode:
                return False
            items = json.loads(response.stdout).get("items") or []
            selected = [item for item in items if self.repo.split("/", 1)[-1] in
                        json.dumps(item.get("spec", {}).get("source", {})) +
                        json.dumps(item.get("spec", {}).get("sources", []))]
            if len(selected) < 6:
                return False
            selected_revisions: list[str] = []
            all_healthy_at_other_revision = True
            for item in selected:
                status = item.get("status") or {}
                sync = status.get("sync") or {}
                revisions = [sync.get("revision")]
                revisions.extend(sync.get("revisions") or [])
                revisions = [revision for revision in revisions if revision]
                selected_revisions.extend(revisions)
                if (not revisions or self.sha in revisions or
                        sync.get("status") not in {"Synced", "OutOfSync"} or
                        status.get("health", {}).get("status") != "Healthy"):
                    all_healthy_at_other_revision = False
            if all_healthy_at_other_revision:
                observed = ", ".join(sorted(set(selected_revisions)))
                raise E2EError("Argo applications are Healthy at revision(s) "
                               f"{observed}, not tested SHA {self.sha}")
            applications = {item.get("metadata", {}).get("name"): item for item in items}
            return all(self.application_ready(item, applications) for item in selected)
        self.wait_for("Argo applications at the tested SHA", ready, seconds=5400)

    def application_ready(self, item: dict[str, Any],
                          applications: dict[str, dict[str, Any]]) -> bool:
        status = item.get("status") or {}
        sync = status.get("sync") or {}
        revisions = [sync.get("revision")]
        revisions.extend(sync.get("revisions") or [])
        if self.sha not in revisions or status.get("health", {}).get("status") != "Healthy":
            return False
        if sync.get("status") == "Synced":
            return True

        # The saw-users app owns child Application resources. Argo can keep
        # this parent OutOfSync while those children reconcile their own
        # specs. Accept that state only when every drifted resource is a child
        # Application and each child is healthy and synced at this SHA.
        resources = status.get("resources") or []
        drifted = [resource for resource in resources if resource.get("status") == "OutOfSync"]
        if not drifted or any(resource.get("kind") != "Application" for resource in drifted):
            return False
        for resource in drifted:
            child = applications.get(resource.get("name"))
            if child is None:
                return False
            child_status = child.get("status") or {}
            child_sync = child_status.get("sync") or {}
            child_revisions = [child_sync.get("revision")]
            child_revisions.extend(child_sync.get("revisions") or [])
            if (self.sha not in child_revisions or child_sync.get("status") != "Synced" or
                    child_status.get("health", {}).get("status") != "Healthy"):
                return False
        return True

    def verify_deployment_smoke(self) -> None:
        self.check_argo()
        for user in USERS:
            namespace = f"saw-{user}"
            def vm_ready() -> bool:
                response = self.call(["oc", "get", "vm", user, "-n", namespace,
                                      "-o", "json"], allow_failure=True)
                if response.returncode:
                    return False
                vm = json.loads(response.stdout)
                return vm.get("status", {}).get("printableStatus") == "Running"
            self.wait_for(f"{user} VM", vm_ready, seconds=3600)
        self.verify_images()

    def verify_guest_install(self) -> None:
        self.install_virtctl()
        for user in USERS:
            # The in-guest status check is an existing Make interface.
            def installer_ready() -> bool:
                output = self.call(["make", "saw-status", f"OPENSHELL_SAW_NAME={user}"],
                                   timeout=90, allow_failure=True)
                if output.returncode:
                    return False
                try:
                    status = json.loads(output.stdout)
                except json.JSONDecodeError:
                    return False
                phases = (status.get("install", {}).get("phase"),
                          status.get("apply", {}).get("phase"))
                for step, phase in zip(("install", "apply"), phases):
                    if phase == "Failed":
                        raise E2EError(f"{user} {step} phase failed")
                return phases == ("Done", "Done")
            self.wait_for(f"{user} installer phases", installer_ready, seconds=3600)

    def cluster_tls_context(self) -> ssl.SSLContext:
        if self.home is None:
            raise E2EError("private HOME is not ready")
        context = ssl.create_default_context()
        context.load_verify_locations(cafile=str(self.home / "cluster-ca.pem"))
        return context

    def install_virtctl(self) -> None:
        if self.home is None:
            raise E2EError("private HOME is not ready")
        system, architecture, archive_format = self.virtctl_download_target()
        def download_link() -> str | None:
            result = self.call(["oc", "get", "consoleclidownloads.console.openshift.io",
                                "-o", "json"], allow_failure=True)
            if result.returncode:
                return None
            for item in json.loads(result.stdout).get("items") or []:
                for link in item.get("spec", {}).get("links") or []:
                    label = str(link.get("text", "")).lower()
                    if ("virtctl" in label and system in label and architecture in label):
                        return link.get("href")
            return None
        self.wait_for("virtctl client download", lambda: bool(download_link()), seconds=2400)
        url = download_link()
        if not url or not url.startswith("https://"):
            raise E2EError("virtctl download URL is invalid")
        context = self.cluster_tls_context()
        with urllib.request.urlopen(url, context=context, timeout=60) as response:
            payload = response.read(100_000_001)
        if len(payload) > 100_000_000:
            raise E2EError("virtctl download exceeds 100 MB")
        if archive_format == "tar.gz":
            if not payload.startswith(b"\x1f\x8b"):
                raise E2EError("virtctl download is not a gzip archive")
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
                members = [member for member in archive.getmembers()
                           if member.isfile() and Path(member.name).name == "virtctl"]
                if len(members) != 1:
                    raise E2EError("virtctl archive has no unique binary")
                source = archive.extractfile(members[0])
                if source is None:
                    raise E2EError("virtctl archive cannot be read")
                payload = source.read()
        else:
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    members = [member for member in archive.infolist()
                               if not member.is_dir() and Path(member.filename).name == "virtctl"]
                    if len(members) != 1:
                        raise E2EError("virtctl archive has no unique binary")
                    payload = archive.read(members[0])
            except zipfile.BadZipFile as exc:
                raise E2EError("virtctl download is not a ZIP archive") from exc
        if system == "linux" and not payload.startswith(b"\x7fELF"):
            raise E2EError("virtctl download is not a Linux binary")
        if system == "mac" and payload[:4] not in {
                b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
            raise E2EError("virtctl download is not a Mac binary")
        binary = self.home / "bin/virtctl"
        binary.parent.mkdir(mode=0o700, exist_ok=True)
        binary.write_bytes(payload)
        binary.chmod(0o700)
        self.env["PATH"] = str(binary.parent) + os.pathsep + self.env["PATH"]
        self.call(["virtctl", "version", "--client"], timeout=20)

    @staticmethod
    def virtctl_download_target() -> tuple[str, str, str]:
        system = {"Linux": "linux", "Darwin": "mac"}.get(platform.system())
        architecture = {
            "x86_64": "x86_64", "amd64": "x86_64",
            "arm64": "arm 64", "aarch64": "arm 64", "s390x": "ibm z",
        }.get(platform.machine().lower())
        if system is None or architecture is None:
            raise E2EError("virtctl download is not available for this platform")
        return system, architecture, "tar.gz" if system == "linux" else "zip"

    def verify_images(self) -> None:
        registry = f"image-registry.openshift-image-registry.svc:5000/{NAMESPACE}"
        guest_registry = f"{REGISTRY_HOST}/{NAMESPACE}"
        digests = self.report["image_digests"]
        deployment = self.oc_json("get", "deployment", "governance-interceptor",
                                  "-n", NAMESPACE)
        actual = deployment["spec"]["template"]["spec"]["containers"][0]["image"]
        if actual != f"{registry}/governance-interceptor@{digests['governance-interceptor']}":
            raise E2EError("governance deployment does not use the new build digest")
        for user in USERS:
            namespace = f"saw-{user}"
            config = self.oc_json("get", "configmap", f"{user}-installer", "-n", namespace)
            bom = yaml.safe_load(config["data"]["installer-bom.yaml"])
            cli_image = bom["spec"]["nemoclaw"]["cliImage"]
            if cli_image != f"{guest_registry}/nemoclaw-cli@{digests['nemoclaw-cli']}":
                raise E2EError(f"{user} BOM does not use the new CLI digest")
            profiles = self.oc_json("get", "configmap", "saw-bom-profiles", "-n", namespace)
            payload = "\n".join(profiles.get("data", {}).values())
            if f"{guest_registry}/nemoclaw-sandbox@{digests['nemoclaw-sandbox']}" not in payload:
                raise E2EError(f"{user} profile does not use the new sandbox digest")
            volumes = self.oc_json("get", "datavolume", "-n", namespace)
            expected = f"docker://{registry}/openshell-gateway@{digests['openshell-gateway']}"
            if not any((item.get("spec", {}).get("source", {}).get("registry") or {}).get("url") ==
                       expected for item in volumes.get("items", [])):
                raise E2EError(f"{user} VM disk does not use the new gateway digest")

    def configure_cli_gateway(self, user: str) -> None:
        """Register the gateway without the CLI's interactive browser login."""
        if self.home is None:
            raise E2EError("private HOME is not ready")
        namespace = f"saw-{user}"
        route = self.oc_json("get", "route", f"{user}-gateway", "-n", namespace)
        host = route.get("spec", {}).get("host")
        if not isinstance(host, str) or not host:
            raise E2EError(f"gateway route is missing for {user}")
        keycloak_host = self.call(["scripts/keycloak-host.sh", "saw-keycloak"]).stdout.strip()
        if not keycloak_host:
            raise E2EError("Keycloak route is missing")
        issuer = f"https://{keycloak_host}/realms/openshell"

        gateway_dir = self.home / ".config/openshell/gateways" / user
        ca_path = gateway_dir / "mtls/ca.crt"
        extract_env = dict(
            self.env, NS=namespace, VM_NAME=user,
            SSH_KEY_PATH=str(self.home / "ssh/sandbox-ssh"),
            OUT_FILE=str(ca_path),
        )
        self.call(["scripts/extract-gateway-ca.sh"], timeout=180, env=extract_env)
        if not ca_path.is_file():
            raise E2EError(f"gateway CA was not installed for {user}")
        ca_data = ca_path.read_text(encoding="utf-8")
        if "BEGIN CERTIFICATE" not in ca_data or "PRIVATE KEY" in ca_data:
            raise E2EError(f"gateway CA is invalid for {user}")

        metadata = {
            "name": user,
            "gateway_endpoint": f"https://{host}",
            "is_remote": False,
            "gateway_port": 0,
            "auth_mode": "oidc",
            "oidc_issuer": issuer,
            "oidc_client_id": "openshell-cli",
            "oidc_audience": "openshell-cli",
            "oidc_scopes": "openid email profile",
        }
        metadata_path = gateway_dir / "metadata.json"
        self.private_file(
            str(metadata_path.relative_to(self.home)),
            (json.dumps(metadata, indent=2) + "\n").encode(),
        )
        # `gateway add --oidc-issuer` always starts an interactive browser flow.
        # CI has already obtained a token with this user's generated Keycloak password.
        self.call(["openshell", "gateway", "select", user], timeout=30)

    def oidc_login(self, user: str, gateway: str, token_dir: Path, *,
                   persist_for_cli: bool = True) -> dict[str, Any]:
        if self.home is None:
            raise E2EError("private HOME is not ready")
        host = self.call(["scripts/keycloak-host.sh", "saw-keycloak"]).stdout.strip()
        issuer = f"https://{host}/realms/openshell"
        context = self.cluster_tls_context()
        with urllib.request.urlopen(issuer + "/.well-known/openid-configuration",
                                    context=context, timeout=15) as response:
            discovery = json.load(response)
        password = (self.home / f"{user}-password").read_text(encoding="utf-8")
        request = urllib.request.Request(
            discovery["token_endpoint"],
            data=urllib.parse.urlencode({
                "grant_type": "password", "client_id": "openshell-cli",
                "username": user, "password": password, "scope": "openid email profile",
            }).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            token = json.load(response)
        if not token.get("access_token") or not token.get("expires_in"):
            raise E2EError(f"{user} authentication returned no usable token")
        token_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        file = token_dir / "token.json"
        file.write_text(json.dumps(token), encoding="utf-8")
        file.chmod(0o600)
        # OpenShell 0.1.2 stores this bundle under the gateway directory.
        bundle = {
            "access_token": token["access_token"],
            "refresh_token": token.get("refresh_token"),
            "expires_at": int(time.time()) + int(token["expires_in"]),
            "issuer": issuer, "client_id": "openshell-cli",
        }
        if persist_for_cli:
            gateway_dir = self.home / ".config/openshell/gateways" / gateway
            gateway_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            cache = gateway_dir / "oidc_token.json"
            cache.write_text(json.dumps(bundle), encoding="utf-8")
            cache.chmod(0o600)
        return token

    def live_behavior(self) -> None:
        if self.home is None:
            raise E2EError("private HOME is not ready")
        owner = USERS[0]
        self.configure_cli_gateway(owner)
        owner_token = self.oidc_login(owner, owner, self.home / "owner-oidc")
        self.oidc_login(USERS[1], owner, self.home / "second-oidc",
                       persist_for_cli=False)
        self.env["TEST_OWNER_SUBJECT"] = self.jwt_subject(owner_token["access_token"])
        listing = self.call(["openshell", "--gateway", owner, "sandbox", "list",
                             "--output", "json"], timeout=45).stdout
        if "notebook" not in listing:
            raise E2EError("owner cannot list the notebook sandbox")
        self.call(["openshell", "--gateway", owner, "sandbox", "exec", "-n",
                   "notebook", "--no-tty", "--", "sh", "-c",
                   "test -d /sandbox && printf ready"], timeout=90)
        denial = self.call(["scripts/check-second-user-denied.sh"], timeout=30)
        if json.loads(denial.stdout).get("status_code") != 403:
            raise E2EError("second-user denial did not return 403")
        inference_script = (
            "fetch('https://integrate.api.nvidia.com/v1/chat/completions',"
            "{method:'POST',headers:{'content-type':'application/json',"
            "authorization:'Bearer '+process.env.NVIDIA_API_KEY},"
            "body:JSON.stringify({model:" + json.dumps(self.required("CI_MODEL")) + ",messages:"
            "[{role:'user',content:'Reply with OK'}],max_tokens:8})})"
            ".then(async r=>{if(!r.ok)process.exit(2);"
            "let j=await r.json();if(!j.choices?.length)process.exit(3);"
            "process.stdout.write('accepted')}).catch(()=>process.exit(4))"
        )
        self.call(["openshell", "--gateway", owner, "sandbox", "exec", "-n",
                   "notebook", "--no-tty", "--", "node", "-e", inference_script],
                  timeout=120)
        isolation_script = (
            "fetch('https://example.org',{signal:AbortSignal.timeout(8000)})"
            ".then(()=>process.exit(5)).catch(()=>process.stdout.write('blocked'))"
        )
        self.call(["openshell", "--gateway", owner, "sandbox", "exec", "-n",
                   "notebook", "--no-tty", "--", "node", "-e", isolation_script],
                  timeout=45)

    @staticmethod
    def jwt_subject(token: str) -> str:
        try:
            payload = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            return claims["sub"]
        except (IndexError, KeyError, ValueError) as exc:
            raise E2EError("owner token has no subject") from exc

    def diagnostics(self) -> None:
        # Only resource status is captured. No Secret or ConfigMap data enters
        # the artifact. A failed diagnostic does not hide the primary failure.
        snapshot: dict[str, Any] = {"captured_at": now()}
        for name, args in (
            ("applications", ["oc", "get", "applications.argoproj.io",
                              "-n", "vp-gitops", "-o", "json"]),
            ("virtualmachines", ["oc", "get", "vm", "-A", "-o", "json"]),
            ("builds", ["oc", "get", "builds", "-A", "-o", "json"]),
        ):
            response = self.call(args, timeout=45, allow_failure=True)
            if response.returncode:
                snapshot[name] = {"error": self.redact(response.stderr.strip())[-200:]}
                continue
            items = json.loads(response.stdout).get("items") or []
            snapshot[name] = [
                {"name": item.get("metadata", {}).get("name"),
                 "namespace": item.get("metadata", {}).get("namespace"),
                 "status": item.get("status", {}).get("phase") or
                           item.get("status", {}).get("printableStatus") or
                           item.get("status", {}).get("sync", {}).get("status")}
                for item in items
            ]
        (self.artifacts / "diagnostics.json").write_text(
            json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")

    def cleanup(self) -> None:
        self.update_lock_data({"state": "cleanup-in-progress"})
        if self.install_attempted:
            self.call(["./pattern.sh", "make", "pattern-uninstall"], timeout=5400)
            self.call(["./pattern.sh", "make", "pattern-uninstall"], timeout=5400)
        if self.build_attempted:
            # These names were absent at preflight. Check for remaining VMs
            # before removing the namespaces that the run created.
            for namespace in (NAMESPACE, "saw-keycloak", *[f"saw-{u}" for u in USERS]):
                exists = self.call(["oc", "get", "namespace", namespace, "-o", "name"],
                                   allow_failure=True)
                if exists.returncode:
                    continue
                vms = self.call(["oc", "get", "vm", "-n", namespace, "-o", "json"],
                                allow_failure=True)
                if vms.returncode == 0 and json.loads(vms.stdout).get("items"):
                    raise E2EError(f"cleanup left a VM in {namespace}")
                self.call(["oc", "delete", "namespace", namespace, "--wait=true",
                           "--timeout=20m"], timeout=1300)
        for namespace in (NAMESPACE, "saw-keycloak", *[f"saw-{u}" for u in USERS]):
            response = self.call(["oc", "get", "namespace", namespace, "-o", "name"],
                                 allow_failure=True)
            if response.returncode == 0:
                raise E2EError(f"cleanup left namespace {namespace}")
        namespaces = {item["metadata"]["name"]
                      for item in self.oc_json("get", "namespaces")["items"]}
        patterns = self.call(["oc", "get", "patterns.gitops.hybrid-cloud-patterns.io",
                              "-A", "-o", "json"], allow_failure=True)
        if patterns.returncode == 0 and json.loads(patterns.stdout).get("items"):
            raise E2EError("cleanup left a Pattern resource")
        if patterns.returncode and "the server doesn't have a resource type" not in patterns.stderr:
            raise E2EError("cannot verify Pattern resource cleanup")
        applications = self.call(["oc", "get", "applications.argoproj.io", "-A", "-o", "json"],
                                 allow_failure=True)
        if applications.returncode == 0:
            remaining = [item for item in json.loads(applications.stdout).get("items", [])
                         if self.repo.split("/", 1)[-1] in
                         json.dumps(item.get("spec", {}).get("source", {}))]
            if remaining:
                raise E2EError("cleanup left repository Argo applications")
        elif "the server doesn't have a resource type" not in applications.stderr:
            raise E2EError("cannot verify Argo application cleanup")
        # The framework removes the Pattern and its applications but can leave
        # its operator and Argo CD namespaces. Remove only namespaces absent
        # at preflight, after confirming that no managed resources remain.
        for namespace in ("patterns-operator", "vp-gitops"):
            if namespace in namespaces and namespace not in self.baseline_namespaces:
                self.call(["oc", "delete", "namespace", namespace, "--wait=true",
                           "--timeout=20m"], timeout=1300)
        namespaces = {item["metadata"]["name"]
                      for item in self.oc_json("get", "namespaces")["items"]}
        new_pattern_namespaces = (namespaces - self.baseline_namespaces) & set(PATTERN_NAMESPACES)
        if new_pattern_namespaces:
            raise E2EError("cleanup left Pattern namespaces: "
                           + ", ".join(sorted(new_pattern_namespaces)))
        self.update_lock_data({"state": "cleanup-verified", "cleanup-verified": "true"})
        self.report["cleanup_verified"] = True
        self.save_report()
        self.release_lock()

    def finish(self) -> None:
        if self.home is not None:
            shutil.rmtree(self.home)
            self.home = None
        self.report["finished_at"] = now()
        self.save_report()

    def run(self) -> int:
        failure: str | None = None
        try:
            self.stage("prepare-files", self.setup_files)
            self.stage("cluster-preflight-and-lock", self.preflight)
            self.stage("build-and-record-digests", self.build)
            self.stage("prepare-registry-pull", self.prepare_registry_pull)
            self.stage("pattern-install", self.install)
            self.stage("deployment-readiness-and-digest-checks", self.verify_deployment_smoke)
            self.stage("guest-installer", self.verify_guest_install)
            self.stage("live-behavior", self.live_behavior)
        except BaseException as exc:
            failure = self.redact(str(exc)) or "runner cancelled"
            self.report["failure"] = failure
        finally:
            if self.locked:
                try:
                    self.diagnostics()
                except Exception as exc:
                    self.report["diagnostics_error"] = self.redact(str(exc))
                try:
                    self.update_lock_data({
                        "state": "cleanup-required",
                        "test-outcome": "failure" if failure else "success",
                    })
                except Exception as exc:
                    self.report["lock_state_error"] = self.redact(str(exc))
                    failure = failure or "could not mark the cluster for cleanup"
            self.finish()
        if failure:
            print(f"Pattern E2E failed: {failure}", file=sys.stderr)
            return 1
        return 0

    def recover_cleanup(self) -> int:
        failure: str | None = None
        try:
            self.stage("cleanup-prerequisites", self.setup_recovery_files)
            self.stage("cluster-identity", lambda: self.cluster_identity(
                create_lock_namespace=False))
            self.load_recovery_state()
            if self.locked:
                try:
                    self.diagnostics()
                except Exception as exc:
                    self.report["diagnostics_error"] = self.redact(str(exc))
                self.stage("recovery-cleanup", self.cleanup)
        except BaseException as exc:
            failure = self.redact(str(exc)) or "cleanup recovery failed"
            self.report["cleanup_recovery_failure"] = failure
        finally:
            if self.locked:
                try:
                    self.mark_cleanup_required()
                except Exception as exc:
                    self.report["cleanup_lock_error"] = self.redact(str(exc))
            else:
                self.report["cleanup_verified"] = self.report.get("cleanup_verified", False)
            self.finish()
        if failure:
            print(f"Pattern E2E cleanup failed: {failure}", file=sys.stderr)
            return 1
        return 0


def main() -> int:
    if sys.argv[1:]:
        print("Usage: pattern_e2e.py", file=sys.stderr)
        return 2
    try:
        runner = Runner()
    except E2EError as exc:
        print(f"Pattern E2E setup failed: {exc}", file=sys.stderr)
        return 1
    def cancelled(_signal, _frame):
        runner.cancelled = True
        raise KeyboardInterrupt("runner cancelled")
    signal.signal(signal.SIGINT, cancelled)
    signal.signal(signal.SIGTERM, cancelled)
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
