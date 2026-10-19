#!/usr/bin/env python3
"""Run the minimal SAW Pattern deployment test on a dedicated cluster."""

from __future__ import annotations

import argparse
import base64
import contextlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import shutil
import signal
import ssl
import subprocess
import sys
import tarfile
import tempfile
import termios
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

import yaml


ROOT = Path(__file__).resolve().parents[1]
OWNER = "e2e-owner"
SAW_NS = f"saw-{OWNER}"
LOCK_NS = "default"
LOCK_NAME = "saw-tp-e2e-lock"
DEPLOY_SECONDS = 90 * 60
CLEANUP_SECONDS = 20 * 60
EXPECTED_APPS = {
    "openshift-external-secrets", "vault", "openshift-cnv",
    "openshell-keycloak", "saw-users",
}
EXPECTED_SUBSCRIPTIONS = {"eso", "openshift-virtualization", "rhbk"}
EXPECTED_CHILD_APPS = {f"saw-{OWNER}-secrets", f"saw-{OWNER}-bom", f"saw-{OWNER}"}
IMAGE_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


class E2EError(Exception):
    """A test check failed without exposing credential data."""


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def private_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def clean_message(message: str, sensitive: list[str]) -> str:
    for value in sensitive:
        if value:
            message = message.replace(value, "[REDACTED]")
    message = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~-]+", r"\1[REDACTED]", message)
    message = re.sub(r"(?i)((?:api[_-]?key|password|token)\s*[=:]\s*)\S+",
                     r"\1[REDACTED]", message)
    return message[:1200]


def ansible_failure_summary(output: str) -> str:
    tasks = re.findall(r"(?m)^TASK \[([^\]\r\n]{1,150})\]", output)
    fatal = len(re.findall(r"(?m)^fatal: \[", output))
    parts = []
    if tasks:
        parts.append("last Ansible task: " + tasks[-1])
    if fatal:
        parts.append(f"Ansible fatal results: {fatal}")
    return "; ".join(parts)


def load_config(path: Path, *, require_key: bool) -> dict:
    if not path.is_absolute() or not path.is_file():
        raise E2EError("E2E_CONFIG must name an existing absolute file")
    if path.stat().st_mode & 0o077:
        raise E2EError("E2E_CONFIG must be readable only by its owner")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise E2EError("E2E_CONFIG must contain a YAML object")
    cluster = data.get("cluster")
    inference = data.get("inference")
    if not isinstance(cluster, dict) or not isinstance(inference, dict):
        raise E2EError("cluster and inference must be objects")
    if cluster.get("apiURL"):
        url = urllib.parse.urlparse(str(cluster["apiURL"]))
        try:
            port = url.port
        except ValueError as exc:
            raise E2EError("cluster.apiURL has an invalid port") from exc
        if (url.scheme != "https" or not url.hostname or not port or url.username
                or url.password or url.path not in ("", "/") or url.query):
            raise E2EError("cluster.apiURL must be an HTTPS API URL with a port")
        if not isinstance(cluster.get("username"), str) or not cluster["username"]:
            raise E2EError("cluster.username is required")
        if (not isinstance(cluster.get("password"), str) or not cluster["password"]
                or "\n" in cluster["password"] or "\r" in cluster["password"]):
            raise E2EError("cluster.password is required")
    else:
        kubeconfig = Path(str(cluster.get("kubeconfig", "")))
        if not kubeconfig.is_absolute() or not kubeconfig.is_file() or not cluster.get("context"):
            raise E2EError("cluster.apiURL with credentials or kubeconfig with context is required")
        data["cluster"]["kubeconfig"] = str(kubeconfig)
    if inference.get("provider") != "nvidia":
        raise E2EError("inference.provider must be nvidia")
    model = inference.get("model")
    if not isinstance(model, str) or not re.fullmatch(r"nvidia/[A-Za-z0-9._/-]+", model):
        raise E2EError("inference.model must be a NVIDIA model identifier")
    key_file = Path(str(inference.get("apiKeyFile", "")))
    if require_key:
        if inference.get("apiKey"):
            if not isinstance(inference["apiKey"], str) or "\n" in inference["apiKey"]:
                raise E2EError("inference.apiKey must be one line")
        else:
            if not key_file.is_absolute() or not key_file.is_file():
                raise E2EError("inference.apiKey or an absolute apiKeyFile is required")
            if key_file.stat().st_mode & 0o077:
                raise E2EError("inference.apiKeyFile must be readable only by its owner")
            if not key_file.read_bytes().strip():
                raise E2EError("inference.apiKeyFile is empty")
    if data.get("cleanup", "always") not in ("always", "retain"):
        raise E2EError("cleanup must be always or retain")
    if not inference.get("apiKey"):
        data["inference"]["apiKeyFile"] = str(key_file)
    return data


class CommandRunner:
    def __init__(self, env: dict[str, str], sensitive: list[str] | None = None):
        self.env = env
        self.sensitive = sensitive or []

    def run(self, label: str, args: list[str], *, input_text: str | None = None,
            timeout: float = 120, cwd: Path = ROOT) -> str:
        try:
            result = subprocess.run(args, input=input_text, text=True,
                                    stdin=subprocess.DEVNULL if input_text is None else None,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=self.env, cwd=cwd, timeout=max(1, timeout),
                                    check=False)
        except subprocess.TimeoutExpired as exc:
            raise E2EError(f"{label} timed out after {int(timeout)} seconds") from exc
        except OSError as exc:
            raise E2EError(f"{label} could not start: {exc.strerror}") from exc
        if result.returncode:
            detail = clean_message(result.stderr or result.stdout, self.sensitive)
            if label == "install minimal Pattern":
                summary = ansible_failure_summary(result.stdout)
                if summary:
                    detail += "\n" + clean_message(summary, self.sensitive)
            raise E2EError(f"{label} failed with exit code {result.returncode}: {detail}")
        return result.stdout

    def oc_json(self, label: str, *args: str, timeout: float = 120) -> dict:
        output = self.run(label, ["oc", *args, "-o", "json"], timeout=timeout)
        try:
            value = json.loads(output)
        except json.JSONDecodeError as exc:
            raise E2EError(f"{label} did not return JSON") from exc
        if not isinstance(value, dict):
            raise E2EError(f"{label} did not return a JSON object")
        return value


def yaml_docs(output: str) -> list[dict]:
    try:
        return [item for item in yaml.safe_load_all(output) if isinstance(item, dict)]
    except yaml.YAMLError as exc:
        raise E2EError("Helm render did not return valid YAML") from exc


def checked_in_selection() -> dict:
    values = yaml.safe_load((ROOT / "values-e2e.yaml").read_text(encoding="utf-8"))
    group = values.get("clusterGroup") or {}
    apps = set((group.get("applications") or {}).keys())
    subs = set((group.get("subscriptions") or {}).keys())
    if group.get("name") != "e2e" or apps != EXPECTED_APPS or subs != EXPECTED_SUBSCRIPTIONS:
        raise E2EError("minimal Pattern application or subscription selection changed")
    jobs = {item.get("name") for item in (group.get("imperative") or {}).get("jobs", [])}
    if jobs != {"saw-ingress-ca"}:
        raise E2EError("minimal Pattern imperative job selection changed")
    if set((group.get("namespaces") or {}).keys()) != {
        "external-secrets", "external-secrets-operator", "openshift-cnv",
        "openshell-agents", "saw-keycloak", "vault",
    }:
        raise E2EError("minimal Pattern namespace selection changed")
    return values


def render_children(runner: CommandRunner, runtime_file: Path, sha: str) -> dict[str, dict]:
    output = runner.run("render SAW child applications", [
        "helm", "template", "saw-users", "charts/saw-users", "--namespace",
        "openshell-agents", "-f", "overrides/saw-users-e2e.yaml", "--set-file",
        f"global.e2eRuntimeB64={runtime_file}", "--set-string",
        f"global.targetRevision={sha}",
    ])
    apps = {item["metadata"]["name"]: item for item in yaml_docs(output)
            if item.get("kind") == "Application"}
    if set(apps) != EXPECTED_CHILD_APPS:
        raise E2EError("rendered child application selection changed")
    namespaces = [item for item in yaml_docs(output) if item.get("kind") == "Namespace"]
    if len(namespaces) != 1 or namespaces[0]["metadata"]["name"] != SAW_NS:
        raise E2EError("rendered SAW namespace selection changed")
    values_by_app = {}
    for name, app in apps.items():
        source = app["spec"]["source"]
        if source.get("targetRevision") != sha:
            raise E2EError(f"{name} does not select the tested SHA")
        values_by_app[name] = yaml.safe_load(source["helm"]["values"]) or {}
    secrets_values = values_by_app[f"saw-{OWNER}-secrets"]
    if secrets_values.get("secrets") != ["inference"] or secrets_values.get("vaultPrefix") != f"secret/data/hub/saw-{OWNER}":
        raise E2EError("rendered External Secrets path or selection changed")
    bom_values = values_by_app[f"saw-{OWNER}-bom"]
    if bom_values.get("profiles") != ["e2e"] or bom_values.get("harnessEnabled", False):
        raise E2EError("rendered BOM profile selection changed")
    saw = values_by_app[f"saw-{OWNER}"]
    if saw.get("governance", {}).get("enabled") is not False:
        raise E2EError("rendered gateway still enables governance")
    if saw.get("containerRuntime") != "podman" or not saw.get("networkPolicy", {}).get("enabled"):
        raise E2EError("rendered gateway lacks Podman or NetworkPolicy")
    if not IMAGE_RE.search(saw.get("source", {}).get("registryURL", "")):
        raise E2EError("rendered VM image is not pinned by digest")
    if saw.get("additionalProviderSecrets"):
        raise E2EError("rendered VM mounts an unrelated provider Secret")
    return values_by_app


def render_charts(runner: CommandRunner, child_values: dict[str, dict], work: Path) -> None:
    for chart, app in (("charts/saw-bom", f"saw-{OWNER}-bom"),
                       ("charts/openshell-saw", f"saw-{OWNER}"),
                       ("charts/pattern-secrets", f"saw-{OWNER}-secrets")):
        values_file = work / (app + "-values.yaml")
        private_write(values_file, yaml.safe_dump(child_values[app]).encode())
        output = runner.run(f"render {chart}", ["helm", "template", OWNER, chart,
                            "--namespace", SAW_NS, "-f", str(values_file)])
        docs = yaml_docs(output)
        if chart.endswith("saw-bom"):
            profiles = [item for item in docs if item.get("kind") == "ConfigMap" and
                        item.get("metadata", {}).get("name") == "saw-bom-profiles"]
            if len(profiles) != 1:
                raise E2EError("minimal BOM ConfigMap is absent")
            names = set(profiles[0].get("data", {}))
            if names != {"profiles__e2e__default__workspace.yaml",
                         "profiles__e2e__default__providers.yaml",
                         "profiles__e2e__default__sandbox.yaml"}:
                raise E2EError("minimal BOM contains an excluded profile file")
            providers = yaml.safe_load(profiles[0]["data"]["profiles__e2e__default__providers.yaml"])
            sandboxes = yaml.safe_load(profiles[0]["data"]["profiles__e2e__default__sandbox.yaml"])
            if [(p.get("type"), p.get("credentialSecret")) for p in providers["spec"]["providers"]] != [("nvidia", "inference")]:
                raise E2EError("minimal BOM provider selection changed")
            if [(s.get("type"), s.get("name")) for s in sandboxes["spec"]["sandboxes"]] != [("openclaw", "notebook")]:
                raise E2EError("minimal BOM sandbox selection changed")
        if chart.endswith("openshell-saw"):
            kinds = {item.get("kind") for item in docs}
            if "VirtualMachine" not in kinds or "NetworkPolicy" not in kinds or "EgressFirewall" not in kinds:
                raise E2EError("rendered VM lacks required network resources")
            vms = [item for item in docs if item.get("kind") == "VirtualMachine"]
            if len(vms) != 1:
                raise E2EError("rendered VM selection changed")
            template = vms[0]["spec"]["template"]["spec"]
            devices = template["domain"]["devices"]
            attached = {item["name"] for kind in ("disks", "filesystems")
                        for item in devices.get(kind, [])}
            volumes = {item["name"] for item in template.get("volumes", [])}
            if not volumes.issubset(attached):
                raise E2EError("rendered VM has a volume without a matching device")
            installers = [item for item in docs if item.get("kind") == "ConfigMap" and
                          item.get("metadata", {}).get("name") == f"{OWNER}-installer"]
            if len(installers) != 1:
                raise E2EError("rendered installer ConfigMap is absent")
            bom = yaml.safe_load(installers[0]["data"]["installer-bom.yaml"])
            if "nemoclaw" in bom.get("spec", {}):
                raise E2EError("rendered installer still includes NemoClaw")
            for component in bom["spec"]["openshell"].values():
                if not IMAGE_RE.search(component.get("image", "")):
                    raise E2EError("rendered installer contains an unpinned component")
        if chart.endswith("pattern-secrets"):
            external = {item["metadata"]["name"] for item in docs if item.get("kind") == "ExternalSecret"}
            if "inference" not in external or "web-search" in external:
                raise E2EError("rendered External Secrets selection changed")
    keycloak = yaml_docs(runner.run("render minimal Keycloak", [
        "helm", "template", "e2e-keycloak", "charts/openshell-keycloak",
        "--namespace", "saw-keycloak", "-f", "overrides/keycloak-e2e.yaml"]))
    realms = [item for item in keycloak if item.get("kind") == "KeycloakRealmImport"]
    if len(realms) != 1 or [user.get("username") for user in realms[0]["spec"]["realm"]["users"]] != [OWNER]:
        raise E2EError("rendered Keycloak owner selection changed")
    if not any(item.get("kind") == "ExternalSecret" and
               item.get("metadata", {}).get("name") == "openshell-keycloak-user-passwords"
               for item in keycloak):
        raise E2EError("rendered Keycloak password Secret bypasses External Secrets")


def report_paths(state_dir: Path, run_id: str) -> tuple[Path, Path, Path]:
    return (state_dir / f"{run_id}.inventory.json", state_dir / f"{run_id}.report.json",
            state_dir / f"{run_id}.junit.xml")


def write_reports(inventory: dict, state_dir: Path) -> None:
    run_id = inventory["run_id"]
    inv_path, report_path, junit_path = report_paths(state_dir, run_id)
    private_write(inv_path, (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode())
    report = {key: inventory.get(key) for key in (
        "run_id", "started_at", "finished_at", "source_sha", "cluster_context",
        "provider", "driver", "model", "image_digests", "installed_versions",
        "stages", "coverage", "status", "cleanup_status", "error", "cleanup_errors",
    )}
    private_write(report_path, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    suite = ET.Element("testsuite", name="saw-tp-e2e", tests=str(len(inventory.get("stages", []))),
                       failures=str(sum(item["status"] == "failed" for item in inventory.get("stages", []))),
                       timestamp=inventory["started_at"])
    for item in inventory.get("stages", []):
        case = ET.SubElement(suite, "testcase", name=item["name"],
                             time=str(item.get("seconds", 0)))
        if item["status"] == "failed":
            ET.SubElement(case, "failure", message=item.get("error", "stage failed"))
    private_write(junit_path, ET.tostring(suite, encoding="utf-8", xml_declaration=True))


def stage(inventory: dict, state_dir: Path, name: str, operation,
          sensitive: list[str] | None = None):
    started = time.monotonic()
    item = {"name": name, "started_at": now(), "status": "running"}
    inventory["stages"].append(item)
    write_reports(inventory, state_dir)
    try:
        result = operation()
    except BaseException as exc:
        item.update(status="failed", ended_at=now(), seconds=round(time.monotonic()-started, 2),
                    error=clean_message(str(exc), sensitive or []))
        write_reports(inventory, state_dir)
        raise
    item.update(status="passed", ended_at=now(), seconds=round(time.monotonic()-started, 2))
    write_reports(inventory, state_dir)
    return result


def _quantity(value: str) -> int:
    match = re.fullmatch(r"([0-9]+)(n|m|Ki|Mi|Gi|Ti)?", str(value))
    if not match:
        raise E2EError("cluster returned an unsupported resource quantity")
    amount, suffix = int(match[1]), match[2]
    factors = {None: 1, "n": 1e-9, "m": 1e-3, "Ki": 1024,
               "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4}
    return int(amount * factors[suffix])


def preflight_cluster(runner: CommandRunner, config: dict) -> dict:
    required = ("oc", "helm", "podman", "ssh-keygen", "git", "make")
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        raise E2EError("missing required tools: " + ", ".join(missing))
    context = runner.env["SAW_E2E_CONTEXT"]
    contexts = runner.run("read kubeconfig contexts", ["oc", "config", "get-contexts", "-o", "name"])
    if context not in contexts.splitlines():
        raise E2EError("configured OpenShift context is absent from kubeconfig")
    runner.run("verify OpenShift login", ["oc", "whoami"])
    allowed = runner.run("verify cluster-admin", ["oc", "auth", "can-i", "*", "*", "--all-namespaces"])
    if allowed.strip() != "yes":
        raise E2EError("the selected context lacks cluster-admin access")
    runner.oc_json("read cluster network", "get", "network.config", "cluster")
    ingress = runner.oc_json("read ingress", "get", "ingresses.config.openshift.io", "cluster")
    domain = ingress.get("spec", {}).get("domain")
    if not isinstance(domain, str) or not domain:
        raise E2EError("cluster ingress domain is absent")
    nodes = runner.oc_json("read nodes", "get", "nodes").get("items", [])
    vm = config.get("vm") or {}
    cores = vm.get("cores", 4)
    memory = vm.get("memory", "8Gi")
    disk = vm.get("diskSize", "40Gi")
    if not isinstance(cores, int) or isinstance(cores, bool) or cores < 1:
        raise E2EError("vm.cores must be a positive integer")
    memory_bytes = _quantity(memory)
    disk_bytes = _quantity(disk)
    if memory_bytes < 1024**3 or disk_bytes < 1024**3:
        raise E2EError("VM memory and disk must each be at least 1 GiB")
    suitable = [node for node in nodes
                if not node.get("spec", {}).get("unschedulable")
                and any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in node.get("status", {}).get("conditions", []))
                and _quantity(node.get("status", {}).get("allocatable", {}).get("cpu", "0")) >= cores
                and _quantity(node.get("status", {}).get("allocatable", {}).get("memory", "0")) >= memory_bytes]
    if not suitable:
        raise E2EError("no Ready node has the requested VM CPU and memory capacity")
    classes = runner.oc_json("read storage classes", "get", "storageclasses").get("items", [])
    selected_class = vm.get("storageClassName")
    if selected_class:
        if not any(item["metadata"]["name"] == selected_class for item in classes):
            raise E2EError("configured VM StorageClass does not exist")
    elif not any(item.get("metadata", {}).get("annotations", {}).get(
            "storageclass.kubernetes.io/is-default-class") == "true" for item in classes):
        raise E2EError("no default VM StorageClass is available")
    namespaces = {item["metadata"]["name"]: item["metadata"]["uid"] for item in
                  runner.oc_json("read namespaces", "get", "namespaces").get("items", [])}
    subscriptions = {item["metadata"]["namespace"] + "/" + item["metadata"]["name"]
                     for item in runner.oc_json("read operator subscriptions", "get",
                                                "subscriptions", "-A").get("items", [])}
    # The Pattern must not adopt an existing application namespace.
    for name in (SAW_NS, "openshell-agents", "vault", "external-secrets",
                 "external-secrets-operator", "openshift-cnv", "saw-keycloak"):
        if name in namespaces:
            raise E2EError(f"{name} already exists; use a dedicated base cluster")
    pattern = subprocess.run(["scripts/pattern-exists.sh"], cwd=ROOT, env=runner.env,
                             capture_output=True, text=True, check=False)
    if pattern.returncode == 0:
        raise E2EError("a SAW Pattern installation already exists")
    if pattern.returncode != 1:
        raise E2EError("could not determine whether a SAW Pattern exists")
    registry = runner.oc_json("read image registry configuration", "get",
                              "configs.imageregistry.operator.openshift.io", "cluster")
    return {"namespaces": namespaces, "subscriptions": sorted(subscriptions),
            "ingress_domain": domain,
            "registry_default_route": registry.get("spec", {}).get("defaultRoute", False),
            "vm_cores": cores, "vm_memory": memory, "vm_disk": disk}


def create_lock(runner: CommandRunner, inventory: dict) -> None:
    obj = {"apiVersion": "v1", "kind": "ConfigMap",
           "metadata": {"name": LOCK_NAME, "namespace": LOCK_NS,
                        "labels": {"saw.redhat.com/e2e-lock": "true"}},
           "data": {"inventory": json.dumps(inventory, separators=(",", ":"))}}
    runner.run("acquire cluster lock", ["oc", "create", "-f", "-"],
               input_text=json.dumps(obj), timeout=30)


def update_lock(runner: CommandRunner, inventory: dict) -> None:
    obj = runner.oc_json("read cluster lock", "get", "configmap", LOCK_NAME,
                         "-n", LOCK_NS)
    prior = json.loads(obj.get("data", {}).get("inventory", "{}"))
    if prior.get("run_id") != inventory["run_id"]:
        raise E2EError("cluster lock belongs to another run")
    obj["data"] = {"inventory": json.dumps(inventory, separators=(",", ":"))}
    runner.run("update cluster lock", ["oc", "replace", "-f", "-"],
               input_text=json.dumps(obj), timeout=30)


def read_lock(runner: CommandRunner) -> dict:
    obj = runner.oc_json("read cluster lock", "get", "configmap", LOCK_NAME,
                         "-n", LOCK_NS)
    try:
        inventory = json.loads(obj["data"]["inventory"])
    except (KeyError, ValueError, TypeError) as exc:
        raise E2EError("cluster lock has no valid run inventory") from exc
    if inventory.get("cluster_context") != runner.env.get("SAW_E2E_CONTEXT"):
        raise E2EError("cluster lock context differs from the selected context")
    return inventory


def release_lock(runner: CommandRunner, inventory: dict) -> None:
    current = read_lock(runner)
    if current.get("run_id") != inventory["run_id"]:
        raise E2EError("cluster lock belongs to another run")
    runner.run("release cluster lock", ["oc", "delete", "configmap", LOCK_NAME,
                                         "-n", LOCK_NS, "--wait=true"], timeout=60)


def remote_sha(runner: CommandRunner, branch: str, expected: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch) or branch.startswith("-"):
        raise E2EError("the Git branch name is invalid")
    output = runner.run("verify pushed source SHA", ["git", "ls-remote", "--heads",
                                                      "origin", branch], timeout=30)
    lines = [line.split() for line in output.splitlines() if line.strip()]
    if len(lines) != 1 or lines[0][0] != expected:
        raise E2EError("the pushed Pattern branch does not match the tested SHA")


def source_identity(runner: CommandRunner) -> tuple[str, str]:
    sha = runner.run("read source SHA", ["git", "rev-parse", "HEAD"]).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise E2EError("could not determine the source SHA")
    branch = runner.env.get("E2E_TARGET_BRANCH") or runner.run(
        "read source branch", ["git", "branch", "--show-current"]).strip()
    if not branch:
        raise E2EError("set E2E_TARGET_BRANCH for a detached checkout")
    supplied = runner.env.get("E2E_SOURCE_SHA")
    if supplied and supplied != sha:
        raise E2EError("workflow SHA differs from the checked-out source")
    if runner.run("check tracked changes", ["git", "status", "--porcelain"]).strip():
        raise E2EError("push and check out a clean implementation commit before a live run")
    remote_sha(runner, branch, sha)
    return sha, branch


def prepare_workspace(config: dict, run_id: str) -> tuple[Path, Path, dict]:
    state_dir = Path(os.environ.get("E2E_STATE_DIR") or config.get("stateDir")
                     or Path.home() / ".local/state/saw-tp-e2e")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    work = Path(tempfile.mkdtemp(prefix=f"saw-tp-e2e-{run_id}-"))
    os.chmod(work, 0o700)
    source = config["cluster"].get("kubeconfig")
    private_write(work / "kubeconfig", Path(source).read_bytes() if source else b"")
    env = dict(os.environ)
    env.update(KUBECONFIG=str(work / "kubeconfig"), SAW_E2E_MOUNT=str(work),
               SAW_E2E_NONINTERACTIVE="1",
               SAW_E2E_CONTEXT=str(config["cluster"].get("context", "")),
               PATTERN_TRACKING_ID="secure-agent-workspace-e2e")
    return state_dir, work, env


def login_cluster(runner: CommandRunner, config: dict) -> str:
    cluster = config["cluster"]
    if "apiURL" not in cluster:
        context = cluster["context"]
        runner.run("select copied kubeconfig context", ["oc", "config", "use-context", context])
        return context
    args = ["oc", "login", cluster["apiURL"], "--username", cluster["username"]]
    ca_file = cluster.get("caFile")
    if ca_file:
        ca = Path(ca_file)
        if not ca.is_absolute() or not ca.is_file():
            raise E2EError("cluster.caFile must name an existing absolute file")
        args.extend(["--certificate-authority", str(ca)])
    master, slave = pty.openpty()
    settings = termios.tcgetattr(slave)
    settings[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, settings)
    process = None
    try:
        process = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                                   env=runner.env, cwd=ROOT, start_new_session=True)
        os.close(slave)
        slave = -1
        deadline = time.monotonic() + 60
        seen = b""
        sent = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            readable, _, _ = select.select([master], [], [], 1)
            if not readable:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError:
                process.wait(timeout=2)
                break
            if not chunk:
                process.wait(timeout=2)
                break
            seen = (seen + chunk)[-8192:]
            if not sent and re.search(rb"(?i)password(?: for [^\r\n:]+)?\s*:\s*$", seen):
                os.write(master, cluster["password"].encode() + b"\n")
                sent = True
                seen = b""
        if process.poll() is None:
            process.kill()
            process.wait()
            raise E2EError("OpenShift login timed out")
        if process.returncode != 0 or not sent:
            raise E2EError("OpenShift login failed; check the API URL, CA, and credentials")
    finally:
        os.close(master)
        if slave >= 0:
            os.close(slave)
        if process and process.poll() is None:
            process.kill()
            process.wait()
    context = runner.run("read generated context", ["oc", "config", "current-context"]).strip()
    if not context:
        raise E2EError("OpenShift login did not create a context")
    flattened = runner.run("embed API CA in temporary kubeconfig",
                           ["oc", "config", "view", "--raw", "--flatten", "-o", "yaml"])
    private_write(Path(runner.env["KUBECONFIG"]), flattened.encode())
    runner.env["SAW_E2E_CONTEXT"] = context
    return context


def discover_topology(runner: CommandRunner, work: Path, deadline: float) -> dict:
    output_file = work / "topology.json"
    runner.run("discover network topology", ["uv", "run", "--locked", "python",
              "scripts/network-topology.py", "discover", "--output", str(output_file)],
              timeout=min(120, max(1, deadline - time.monotonic())))
    return json.loads(output_file.read_text(encoding="utf-8"))


def mirror_image(runner: CommandRunner, deadline: float) -> str:
    env = dict(runner.env)
    env.update(MIRROR_IMAGES="openshell-gateway", IMAGE_TAG="latest")
    copy = CommandRunner(env, runner.sensitive)
    copy.run("mirror golden VM image", ["make", "images-mirror"],
             timeout=max(1, deadline - time.monotonic()))
    stream = runner.oc_json("read mirrored image digest", "get", "imagestreamtag",
                            "openshell-gateway:latest", "-n", "openshell-agents")
    digest = stream.get("image", {}).get("metadata", {}).get("name", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise E2EError("mirrored golden VM image has no digest")
    return digest


def runtime_values(config: dict, topology: dict, digest: str) -> dict:
    runtime = dict(topology)
    runtime["registryURL"] = (
        "docker://image-registry.openshift-image-registry.svc:5000/"
        f"openshell-agents/openshell-gateway@{digest}")
    vm = config.get("vm") or {}
    if vm:
        runtime["vm"] = {key: vm[key] for key in ("cores", "memory", "diskSize",
                                                   "storageClassName") if key in vm}
    ca_file = (config.get("oidc") or {}).get("caFile")
    if ca_file:
        ca = Path(ca_file)
        if not ca.is_absolute() or not ca.is_file():
            raise E2EError("oidc.caFile must name an existing absolute file")
        value = ca.read_text(encoding="utf-8")
        if "BEGIN CERTIFICATE" not in value or "PRIVATE KEY" in value:
            raise E2EError("oidc.caFile must contain a public CA certificate")
        runtime["oidcCaBundle"] = value
    return runtime


def pinned_image_digests() -> dict[str, str]:
    bom = yaml.safe_load((ROOT / "charts/openshell-saw/values.yaml").read_text())
    images = {f"openshell_{name}": item["image"] for name, item in
              bom["bom"]["spec"]["openshell"].items() if isinstance(item, dict)
              and "image" in item}
    sandbox = yaml.safe_load((ROOT / "charts/saw-bom/profiles/e2e/default/sandbox.yaml").read_text())
    images["openclaw"] = sandbox["spec"]["sandboxes"][0]["image"]
    if not all(IMAGE_RE.search(image) for image in images.values()):
        raise E2EError("a required component image is not pinned by digest")
    return {name: image.rsplit("@", 1)[1] for name, image in images.items()}


def generate_inputs(runner: CommandRunner, config: dict, work: Path) -> tuple[Path, str]:
    runner.run("generate test SSH key", ["ssh-keygen", "-q", "-t", "ed25519",
                                         "-N", "", "-f", str(work / "ssh-key")], timeout=30)
    key = (config["inference"]["apiKey"].encode()
           if config["inference"].get("apiKey") else
           Path(config["inference"]["apiKeyFile"]).read_bytes()).strip()
    if b"\n" in key or b"\r" in key:
        raise E2EError("NVIDIA API key file must contain one line")
    private_write(work / "nvidia-key", key + b"\n")
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!@#%^*+="
    password = ""
    while not (any(c.islower() for c in password) and any(c.isupper() for c in password)
               and any(c.isdigit() for c in password) and any(not c.isalnum() for c in password)):
        password = "".join(secrets.choice(alphabet) for _ in range(24))
    private_write(work / "keycloak-password", password.encode())
    values = {
        "version": "2.0", "backingStore": "vault",
        "secrets": [
            {"name": "ssh", "fields": [
                {"name": "private_key", "path": str(work / "ssh-key")},
                {"name": "public_key", "path": str(work / "ssh-key.pub")}]},
            {"name": "inference", "vaultPrefixes": [f"hub/saw-{OWNER}"], "fields": [
                {"name": "provider", "value": "nvidia"},
                {"name": "model", "value": config["inference"]["model"]},
                {"name": "api_key", "path": str(work / "nvidia-key")}]},
            {"name": "keycloak-users", "fields": [
                {"name": OWNER, "path": str(work / "keycloak-password")}]},
        ],
    }
    file = work / "values-secret.yaml"
    private_write(file, yaml.safe_dump(values, sort_keys=False).encode())
    runner.sensitive.extend([key.decode(), password])
    return file, password


def pattern_environment(runner: CommandRunner, work: Path, branch: str) -> CommandRunner:
    env = dict(runner.env)
    env.update(TARGET_CLUSTERGROUP="e2e", TARGET_BRANCH=branch, TARGET_ORIGIN="origin",
               VALUES_SECRET=str(work / "values-secret.yaml"),
               SSH_KEY_PATH=str(work / "ssh-key"),
               EXTRA_HELM_OPTS=("--set-string main.extraParameters[0].name=global.e2eRuntimeB64 "
                                f"--set-file main.extraParameters[0].value={work / 'e2e-runtime.b64'}"))
    return CommandRunner(env, runner.sensitive)


def write_runtime(work: Path, runtime: dict) -> Path:
    raw = json.dumps(runtime, separators=(",", ":"))
    path = work / "e2e-runtime.b64"
    # Argo CD passes extraParameters to Helm as --set. Base64 avoids Helm
    # treating JSON commas and brackets as --set syntax.
    private_write(path, base64.b64encode(raw.encode()))
    return path


def pattern_show(runner: CommandRunner, deadline: float) -> None:
    runner.run("render Pattern install", ["./pattern.sh", "make", "show"],
               timeout=min(300, max(1, deadline - time.monotonic())))


def wait_until(label: str, deadline: float, predicate, interval: int = 10):
    last = "condition not met"
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except E2EError as exc:
            last = str(exc)
        time.sleep(min(interval, max(0, deadline - time.monotonic())))
    raise E2EError(f"{label} timed out: {last}")


def application_health(runner: CommandRunner, names: set[str], sha: str,
                       deadline: float) -> None:
    def check():
        apps = runner.oc_json("read GitOps applications", "get", "applications.argoproj.io",
                              "-n", "vp-gitops", timeout=30).get("items", [])
        selected = {item["metadata"]["name"]: item for item in apps
                    if item.get("metadata", {}).get("name") in names}
        if set(selected) != names:
            return False
        for name, app in selected.items():
            status = app.get("status", {})
            if status.get("sync", {}).get("status") != "Synced":
                return False
            if status.get("health", {}).get("status") != "Healthy":
                return False
            revision = status.get("sync", {}).get("revision", "")
            if revision and revision != sha:
                raise E2EError(f"{name} synced a different source SHA")
        return True
    wait_until("GitOps application health", deadline, check)


def post_deploy_selection(runner: CommandRunner, baseline: dict) -> None:
    apps = runner.oc_json("read deployed applications", "get", "applications.argoproj.io",
                          "-n", "vp-gitops").get("items", [])
    names = {item.get("metadata", {}).get("name") for item in apps}
    forbidden_apps = {"openshell-rhdh", "governance-interceptor", "governance-policy",
                      "governance-apf", "saw-portal-vault"}
    if names & forbidden_apps:
        raise E2EError("minimal Pattern created an excluded application")
    allowed = EXPECTED_APPS | EXPECTED_CHILD_APPS | {
        "hub", "e2e", "secure-agent-workspace",
    }
    if names - allowed:
        raise E2EError("minimal Pattern created an unexpected application")
    subscriptions = {item["metadata"]["namespace"] + "/" + item["metadata"]["name"]
                     for item in runner.oc_json("read deployed subscriptions", "get",
                                                "subscriptions", "-A").get("items", [])}
    new = subscriptions - set(baseline.get("subscriptions", []))
    forbidden = {"rhdh", "openshift-pipelines-operator-rh", "rhods-operator"}
    if any(name.split("/")[-1] in forbidden for name in new):
        raise E2EError("minimal Pattern created an excluded operator subscription")


def secret_ready(runner: CommandRunner, namespace: str, name: str,
                 deadline: float) -> None:
    def check():
        obj = runner.oc_json(f"read {name} ExternalSecret", "get", "externalsecret",
                             name, "-n", namespace, timeout=30)
        ready = any(item.get("type") == "Ready" and item.get("status") == "True"
                    for item in obj.get("status", {}).get("conditions", []))
        if not ready:
            return False
        found = runner.run(f"check {name} target Secret", ["oc", "get", "secret",
                           name, "-n", namespace, "-o", "name"], timeout=30).strip()
        return found == f"secret/{name}"
    wait_until(f"{namespace}/{name} secret synchronization", deadline, check)


def vm_ready(runner: CommandRunner, deadline: float) -> None:
    def check():
        obj = runner.oc_json("read SAW VM", "get", "vm", OWNER, "-n", SAW_NS,
                             timeout=30)
        if obj.get("status", {}).get("ready") is not True:
            return False
        vmi = runner.oc_json("read SAW VMI", "get", "vmi", OWNER, "-n", SAW_NS,
                             timeout=30)
        return vmi.get("status", {}).get("phase") == "Running"
    wait_until("SAW VM readiness", deadline, check)


def ensure_virtctl(runner: CommandRunner, config: dict, work: Path) -> None:
    if shutil.which("virtctl", path=runner.env.get("PATH")):
        return
    item = runner.oc_json("read virtctl download", "get", "consoleclidownload",
                          "virtctl-clidownloads-kubevirt-hyperconverged")
    links = item.get("spec", {}).get("links", [])
    candidates = [link.get("href", "") for link in links
                  if "linux" in link.get("text", "").lower()
                  and any(arch in link.get("text", "").lower() for arch in
                          ("x86_64", "amd64", "x64"))]
    if not candidates:
        candidates = [link.get("href", "") for link in links
                      if "/amd64/linux/" in link.get("href", "")]
    if len(candidates) != 1 or not candidates[0].startswith("https://"):
        raise E2EError("cluster has no single Linux x64 virtctl download")
    try:
        with urllib.request.urlopen(candidates[0], context=ingress_context(runner, config),
                                    timeout=120) as response:
            archive = response.read(100 * 1024 * 1024 + 1)
        if len(archive) > 100 * 1024 * 1024:
            raise E2EError("virtctl download exceeds 100 MiB")
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as bundle:
            binaries = [member for member in bundle.getmembers()
                        if member.isfile() and Path(member.name).name == "virtctl"]
            if len(binaries) != 1:
                raise E2EError("virtctl archive has no single executable")
            binary = bundle.extractfile(binaries[0])
            if binary is None:
                raise E2EError("virtctl executable could not be read")
            target = work / "bin" / "virtctl"
            private_write(target, binary.read())
            target.chmod(0o700)
    except (urllib.error.URLError, tarfile.TarError, OSError) as exc:
        raise E2EError("could not install virtctl from the cluster") from exc
    runner.env["PATH"] = str(target.parent) + os.pathsep + runner.env.get("PATH", "")


def add_guest_key(runner: CommandRunner, work: Path, deadline: float) -> None:
    public = (work / "ssh-key.pub").read_text(encoding="utf-8").strip()
    patch = work / "ssh-pubkey-patch.json"
    private_write(patch, json.dumps({"stringData": {"e2e": public}}).encode())
    runner.run("authorize temporary VM SSH key", ["oc", "patch", "secret",
               f"{OWNER}-ssh-pubkey", "-n", SAW_NS, "--type", "merge",
               "--patch-file", str(patch)], timeout=30)
    def synced():
        vmi = runner.oc_json("read VM key sync", "get", "vmi", OWNER,
                             "-n", SAW_NS, timeout=30)
        return any(item.get("type") == "AccessCredentialsSynchronized"
                   and item.get("status") == "True"
                   for item in vmi.get("status", {}).get("conditions", []))
    wait_until("VM SSH key synchronization", min(deadline, time.monotonic()+180), synced, 5)


def guest(runner: CommandRunner, work: Path, label: str, command: str,
          timeout: float = 120) -> str:
    args = ["virtctl", "-n", SAW_NS, "ssh", f"cloud-user@vm/{OWNER}",
            f"--identity-file={work / 'ssh-key'}",
            "--local-ssh-opts=-oStrictHostKeyChecking=no",
            "--local-ssh-opts=-oUserKnownHostsFile=/dev/null",
            "--local-ssh-opts=-oLogLevel=ERROR",
            "--local-ssh-opts=-oBatchMode=yes", "--command", command]
    return runner.run(label, args, timeout=timeout)


def installer_status(runner: CommandRunner, work: Path, deadline: float) -> dict:
    def check():
        output = guest(runner, work, "read VM installer status",
                       "sudo cat /var/lib/saw/status.json", timeout=40)
        try:
            status = json.loads(output)
        except json.JSONDecodeError:
            return False
        if status.get("install", {}).get("phase") == "Failed" or status.get("apply", {}).get("phase") == "Failed":
            raise E2EError("VM installer reported a failed phase")
        if all(status.get(phase, {}).get("phase") == "Done" for phase in ("install", "apply")):
            return status
        return False
    return wait_until("VM installer phases", deadline, check)


def inspect_guest(runner: CommandRunner, work: Path) -> dict:
    release = guest(runner, work, "read Fedora version",
                    "cat /etc/os-release", timeout=40)
    if "VERSION_ID=44" not in release and 'VERSION_ID="44"' not in release:
        raise E2EError("VM does not run Fedora 44")
    driver = guest(runner, work, "read Podman driver",
                   "grep -F 'compute_driver = \"podman\"' /home/cloud-user/.config/openshell/gateway.toml",
                   timeout=40)
    if 'compute_driver = "podman"' not in driver:
        raise E2EError("gateway does not use the Podman driver")
    versions = {
        "fedora": "44",
        "podman": guest(runner, work, "read Podman version", "podman --version", timeout=40).strip(),
        "openshell": guest(runner, work, "read OpenShell version", "openshell --version", timeout=40).strip(),
        "openclaw": guest(runner, work, "read OpenClaw version",
                          "openshell sandbox exec -n notebook --no-tty -- openclaw --version",
                          timeout=70).strip(),
    }
    bom = yaml.safe_load((ROOT / "charts/openshell-saw/values.yaml").read_text(encoding="utf-8"))["bom"]
    expected = bom["spec"]["openshell"]["cli"]["version"]
    if expected not in versions["openshell"]:
        raise E2EError("installed OpenShell version differs from the BOM")
    if not versions["openclaw"]:
        raise E2EError("OpenClaw did not report a version")
    guest(runner, work, "check OpenClaw gateway",
          "openshell sandbox exec -n notebook --no-tty -- openclaw gateway status",
          timeout=60)
    return versions


def sandbox_command(runner: CommandRunner, work: Path) -> None:
    marker = "SAW_E2E_SANDBOX_OK"
    output = guest(runner, work, "run sandbox command",
                   "openshell sandbox exec -n notebook --no-tty -- printf SAW_E2E_SANDBOX_OK",
                   timeout=90)
    if output.strip() != marker:
        raise E2EError("sandbox command returned an unexpected result")


def openclaw_request(runner: CommandRunner, work: Path, deadline: float) -> None:
    marker = "SAW_E2E_INFERENCE_OK"
    command = ("openshell sandbox exec -n notebook --no-tty -- "
               "openclaw agent --agent main --message "
               "'Reply with exactly SAW_E2E_INFERENCE_OK.' --json")
    output = guest(runner, work, "request NVIDIA inference through OpenClaw",
                   command, timeout=min(180, max(1, deadline - time.monotonic())))
    try:
        response = json.loads(output)
    except json.JSONDecodeError as exc:
        raise E2EError("OpenClaw did not return a completed JSON response") from exc
    if not isinstance(response, dict) or response.get("ok") is False or response.get("status") in ("error", "failed", "timeout", "cancelled"):
        raise E2EError("OpenClaw reported an incomplete inference response")
    payloads = response.get("payloads") or (response.get("result") or {}).get("payloads") or []
    if not any(isinstance(item, dict) and marker in item.get("text", "") for item in payloads):
        raise E2EError("OpenClaw did not return the expected inference marker")


def oidc_host(runner: CommandRunner) -> str:
    keycloak = runner.oc_json("read Keycloak status", "get", "keycloaks",
                              "-n", "saw-keycloak")
    for item in keycloak.get("items", []):
        url = item.get("status", {}).get("externalURL") or item.get("spec", {}).get("hostname", {}).get("hostname")
        if url:
            return urllib.parse.urlparse(url if "://" in url else "https://" + url).hostname or ""
    routes = runner.oc_json("read Keycloak routes", "get", "routes", "-n", "saw-keycloak")
    for item in routes.get("items", []):
        if "keycloak" in item.get("metadata", {}).get("name", ""):
            return item.get("spec", {}).get("host", "")
    raise E2EError("Keycloak has no external route")


def ingress_context(runner: CommandRunner, config: dict) -> ssl.SSLContext:
    ca_file = (config.get("oidc") or {}).get("caFile")
    if ca_file:
        return ssl.create_default_context(cafile=str(ca_file))
    output = runner.run("read public ingress certificate", ["oc", "get", "configmap",
                        "default-ingress-cert", "-n", "openshift-config-managed",
                        "--ignore-not-found", "-o", "json"])
    cert = json.loads(output) if output.strip() else {}
    pem = cert.get("data", {}).get("ca-bundle.crt") or cert.get("data", {}).get("tls.crt")
    if pem:
        return ssl.create_default_context(cadata=pem)
    return ssl.create_default_context()


def obtain_token(runner: CommandRunner, config: dict, password: str) -> tuple[str, str]:
    host = oidc_host(runner)
    url = f"https://{host}/realms/openshell/protocol/openid-connect/token"
    body = urllib.parse.urlencode({"grant_type": "password", "client_id": "openshell-cli",
                                   "username": OWNER, "password": password}).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(request, context=ingress_context(runner, config),
                                    timeout=30) as response:
            token = json.load(response)["access_token"]
    except (urllib.error.URLError, KeyError, ValueError) as exc:
        raise E2EError("noninteractive Keycloak token request failed") from exc
    payload = token.split(".")
    if len(payload) != 3:
        raise E2EError("Keycloak returned an invalid access token")
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload[1] + "=" * (-len(payload[1]) % 4)))
    except (ValueError, TypeError) as exc:
        raise E2EError("Keycloak returned invalid token claims") from exc
    if claims.get("preferred_username") != OWNER or not claims.get("sub"):
        raise E2EError("Keycloak token does not belong to the test owner")
    runner.sensitive.append(token)
    return token, claims["sub"]


def gateway_access(runner: CommandRunner, work: Path, token: str, subject: str) -> None:
    owner = runner.oc_json("read resolved owner", "get", "configmap", "saw-owner-subject",
                           "-n", SAW_NS)
    if owner.get("data", {}).get("subject") != subject:
        raise E2EError("resolved SAW owner differs from the Keycloak token subject")
    route = runner.oc_json("read gateway route", "get", "route", f"{OWNER}-gateway",
                           "-n", SAW_NS)
    host = route.get("spec", {}).get("host")
    if not host:
        raise E2EError("gateway route has no host")
    pem = guest(runner, work, "read public gateway CA",
                "cat /home/cloud-user/.local/state/openshell/tls/ca.crt", timeout=40)
    context = ssl.create_default_context(cadata=pem)
    def status(bearer: str | None) -> int:
        request = urllib.request.Request(f"https://{host}/")
        if bearer:
            request.add_header("Authorization", "Bearer " + bearer)
        try:
            with urllib.request.urlopen(request, context=context, timeout=15) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except urllib.error.URLError as exc:
            raise E2EError("gateway HTTPS access failed") from exc
    if status(None) not in (401, 403):
        raise E2EError("gateway accepted a request without authentication")
    if not 200 <= status(token) < 300:
        raise E2EError("gateway rejected the owner token")


def namespace_names(runner: CommandRunner) -> dict[str, str]:
    return {item["metadata"]["name"]: item["metadata"]["uid"] for item in
            runner.oc_json("read namespaces", "get", "namespaces").get("items", [])}


def cleanup_run(runner: CommandRunner, inventory: dict, state_dir: Path,
                work: Path, *, release: bool = True) -> None:
    deadline = time.monotonic() + CLEANUP_SECONDS
    inventory["cleanup_status"] = "running"
    write_reports(inventory, state_dir)
    update_lock(runner, inventory)
    failures: list[str] = []
    branch = inventory.get("source_branch", "")
    pattern = pattern_environment(runner, work, branch)
    if inventory.get("pattern_attempted"):
        try:
            stage(inventory, state_dir, "cleanup.pattern", lambda: pattern.run(
                "uninstall minimal Pattern", ["./pattern.sh", "make", "uninstall"],
                timeout=max(1, deadline - time.monotonic())))
        except E2EError as exc:
            failures.append(str(exc))
    if not failures:
        try:
            current = namespace_names(runner)
            baseline = inventory.get("baseline", {}).get("namespaces", {})
            targets = (SAW_NS, "openshell-agents", "vault", "external-secrets",
                       "saw-keycloak", "external-secrets-operator", "openshift-cnv",
                       "vp-gitops", "patterns-operator", "imperative")
            for name in targets:
                if name in baseline:
                    if name not in current or current[name] != baseline[name]:
                        raise E2EError(f"pre-existing namespace {name} changed during cleanup")
                    continue
                if name not in current:
                    continue
                if name == SAW_NS:
                    obj = runner.oc_json("check SAW namespace ownership", "get", "namespace", name)
                    labels = obj.get("metadata", {}).get("labels", {})
                    if labels.get("openshell.pattern/owner") != OWNER:
                        raise E2EError("SAW namespace lacks expected ownership label")
                runner.run(f"delete test namespace {name}",
                           ["oc", "delete", "namespace", name, "--wait=false"], timeout=30)
            def namespaces_absent():
                current_names = namespace_names(runner)
                return all(name in baseline or name not in current_names for name in targets)
            wait_until("test namespace removal", deadline, namespaces_absent, 10)
        except E2EError as exc:
            failures.append(str(exc))
    if inventory.get("mirror_attempted") and not inventory.get("baseline", {}).get("registry_default_route"):
        try:
            runner.run("restore image registry route", ["oc", "patch",
                "configs.imageregistry.operator.openshift.io/cluster", "--type=merge",
                "--patch", '{"spec":{"defaultRoute":false}}'], timeout=30)
        except E2EError as exc:
            failures.append(str(exc))
    if not failures:
        try:
            pattern_exists = subprocess.run(["scripts/pattern-exists.sh"], cwd=ROOT,
                                            env=runner.env, capture_output=True,
                                            text=True, check=False)
            if pattern_exists.returncode != 1:
                raise E2EError("SAW Pattern remains after cleanup")
            if release:
                inventory["cleanup_status"] = "complete"
                inventory["finished_at"] = now()
                write_reports(inventory, state_dir)
                update_lock(runner, inventory)
                release_lock(runner, inventory)
        except E2EError as exc:
            failures.append(str(exc))
    if failures:
        inventory["cleanup_status"] = "failed"
        inventory["cleanup_errors"] = failures
        write_reports(inventory, state_dir)
        update_lock(runner, inventory)
        raise E2EError("cleanup failed; the cluster lock remains: " + "; ".join(failures))


def execute_run(config_path: Path, *, retain: bool = False) -> int:
    config = load_config(config_path, require_key=True)
    run_id = now().replace(":", "").replace("-", "") + "-" + uuid.uuid4().hex[:8]
    state_dir, work, env = prepare_workspace(config, run_id)
    runner = CommandRunner(env, [str(config["cluster"].get("password", "")),
                                 str(config["inference"].get("apiKey", ""))])
    inventory = {
        "run_id": run_id, "started_at": now(), "source_sha": "",
        "source_branch": "", "cluster_context": "",
        "provider": "nvidia", "driver": "podman", "model": config["inference"]["model"],
        "image_digests": {}, "installed_versions": {}, "stages": [],
        "coverage": {"tested": ["OpenShift Virtualization", "Fedora 44", "Podman",
                                "OpenClaw", "NVIDIA", "Keycloak/OIDC", "Vault",
                                "External Secrets"],
                     "future": ["Codex", "Anthropic", "Kubernetes driver", "SPIRE", "RPM"]},
        "status": "running", "cleanup_status": "pending", "pattern_attempted": False,
        "mirror_attempted": False, "baseline": {},
    }
    write_reports(inventory, state_dir)
    deployment_deadline = time.monotonic() + DEPLOY_SECONDS
    locked = False
    error = ""
    try:
        stage(inventory, state_dir, "preflight.selection", checked_in_selection)
        inventory["cluster_context"] = stage(inventory, state_dir,
            "preflight.login", lambda: login_cluster(runner, config), runner.sensitive)
        inventory["image_digests"] = stage(inventory, state_dir,
            "preflight.pinned-images", pinned_image_digests)
        sha, branch = stage(inventory, state_dir, "preflight.source", lambda: source_identity(runner))
        inventory["source_sha"], inventory["source_branch"] = sha, branch
        baseline = stage(inventory, state_dir, "preflight.cluster",
                         lambda: preflight_cluster(runner, config))
        inventory["baseline"] = baseline
        stage(inventory, state_dir, "cluster.lock", lambda: create_lock(runner, inventory))
        locked = True
        topology = stage(inventory, state_dir, "preflight.network",
                         lambda: discover_topology(runner, work, deployment_deadline))
        topology["clusterDomain"] = baseline["ingress_domain"]
        runtime = runtime_values(config, topology, "sha256:" + "0" * 64)
        runtime_file = write_runtime(work, runtime)
        def validate_render():
            values = render_children(runner, runtime_file, sha)
            render_charts(runner, values, work)
        stage(inventory, state_dir, "preflight.render", validate_render)
        _, password = stage(inventory, state_dir, "prepare.private-inputs",
                            lambda: generate_inputs(runner, config, work))
        pattern = pattern_environment(runner, work, branch)
        stage(inventory, state_dir, "preflight.pattern-render",
              lambda: pattern_show(pattern, deployment_deadline))
        inventory["mirror_attempted"] = True
        update_lock(runner, inventory)
        digest = stage(inventory, state_dir, "image.mirror",
                       lambda: mirror_image(runner, deployment_deadline))
        inventory["image_digests"]["golden_vm"] = digest
        runtime = runtime_values(config, topology, digest)
        write_runtime(work, runtime)
        stage(inventory, state_dir, "preflight.final-render", validate_render)
        stage(inventory, state_dir, "preflight.final-pattern-render",
              lambda: pattern_show(pattern, deployment_deadline))
        inventory["pattern_attempted"] = True
        update_lock(runner, inventory)
        stage(inventory, state_dir, "pattern.install", lambda: pattern.run(
            "install minimal Pattern", ["./pattern.sh", "make", "install"],
            timeout=max(1, deployment_deadline - time.monotonic())))
        (work / "nvidia-key").unlink(missing_ok=True)
        stage(inventory, state_dir, "pattern.selection",
              lambda: post_deploy_selection(runner, baseline))
        stage(inventory, state_dir, "gitops.parent-health",
              lambda: application_health(runner, EXPECTED_APPS, sha, deployment_deadline))
        stage(inventory, state_dir, "gitops.child-health",
              lambda: application_health(runner, EXPECTED_CHILD_APPS, sha, deployment_deadline))
        stage(inventory, state_dir, "vm.virtctl",
              lambda: ensure_virtctl(runner, config, work))
        stage(inventory, state_dir, "secret.keycloak",
              lambda: secret_ready(runner, "saw-keycloak",
                                   "openshell-keycloak-user-passwords", deployment_deadline))
        stage(inventory, state_dir, "secret.inference",
              lambda: secret_ready(runner, SAW_NS, "inference", deployment_deadline))
        stage(inventory, state_dir, "vm.ready",
              lambda: vm_ready(runner, deployment_deadline))
        stage(inventory, state_dir, "vm.ssh-key",
              lambda: add_guest_key(runner, work, deployment_deadline))
        stage(inventory, state_dir, "vm.installer",
              lambda: installer_status(runner, work, deployment_deadline))
        inventory["installed_versions"] = stage(inventory, state_dir, "vm.versions",
                                                 lambda: inspect_guest(runner, work))
        token, subject = stage(inventory, state_dir, "identity.token",
                               lambda: obtain_token(runner, config, password))
        (work / "keycloak-password").unlink(missing_ok=True)
        stage(inventory, state_dir, "identity.gateway",
              lambda: gateway_access(runner, work, token, subject))
        stage(inventory, state_dir, "sandbox.command",
              lambda: sandbox_command(runner, work))
        stage(inventory, state_dir, "openclaw.inference",
              lambda: openclaw_request(runner, work, deployment_deadline))
        inventory["status"] = "passed"
    except BaseException as exc:
        inventory["status"] = "failed"
        error = clean_message(str(exc), runner.sensitive)
        inventory["error"] = error
    finally:
        inventory["finished_at"] = now()
        write_reports(inventory, state_dir)
        if locked:
            try:
                if retain or config.get("cleanup") == "retain":
                    inventory["cleanup_status"] = "retained"
                    update_lock(runner, inventory)
                else:
                    cleanup_run(runner, inventory, state_dir, work)
            except BaseException as exc:
                inventory["status"] = "failed"
                error = clean_message(str(exc), runner.sensitive)
                inventory["error"] = error
                inventory["cleanup_status"] = "failed"
        write_reports(inventory, state_dir)
        shutil.rmtree(work)
    _, report, junit = report_paths(state_dir, run_id)
    print(f"Run {run_id}: {inventory['status']}; cleanup: {inventory['cleanup_status']}")
    print(f"JSON report: {report}")
    print(f"JUnit report: {junit}")
    if error:
        print("Error: " + error, file=sys.stderr)
    return 0 if inventory["status"] == "passed" and inventory["cleanup_status"] in ("complete", "retained") else 1


def execute_cleanup(config_path: Path) -> int:
    config = load_config(config_path, require_key=False)
    run_id = "recovery-" + uuid.uuid4().hex[:8]
    state_dir, work, env = prepare_workspace(config, run_id)
    runner = CommandRunner(env, [str(config["cluster"].get("password", ""))])
    try:
        login_cluster(runner, config)
        inventory = read_lock(runner)
        branch = inventory.get("source_branch", "")
        if not branch:
            raise E2EError("cluster lock has no source branch")
        # The cleanup path needs the checkout and Pattern scripts. It does
        # not need the engineer's API key or the original test password.
        private_write(work / "values-secret.yaml", b"version: '2.0'\nbackingStore: vault\nsecrets: []\n")
        write_runtime(work, {})
        cleanup_run(runner, inventory, state_dir, work)
        print(f"Cleaned run {inventory['run_id']}; cluster lock released.")
        return 0
    except E2EError as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(work)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="deploy, check, and clean up")
    run.add_argument("--config", default=os.environ.get("E2E_CONFIG"))
    run.add_argument("--retain", action="store_true", help="keep resources and lock for inspection")
    cleanup = commands.add_parser("cleanup", help="remove resources from a retained or failed run")
    cleanup.add_argument("--config", default=os.environ.get("E2E_CONFIG"))
    args = parser.parse_args(argv)
    if not args.config:
        parser.error("--config or E2E_CONFIG is required")
    try:
        if args.command == "run":
            return execute_run(Path(args.config), retain=args.retain)
        return execute_cleanup(Path(args.config))
    except (E2EError, OSError, yaml.YAMLError) as exc:
        print("Error: " + clean_message(str(exc), []), file=sys.stderr)
        return 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda _signal, _frame: (_ for _ in ()).throw(KeyboardInterrupt()))
    sys.exit(main())
