"""GitHub and OpenShift must build the same reviewed MCPorter dependency graph."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "image-builder-charts/helm/nemoclaw-imagestream"
RUNTIME = CHART / "files/mcporter-runtime"
CLI_CHART = ROOT / "image-builder-charts/helm/nemoclaw-cli-imagestream"
HELM = shutil.which("helm")


def test_github_supplies_the_same_reviewed_runtime(tmp_path):
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-nemoclaw-sandbox.yml").read_text())
    injection = next(s["run"] for s in workflow["jobs"]["build"]["steps"]
                     if "install-reviewed-runtime.sh" in s.get("run", ""))
    target = tmp_path / "agents/openclaw/mcporter-runtime"
    target.mkdir(parents=True)
    for name in ("package.json", "package-lock.json"):
        (target / name).write_text("old upstream graph")
    subprocess.run(["bash", "-eu", "-c", injection], cwd=ROOT,
                   env=dict(os.environ, UPSTREAM_DIR=str(tmp_path), BASH_ENV="/dev/null"), check=True)
    for name in ("package.json", "package-lock.json"):
        assert (target / name).read_bytes() == (RUNTIME / name).read_bytes()


def test_reviewed_lock_contains_fixed_dependencies():
    manifest = json.loads((RUNTIME / "package.json").read_text())
    lock = json.loads((RUNTIME / "package-lock.json").read_text())
    for package, minimum in (("@modelcontextprotocol/sdk", (1, 31, 0)),
                             ("fast-uri", (3, 1, 7)), ("proxy-addr", (2, 0, 8))):
        version = lock["packages"][f"node_modules/{package}"]["version"]
        assert manifest["overrides"][package] == version
        assert tuple(map(int, version.split("."))) >= minimum


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_openshift_supplies_the_reviewed_runtime_to_the_upstream_dockerfile():
    rendered = subprocess.check_output([HELM, "template", "image", str(CHART)], text=True)
    resources = [d for d in yaml.safe_load_all(rendered) if d]
    build = next(d for d in resources if d["kind"] == "BuildConfig")
    source = next(s for s in build["spec"]["source"]["configMaps"]
                  if s["destinationDir"] == "agents/openclaw/mcporter-runtime")
    config = next(d for d in resources if d["kind"] == "ConfigMap"
                  and d["metadata"]["name"] == source["configMap"]["name"])
    for name in ("package.json", "package-lock.json"):
        assert config["data"][name] == (RUNTIME / name).read_text()
    assert build["spec"]["strategy"]["dockerStrategy"]["dockerfilePath"] == "Dockerfile"


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_cli_builds_share_one_dockerfile_and_values():
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-nemoclaw-cli.yml").read_text())
    action = next(s for s in workflow["jobs"]["build"]["steps"] if "with" in s)
    shared = ROOT / action["with"]["dockerfile"]
    assert shared == CLI_CHART / "files/Dockerfile"
    rendered = subprocess.check_output([HELM, "template", "image", str(CLI_CHART),
        "--set", "build.nodeImage=node:test", "--set", "build.maxOpenshellVersion=0.0.123"], text=True)
    build = next(d for d in yaml.safe_load_all(rendered) if d and d["kind"] == "BuildConfig")
    assert build["spec"]["source"]["dockerfile"].rstrip() == shared.read_text().rstrip()
    args = {a["name"]: a["value"] for a in build["spec"]["strategy"]["dockerStrategy"]["buildArgs"]}
    assert args == {"NODE_IMAGE": "node:test", "MAX_OPENSHELL_VERSION": "0.0.123"}


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_discovery_runtime_script_is_shared():
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-nemoclaw-sandbox.yml").read_text())
    injection = next(s["run"] for s in workflow["jobs"]["build"]["steps"]
                     if "install-reviewed-runtime.sh" in s.get("run", ""))
    shared = CHART / "files/install-reviewed-runtime.sh"
    assert str(shared.relative_to(ROOT)) in injection
    rendered = subprocess.check_output([HELM, "template", "image", str(CHART)], text=True)
    config = next(d for d in yaml.safe_load_all(rendered)
                  if d and d["kind"] == "ConfigMap" and d["metadata"]["name"] == "nemoclaw-audit-patch")
    assert config["data"]["install-reviewed-runtime.sh"] == shared.read_text()
