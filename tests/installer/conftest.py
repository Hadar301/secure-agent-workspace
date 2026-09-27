"""Fixtures for the in-guest installer tests.

The installer is exercised for real (real subprocesses, real files) against
fake `podman`, `openshell`, `nemoclaw` and `sudo` executables placed first on
PATH. No cluster, VM, network or credentials are used.
"""

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "openshell-saw"
SCRIPT = CHART / "files" / "installer" / "apply_bom.py"
PROFILES = ROOT / "charts" / "saw-bom" / "profiles"
FAKES = Path(__file__).resolve().parent / "fakes"
GATEWAY_ENV = "OPENSHELL_SERVER_PORT=17670\nOPENSHELL_ENABLE_MTLS_AUTH=true\n"
GATEWAY_TOML = '[openshell.drivers.podman]\nsupervisor_image = "quay.io/x/supervisor@sha256:abc"\n'


def _load_module():
    spec = importlib.util.spec_from_file_location("apply_bom", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["apply_bom"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def ab():
    return _load_module()


@pytest.fixture
def chart_bom():
    """The BOM shipped as the chart default."""
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    return values["bom"]


@pytest.fixture
def bom(chart_bom):
    """The chart BOM with only the three OpenShell components; tests that
    need the optional NemoClaw CLI add it themselves."""
    doc = json.loads(json.dumps(chart_bom))
    doc["spec"].pop("nemoclaw", None)
    return doc


def profile_files(profile="data-science"):
    """Flatten a saw-bom profile exactly like templates/configmap-bom.yaml."""
    files = {}
    for path in sorted((PROFILES / profile).rglob("*.yaml")):
        rel = path.relative_to(PROFILES.parent)  # profiles/<profile>/<ws>/<file>
        files[str(rel).replace("/", "__")] = path.read_text()
    return files


@pytest.fixture
def shipped_profile_files():
    return profile_files()


@pytest.fixture
def fake_env(tmp_path, monkeypatch):
    """Put fake executables first on PATH and give them a state directory."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    for fake in FAKES.iterdir():
        target = bin_dir / fake.name
        target.write_text(fake.read_text())
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    state = tmp_path / "fakestate"
    state.mkdir()
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_STATE", str(state))
    monkeypatch.setenv("FAKE_PYTHON", sys.executable)
    return FakeWorld(state)


class FakeWorld:
    """Helpers to configure and inspect the fakes."""

    def __init__(self, state):
        self.state = state

    # podman -------------------------------------------------------------
    def set_images(self, images):
        (self.state / "images.json").write_text(json.dumps(images))

    def images_for_bom(self, bom, version=None, nemoclaw=True):
        images = {}
        paths = {"gateway": "/usr/local/bin/openshell-gateway",
                 "supervisor": "/openshell-sandbox",
                 "cli": "/usr/local/bin/openshell"}
        for comp, entry in bom["spec"]["openshell"].items():
            images[entry["image"]] = {paths[comp]: {"type": "binary",
                                                    "version": version or entry["version"]}}
        if nemoclaw and "nemoclaw" in bom["spec"]:
            images[bom["spec"]["nemoclaw"]["cliImage"]] = {"/opt/nemoclaw": {"type": "nemoclaw"}}
        self.set_images(images)
        return images

    def podman_calls(self):
        log = self.state / "podman.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    # openshell ------------------------------------------------------------
    def openshell_state(self):
        path = self.state / "openshell.json"
        return json.loads(path.read_text()) if path.exists() else None

    def set_openshell_state(self, data):
        (self.state / "openshell.json").write_text(json.dumps(data))

    def openshell_calls(self):
        log = self.state / "openshell.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def deny(self, *operations):
        (self.state / "deny.json").write_text(json.dumps(list(operations)))

    def other_calls(self, name):
        log = self.state / f"{name}.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


@pytest.fixture
def secrets_dir(tmp_path):
    """Provider Secrets as the VM sees them: /run/saw/secrets/<secret>/<key>."""
    base = tmp_path / "secrets"
    for secret, data in {"inference": {"api_key": "nvapi-TEST-KEY-123", "provider": "build"},
                         "web-search": {"api_key": "brave-TEST-KEY-456"}}.items():
        (base / secret).mkdir(parents=True)
        for key, value in data.items():
            (base / secret / key).write_text(value + "\n")
    return base


@pytest.fixture
def config():
    return {"vmName": "saw-test", "namespace": "openshell-agents",
            "runtimeUser": "cloud-user", "mtlsGateway": "openshell",
            "ownerSubject": "", "oidcIssuer": "", "sandboxDashboardRoute": "",
            "dashboard": {"enabled": False}}


@pytest.fixture
def inputs_dir(tmp_path, bom, config, shipped_profile_files, secrets_dir):
    """A complete /run/saw tree built from the real chart files."""
    root = tmp_path / "run-saw"
    installer = root / "installer"
    installer.mkdir(parents=True)
    bom["spec"]["nemoclaw"] = {"cliImage": "quay.io/example/nemoclaw-cli@sha256:" + "e" * 64}
    (installer / "installer-bom.yaml").write_text(yaml.safe_dump(bom))
    (installer / "config.json").write_text(json.dumps(config))
    (installer / "apply_bom.py").write_text(SCRIPT.read_text())
    (installer / "gateway.env").write_text(GATEWAY_ENV)
    (installer / "gateway.toml").write_text(GATEWAY_TOML)
    (installer / "setup-dashboard.sh").write_text(
        (CHART / "files" / "installer" / "setup-dashboard.sh").read_text())
    profiles = root / "profiles"
    profiles.mkdir()
    for key, text in shipped_profile_files.items():
        (profiles / key).write_text(text)
    secrets_dir.rename(root / "secrets")
    return root
