"""charts/openshell-keycloak: own Keycloak, or only the realm for an existing one."""
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "openshell-keycloak"
HELM = shutil.which("helm")
pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")


def render(*args):
    out = subprocess.run([HELM, "template", "openshell-keycloak", str(CHART), "-n", "keycloak", *args],
                         capture_output=True, text=True, check=True).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def test_default_deploys_keycloak_database_and_realm():
    docs = render()
    kinds = {d["kind"] for d in docs}
    assert {"Keycloak", "KeycloakRealmImport", "Deployment"} <= kinds
    (realm,) = [d for d in docs if d["kind"] == "KeycloakRealmImport"]
    assert realm["spec"]["keycloakCRName"] == "openshell-keycloak"


def test_existing_mode_imports_only_the_realm_into_that_keycloak():
    docs = render("--set", "keycloak.existing=keycloak", "--set", "keycloak.realm=openshell")
    assert [d["kind"] for d in docs] == ["KeycloakRealmImport"]
    spec = docs[0]["spec"]
    assert spec["keycloakCRName"] == "keycloak"
    assert spec["realm"]["realm"] == "openshell"
    clients = {c["clientId"]: c for c in spec["realm"]["clients"]}
    assert clients["openshell-cli"]["publicClient"] is True
    assert {"openshell-admin", "openshell-user"} <= {r["name"] for r in spec["realm"]["roles"]["realm"]}
