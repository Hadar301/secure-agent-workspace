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


def test_client_lists_are_never_null(tmp_path):
    """Found live (Helm 4, server-side apply): the dashboard client's empty
    redirectUris/webOrigins rendered as null and the CRD rejected the import."""
    with_uri = tmp_path / "with-uri.yaml"
    with_uri.write_text("keycloak:\n  existing: keycloak\n  clients:\n    dashboard:\n"
                        "      redirectUris: [https://a.example.com/oauth2/callback]\n")
    for args in ((), ("--set", "keycloak.existing=keycloak"), ("-f", str(with_uri))):
        (realm,) = [d for d in render(*args) if d["kind"] == "KeycloakRealmImport"]
        for client in realm["spec"]["realm"]["clients"]:
            for key in ("redirectUris", "webOrigins"):
                assert isinstance(client.get(key), list), (args, client["clientId"], key)
    (realm,) = render("-f", str(with_uri))
    dash = next(c for c in realm["spec"]["realm"]["clients"] if c["clientId"] == "openshell-dashboard")
    assert dash["redirectUris"] == ["https://a.example.com/oauth2/callback"]


def test_no_test_users_and_users_without_roles_render_valid_lists(tmp_path):
    values = tmp_path / "users.yaml"
    values.write_text("keycloak:\n  testUsers:\n    - username: nobody\n      password: x\n")
    (realm,) = [d for d in render("-f", str(values)) if d["kind"] == "KeycloakRealmImport"]
    assert realm["spec"]["realm"]["users"][0]["realmRoles"] == []
    empty = tmp_path / "empty.yaml"
    empty.write_text("keycloak:\n  testUsers: []\n")
    (realm,) = [d for d in render("-f", str(empty)) if d["kind"] == "KeycloakRealmImport"]
    assert realm["spec"]["realm"]["users"] == []
