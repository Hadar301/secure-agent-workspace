"""The self-service portal's pipeline and plugin generator (charts/openshell-rhdh/files/portal.py).

Runs portal.py against small fake Kubernetes and Vault HTTP servers, with
Backstage tokens signed by a throwaway P-256 key.
"""
import base64
import importlib.util
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
PORTAL = ROOT / "charts" / "openshell-rhdh" / "files" / "portal.py"
CATALOG = ROOT / "charts" / "openshell-rhdh" / "files" / "profile-catalog.json"

from cryptography.hazmat.primitives import hashes  # noqa: E402  (tests/requirements.txt)
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402


@pytest.fixture(scope="module")
def portal():
    spec = importlib.util.spec_from_file_location("portal", PORTAL)
    module = importlib.util.module_from_spec(spec)
    sys.modules["portal"] = module
    spec.loader.exec_module(module)
    return module


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Signer:
    def __init__(self, kid="k1"):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid = kid

    def jwks(self):
        nums = self.key.public_key().public_numbers()
        return {"keys": [{"kty": "EC", "crv": "P-256", "kid": self.kid,
                          "x": b64u(nums.x.to_bytes(32, "big")), "y": b64u(nums.y.to_bytes(32, "big"))}]}

    def sign(self, header, payload):
        h = b64u(json.dumps({"kid": self.kid, **header}).encode())
        pl = b64u(json.dumps(payload).encode())
        der = self.key.sign(f"{h}.{pl}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return f"{h}.{pl}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def token(self, sub="user:default/alice", exp=None, alg="ES256"):
        """A full user token (older backends), signed by the auth backend."""
        return self.sign({"alg": alg, "typ": "vnd.backstage.user"},
                         {"sub": sub, "iss": "https://rhdh.example.com/api/auth", "aud": "backstage",
                          "exp": exp or int(time.time()) + 600})

    def limited(self, sub="user:default/alice", exp=None):
        """A limited user token: {sub, iat, exp} only (UserTokenHandler)."""
        now = int(time.time())
        return self.sign({"alg": "ES256", "typ": "vnd.backstage.limited-user"},
                         {"sub": sub, "iat": now, "exp": exp or now + 600})


def plugin_token(scaffolder, obo, sub="scaffolder", aud="catalog"):
    """What the new backend's scaffolder puts in secrets.backstageToken: a
    plugin token signed by the scaffolder, acting on behalf of the user."""
    now = int(time.time())
    return scaffolder.sign({"alg": "ES256", "typ": "vnd.backstage.plugin"},
                           {"sub": sub, "aud": aud, "iat": now, "exp": now + 600, "obo": obo})


# -- token verification (pure-Python ES256) -------------------------------------------

def test_a_full_user_token_names_its_user(portal):
    signer = Signer()
    assert portal.verify_backstage_token(signer.token(), signer.jwks()) == "alice"


def test_the_scaffolders_plugin_token_names_the_user_it_acts_for(portal):
    auth, scaffolder = Signer("auth"), Signer("scaffolder")
    token = plugin_token(scaffolder, auth.limited())
    assert portal.verify_backstage_token(token, auth.jwks(), scaffolder.jwks()) == "alice"


@pytest.mark.parametrize("make, message", [
    (lambda auth, sc: plugin_token(Signer("x"), auth.limited()), "scaffolder token: its signing key"),
    (lambda auth, sc: plugin_token(sc, Signer("auth").limited()), "user token: the signature"),
    (lambda auth, sc: plugin_token(sc, auth.limited(), sub="catalog"), "not the scaffolder"),
    (lambda auth, sc: plugin_token(sc, auth.limited(), aud="scaffolder"), "not the scaffolder"),
    (lambda auth, sc: plugin_token(sc, ""), "does not act for a user"),
    (lambda auth, sc: plugin_token(sc, auth.limited(sub="group:default/admins")), "not for a user"),
    (lambda auth, sc: plugin_token(sc, auth.limited(exp=int(time.time()) - 5)), "expired"),
])
def test_bad_plugin_tokens_are_refused(portal, make, message):
    auth, scaffolder = Signer("auth"), Signer("scaffolder")
    with pytest.raises(portal.PortalError, match=message):
        portal.verify_backstage_token(make(auth, scaffolder), auth.jwks(), scaffolder.jwks())


@pytest.mark.parametrize("mutate, message", [
    (lambda s: s.token(exp=int(time.time()) - 5), "expired"),
    (lambda s: s.token(sub="user:default/bob")[:-4] + "AAAA", "signature is not valid"),
    (lambda s: s.token(sub="group:default/admins"), "not for a user"),
    (lambda s: s.token(alg="HS256"), "unsupported algorithm"),
    (lambda s: "not-a-jwt", "not a JWT"),
])
def test_bad_tokens_are_refused(portal, mutate, message):
    signer = Signer()
    with pytest.raises(portal.PortalError, match=message):
        portal.verify_backstage_token(mutate(signer), signer.jwks())


def test_a_token_from_another_key_is_refused(portal):
    signer, other = Signer(), Signer()
    with pytest.raises(portal.PortalError, match="signature is not valid"):
        portal.verify_backstage_token(other.token(), signer.jwks())


def test_a_payload_edited_after_signing_is_refused(portal):
    """Changing sub to someone else breaks the signature."""
    signer = Signer()
    header, _, sig = signer.token().split(".")
    forged = b64u(json.dumps({"sub": "user:default/bob", "exp": int(time.time()) + 600}).encode())
    # (same header, same signature, another user)
    with pytest.raises(portal.PortalError, match="signature is not valid"):
        portal.verify_backstage_token(f"{header}.{forged}.{sig}", signer.jwks())


# -- the form -------------------------------------------------------------------------

@pytest.fixture(scope="module")
def catalog(portal):
    return portal.load_catalog(CATALOG)


def test_a_request_gets_the_profiles_secrets(portal, catalog):
    profile, secrets = portal.parse_request({
        "profile": "data-science", "inference.api_key": " nvapi-1 ", "web-search.api_key": "brave-1",
        "inference.url": "https://ignored/v1"}, catalog)
    assert profile == "data-science"
    assert secrets == {"inference": {"api_key": "nvapi-1", "provider": "nvidia"},
                       "web-search": {"api_key": "brave-1", "provider": "brave"}}


def test_missing_fields_are_named(portal, catalog):
    with pytest.raises(portal.PortalError, match="needs: inference.api_key, inference.url, inference.model"):
        portal.parse_request({"profile": "custom-inference", "web-search.api_key": "b"}, catalog)


def test_a_url_with_credentials_is_refused(portal, catalog):
    with pytest.raises(portal.PortalError, match="must be an http"):
        portal.parse_request({"profile": "custom-inference", "inference.api_key": "k",
                              "inference.url": "https://user:pw@vllm/v1", "inference.model": "m",
                              "web-search.api_key": "b"}, catalog)


def test_an_unknown_profile_is_refused(portal, catalog):
    with pytest.raises(portal.PortalError, match="unknown profile"):
        portal.parse_request({"profile": "nope"}, catalog)


@pytest.mark.parametrize("user", ["Alice", "a.b", "x" * 20, "", "alice-bom", "alice-secrets"])
def test_user_names_must_name_a_vm(portal, user):
    with pytest.raises(portal.PortalError, match="cannot name a workspace"):
        portal.check_user(user)


# -- generator and catalog entities -----------------------------------------------------

def test_generator_params_are_one_user_saw_users_values(portal):
    defaults = {"global": {"repoURL": "r"}, "namespaceLabels": {"saw.redhat.com/portal": "true"}}
    ws = {"name": "alice", "profiles": ["data-science"], "vaultPrefix": "secret/data/hub/saw-alice"}
    [params] = portal.generator_params([ws], defaults)
    assert params["name"] == "alice"
    assert json.loads(params["values"]) == {**defaults, "users": [ws]}


def test_entities_link_the_web_uis(portal, catalog):
    text = portal.entities_yaml([{"name": "alice", "profiles": ["data-science"]}], catalog,
                                "example.com", "https://rhdh.example.com")
    entity = json.loads(text)
    assert entity["spec"]["owner"] == "user:default/alice"
    urls = [link["url"] for link in entity["metadata"]["links"]]
    assert "https://alice-webui-saw-alice.apps.example.com" in urls
    assert "https://alice-default-notebook-ui.apps.example.com" in urls


def test_no_workspaces_is_still_a_valid_location(portal, catalog):
    assert portal.entities_yaml([], catalog, "example.com", "").startswith("#")


# -- end to end against fake Kubernetes and Vault -------------------------------------

class Fake:
    """A tiny Kubernetes (secrets, configmaps, namespaces) and Vault."""

    def __init__(self):
        self.objects = {}      # path -> object
        self.deleted = []
        self.vault = {}        # kv path -> data
        self.logins = []

    def serve(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def _reply(self, code, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n)) if n else None

            def do_GET(self):
                url = urlsplit(self.path)
                if (url.path.endswith("/configmaps") or url.path.endswith("/secrets")) and "labelSelector" in url.query:
                    sel = parse_qs(url.query)["labelSelector"][0].split("=")
                    items = [o for p, o in fake.objects.items() if p.startswith(url.path + "/")
                             and (o["metadata"].get("labels") or {}).get(sel[0]) == sel[1]]
                    return self._reply(200, {"items": items})
                obj = fake.objects.get(url.path)
                self._reply(200, obj) if obj else self._reply(404, {"reason": "NotFound"})

            def do_POST(self):
                body = self._body()
                if self.path.startswith("/v1/auth/"):
                    fake.logins.append(body)
                    return self._reply(200, {"auth": {"client_token": "vault-token"}})
                if self.path.startswith("/v1/secret/data/"):
                    assert self.headers["X-Vault-Token"] == "vault-token"
                    fake.vault[self.path[len("/v1/secret/data/"):]] = body["data"]
                    return self._reply(200, {})
                fake.objects[f"{self.path}/{body['metadata']['name']}"] = body
                self._reply(201, body)

            def do_PUT(self):
                fake.objects[self.path] = self._body()
                self._reply(200, fake.objects[self.path])

            def do_DELETE(self):
                if self.path.startswith("/v1/secret/metadata/"):
                    fake.vault.pop(self.path[len("/v1/secret/metadata/"):], None)
                    return self._reply(204)
                fake.deleted.append(self.path)
                self._reply(200 if fake.objects.pop(self.path, None) else 404, {})

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}"

    def request(self, name, data, age=0, labels=None):
        created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - age))
        self.objects[f"/api/v1/namespaces/saw-portal/secrets/{name}"] = {
            "metadata": {"name": name, "labels": {"saw.redhat.com/request": "true"} if labels is None else labels,
                         "creationTimestamp": created},
            "data": {k: base64.b64encode(v.encode()).decode() for k, v in data.items()}}


@pytest.fixture
def world(portal, monkeypatch, tmp_path):
    fake = Fake()
    server, url = fake.serve()
    auth, scaffolder = Signer("auth"), Signer("scaffolder")
    sa = tmp_path / "sa"
    sa.mkdir()
    (sa / "token").write_text("pod-sa-token")
    monkeypatch.setattr(portal, "SA_DIR", str(sa))
    monkeypatch.setattr(portal, "kube", lambda: portal.Http(url, "k8s-token"))
    monkeypatch.setattr(portal, "fetch_json", lambda u, insecure=False:
                        scaffolder.jwks() if "/api/scaffolder/" in u else auth.jwks())
    for k, v in {"NAMESPACE": "saw-portal", "CATALOG_PATH": str(CATALOG), "RHDH_INTERNAL_URL": "http://rhdh",
                 "ARGO_NAMESPACE": "vp-gitops",
                 "VAULT_ADDR": url, "VAULT_AUTH_MOUNT": "hub", "VAULT_ROLE": "saw-portal-writer",
                 "VAULT_KV_MOUNT": "secret", "VAULT_PREFIX_BASE": "hub"}.items():
        monkeypatch.setenv(k, v)
    yield fake, Tokens(auth, scaffolder)
    server.shutdown()


class Tokens:
    def __init__(self, auth, scaffolder):
        self.auth, self.scaffolder = auth, scaffolder

    def token(self, sub="user:default/alice"):
        return plugin_token(self.scaffolder, self.auth.limited(sub=sub))


def ds_request(signer, **extra):
    return {"action": "create", "token": signer.token(), "profile": "data-science",
            "inference.api_key": "nvapi-1", "web-search.api_key": "brave-1", **extra}


def test_create_writes_vault_and_the_registry(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    assert fake.vault == {"hub/saw-alice/inference": {"api_key": "nvapi-1", "provider": "nvidia"},
                          "hub/saw-alice/web-search": {"api_key": "brave-1", "provider": "brave"}}
    assert fake.logins == [{"role": "saw-portal-writer", "jwt": "pod-sa-token"}]
    cm = fake.objects["/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice"]
    assert cm["metadata"]["labels"]["saw.redhat.com/workspace"] == "true"
    assert json.loads(cm["data"]["user.json"]) == {
        "name": "alice", "profiles": ["data-science"], "ownerSubject": "",
        "vaultPrefix": "secret/data/hub/saw-alice", "pruneOnRemove": True}
    assert "/api/v1/namespaces/saw-portal/secrets/saw-req-1" not in fake.objects, "request consumed"


def test_the_owner_comes_from_the_token_not_the_form(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer, owner="bob"))
    assert portal.main(["create", "saw-req-1"]) == 0
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice" in fake.objects
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-bob" not in fake.objects


def test_a_forged_request_changes_nothing_and_is_consumed(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(Tokens(Signer("x"), Signer("y"))))
    assert portal.main(["create", "saw-req-1"]) == 1
    assert fake.vault == {} and not any("configmaps" in p for p in fake.objects)
    assert "/api/v1/namespaces/saw-portal/secrets/saw-req-1" not in fake.objects


def test_an_old_request_is_refused(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer), age=2 * 3600)
    assert portal.main(["create", "saw-req-1"]) == 1
    assert fake.vault == {}


def test_a_git_managed_user_is_refused(portal, world):
    fake, signer = world
    fake.objects["/api/v1/namespaces/saw-alice"] = {"metadata": {"name": "saw-alice", "labels": {}}}
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 1
    assert fake.vault == {}


def test_a_portal_workspace_can_be_updated(portal, world):
    fake, signer = world
    fake.objects["/api/v1/namespaces/saw-alice"] = {
        "metadata": {"name": "saw-alice", "labels": {"saw.redhat.com/portal": "true"}}}
    fake.request("saw-req-1", ds_request(signer))
    fake.request("saw-req-2", ds_request(signer, **{"inference.api_key": "nvapi-2"}))
    assert portal.main(["create", "saw-req-1"]) == 0
    assert portal.main(["create", "saw-req-2"]) == 0
    assert fake.vault["hub/saw-alice/inference"]["api_key"] == "nvapi-2"


def test_delete_removes_the_entry_and_the_keys(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    assert portal.main(["delete", "saw-req-2"]) == 0
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice" not in fake.objects
    assert "/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/portal-ws-alice" in fake.deleted
    assert fake.vault == {}


def test_delete_of_someone_elses_workspace_is_impossible(portal, world):
    """bob's token can only name bob, who has no workspace."""
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.request("saw-req-2", {"action": "delete", "token": signer.token(sub="user:default/bob")})
    assert portal.main(["delete", "saw-req-2"]) == 1
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice" in fake.objects


def test_the_generator_lists_the_registry(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    ws = portal.list_workspaces(portal.kube(), "saw-portal")
    assert [w["name"] for w in ws] == ["alice"]


def test_a_create_request_cannot_run_the_delete_pipeline(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.request("saw-req-2", ds_request(signer))
    assert portal.main(["delete", "saw-req-2"]) == 1
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice" in fake.objects


def test_a_secret_that_is_not_a_request_is_left_alone(portal, world):
    fake, signer = world
    fake.request("saw-req-other", ds_request(signer), labels={})
    assert portal.main(["create", "saw-req-other"]) == 1
    assert "/api/v1/namespaces/saw-portal/secrets/saw-req-other" in fake.objects


@pytest.mark.parametrize("name", ["other-secret", "saw-req-../x", "saw-req-A"])
def test_only_request_names_are_read(portal, world, name):
    assert portal.main(["create", name]) == 1


def test_someone_elses_application_blocks_the_workspace(portal, world):
    fake, signer = world
    fake.objects["/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/saw-alice-bom"] = {
        "metadata": {"name": "saw-alice-bom", "labels": {"openshell.pattern/owner": "alice-bom"}}}
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 1
    assert fake.vault == {}


def test_a_broken_registry_entry_fails_the_generator(portal, world):
    """Skipping it would read as "this workspace is gone"."""
    fake, _ = world
    fake.objects["/api/v1/namespaces/saw-portal/configmaps/saw-ws-bob"] = {
        "metadata": {"name": "saw-ws-bob", "labels": {"saw.redhat.com/workspace": "true"}},
        "data": {"user.json": "{not json"}}
    with pytest.raises(portal.PortalError, match="saw-ws-bob"):
        portal.list_workspaces(portal.kube(), "saw-portal")


def test_cleanup_deletes_only_stale_requests(portal, world):
    fake, signer = world
    fake.request("saw-req-old", ds_request(signer), age=2 * 3600)
    fake.request("saw-req-new", ds_request(signer))
    assert portal.main(["cleanup"]) == 0
    assert "/api/v1/namespaces/saw-portal/secrets/saw-req-old" not in fake.objects
    assert "/api/v1/namespaces/saw-portal/secrets/saw-req-new" in fake.objects


def test_delete_removes_the_entry_before_the_application(portal, world):
    """A surviving entry would make the ApplicationSet rebuild a fresh VM."""
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    portal.main(["delete", "saw-req-2"])
    cm = "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice"
    app = "/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/portal-ws-alice"
    assert fake.deleted.index(cm) < fake.deleted.index(app)


def test_a_half_done_delete_can_be_run_again(portal, world):
    """Entry gone, Application still there: a second delete finishes."""
    fake, signer = world
    fake.objects["/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/portal-ws-alice"] = {
        "metadata": {"name": "portal-ws-alice", "labels": {"saw.redhat.com/portal": "true"}}}
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    assert portal.main(["delete", "saw-req-2"]) == 0
    assert "/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/portal-ws-alice" not in fake.objects
