"""charts/openshell-rhdh/files/keycloak-client.py: creates or updates RHDH's
OIDC client in the realm (the PostSync job), against a small fake Keycloak."""
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "charts" / "openshell-rhdh" / "files" / "keycloak-client.py"


class FakeKeycloak:
    def __init__(self, clients=None):
        self.clients = list(clients or [])
        self.logins = []
        self.puts = []

    def serve(self):
        kc = self

        class H(BaseHTTPRequestHandler):
            def _reply(self, code, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _body(self):
                return self.rfile.read(int(self.headers.get("Content-Length") or 0))

            def _admin(self):
                return self.headers.get("Authorization") == "Bearer admin-token"

            def do_POST(self):
                url = urlsplit(self.path)
                if url.path == "/realms/master/protocol/openid-connect/token":
                    form = {k: v[0] for k, v in parse_qs(self._body().decode()).items()}
                    kc.logins.append(form)
                    if form.get("password") != "kc-admin-pass":
                        return self._reply(401, {"error": "invalid_grant"})
                    return self._reply(200, {"access_token": "admin-token"})
                if url.path == "/admin/realms/openshell/clients" and self._admin():
                    body = json.loads(self._body())
                    kc.clients.append({"id": f"id-{len(kc.clients)}", **body})
                    return self._reply(201)
                self._reply(403)

            def do_GET(self):
                url = urlsplit(self.path)
                if url.path == "/admin/realms/openshell/clients" and self._admin():
                    want = parse_qs(url.query).get("clientId", [None])[0]
                    return self._reply(200, [c for c in kc.clients if c["clientId"] == want])
                self._reply(403)

            def do_PUT(self):
                url = urlsplit(self.path)
                if url.path.startswith("/admin/realms/openshell/clients/") and self._admin():
                    body = json.loads(self._body())
                    kc.puts.append(body)
                    cid = url.path.rsplit("/", 1)[1]
                    kc.clients = [body if c["id"] == cid else c for c in kc.clients]
                    return self._reply(204)
                self._reply(403)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def client(monkeypatch):
    spec = importlib.util.spec_from_file_location("keycloak_client", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # The admin credentials come from the operator's Secret through the
    # Kubernetes API; that read is replaced here.
    servers = []

    def run(kc, secret="rhdh-client-secret", password="kc-admin-pass"):
        monkeypatch.setattr(module, "admin_credentials",
                            lambda: {"username": "kc-admin", "password": password})
        server, url = kc.serve()
        servers.append(server)
        for k, v in {"KC_URL": url, "REALM": "openshell", "CLIENT_ID": "rhdh", "CLIENT_SECRET": secret,
                     "RHDH_URL": "https://rhdh.example.com/", "KC_NAMESPACE": "saw-keycloak",
                     "KC_NAME": "openshell-keycloak"}.items():
            monkeypatch.setenv(k, v)
        return module.main()
    yield run
    for s in servers:
        s.shutdown()


def test_creates_the_confidential_client(client):
    kc = FakeKeycloak()
    assert client(kc) == 0
    (c,) = kc.clients
    assert c["clientId"] == "rhdh" and c["publicClient"] is False
    assert c["secret"] == "rhdh-client-secret"
    assert c["redirectUris"] == ["https://rhdh.example.com/api/auth/oidc/handler/frame"]
    assert c["webOrigins"] == ["https://rhdh.example.com"]
    assert c["standardFlowEnabled"] is True and c["directAccessGrantsEnabled"] is False
    assert kc.logins == [{"grant_type": "password", "client_id": "admin-cli",
                          "username": "kc-admin", "password": "kc-admin-pass"}]


def test_updates_an_existing_client_and_keeps_its_other_attributes(client):
    """A realm that existed before the portal: the client is brought in line
    (secret, redirect), attributes it set itself are kept."""
    kc = FakeKeycloak([{"id": "abc", "clientId": "rhdh", "secret": "old", "publicClient": True,
                        "redirectUris": ["https://old/*"], "attributes": {"pkce.code.challenge.method": "S256"}}])
    assert client(kc) == 0
    (c,) = kc.clients
    assert c["id"] == "abc" and c["secret"] == "rhdh-client-secret" and c["publicClient"] is False
    assert c["redirectUris"] == ["https://rhdh.example.com/api/auth/oidc/handler/frame"]
    assert c["attributes"] == {"pkce.code.challenge.method": "S256",
                               "post.logout.redirect.uris": "https://rhdh.example.com/*"}
    assert client(kc) == 0 and len(kc.clients) == 1          # idempotent


def test_without_a_client_secret_nothing_is_changed(client, capsys):
    kc = FakeKeycloak()
    assert client(kc, secret="") == 1
    assert kc.clients == [] and kc.logins == []
    assert "load it into Vault" in capsys.readouterr().err


def test_wrong_admin_credentials_fail(client):
    """main() lets the HTTP error out; the script's __main__ turns it into
    exit 1 and the Job retries."""
    import urllib.error
    kc = FakeKeycloak()
    with pytest.raises(urllib.error.HTTPError):
        client(kc, password="wrong")
    assert kc.clients == []
