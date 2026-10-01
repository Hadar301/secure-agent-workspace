#!/usr/bin/env python3
"""Self-service workspaces for the Secure Agent Workspace pattern.

Standard library only; one file, three uses:

  portal.py create REQUEST   (Tekton, pipeline saw-workspace-create)
  portal.py delete REQUEST   (Tekton, pipeline saw-workspace-delete)
  portal.py serve            (the ApplicationSet plugin generator)
  portal.py cleanup          (CronJob: requests nobody handled)

A request is a Secret the RHDH template creates in the portal namespace. It
holds the user's Backstage token and the form: the profile and the values of
the Secrets that profile's providers read. Who the request is for is taken
only from the token, after its signature is checked against RHDH's JWKS: a
signed-in user who calls the RHDH proxy directly can only act for
themselves.

create  checks the request against the profile catalog, writes each Secret
        to Vault at <kv>/data/<base>/saw-<user>/<secret> (External Secrets
        copies them into namespace saw-<user>), then writes the workspace
        registry entry: ConfigMap saw-ws-<user>, label
        saw.redhat.com/workspace=true.
delete  removes the registry entry (and the user's Vault entries).
serve   answers Argo CD's ApplicationSet plugin generator: one parameter set
        per registry entry, `values` being the saw-users chart values for
        that one user. The generated Application renders saw-users, so a
        portal workspace is built exactly like one in overrides/saw-users.yaml.

The generator also serves GET /catalog.yaml, the RHDH catalog entities of
the registered workspaces (an RHDH url location). create and delete always
delete the request Secret.
"""
import base64
import calendar
import hashlib
import http.server
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
NAME_LIMIT = 19            # the VM name, and OpenShell's name limit
WORKSPACE_LABEL = "saw.redhat.com/workspace"
REQUEST_LABEL = "saw.redhat.com/request"
REQUEST_MAX_AGE = 3600     # seconds a request Secret stays valid
REQUEST_NAME_RE = re.compile(r"^saw-req-[a-z0-9]{1,20}$")
# The Applications saw-users makes for user <u> are saw-<u>, saw-<u>-bom and
# saw-<u>-secrets, and the portal's parent is portal-ws-<u>: these suffixes
# would make one user's app name another user's.
RESERVED_SUFFIXES = ("-bom", "-secrets")


class PortalError(Exception):
    """A request that must be refused; the message is shown in the PipelineRun."""


class NotARequest(PortalError):
    """The named Secret is not a request: it is not deleted."""


def log(msg):
    print(f"[saw-portal] {msg}", flush=True)


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None:
        raise PortalError(f"environment variable {name} is not set")
    return value


# -- ES256 (ECDSA P-256, SHA-256), for Backstage user tokens --------------------

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, point):
    result = None
    while k:
        if k & 1:
            result = _add(result, point)
        point = _add(point, point)
        k >>= 1
    return result


def _on_curve(pt):
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def es256_verify(pub, message, signature):
    """True when signature (64 bytes, r||s) is valid for message under pub (x, y)."""
    if len(signature) != 64 or not _on_curve(pub):
        return False
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, N - 2, N)
    point = _add(_mul(z * w % N, G), _mul(r * w % N, pub))
    return point is not None and point[0] % N == r


def b64url(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def decode_jwt(token):
    """(header, payload, signing input, signature) of a compact JWS."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        return (json.loads(b64url(header_b64)), json.loads(b64url(payload_b64)),
                f"{header_b64}.{payload_b64}".encode(), b64url(sig_b64))
    except (ValueError, UnicodeDecodeError, AttributeError):
        raise PortalError("the request's Backstage token is not a JWT") from None


def verify_jwt(token, jwks, what, now=None):
    """The (header, payload) of a token signed by a key of `jwks`, not expired."""
    header, payload, signed, signature = decode_jwt(token)
    if header.get("alg") != "ES256":
        raise PortalError(f"{what}: unsupported algorithm {header.get('alg')!r} (expected ES256)")
    keys = [k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")
            and k.get("kty") == "EC" and k.get("crv") == "P-256"]
    if not keys:
        raise PortalError(f"{what}: its signing key is not in the JWKS")
    pub = (int.from_bytes(b64url(keys[0]["x"]), "big"), int.from_bytes(b64url(keys[0]["y"]), "big"))
    if not es256_verify(pub, signed, signature):
        raise PortalError(f"{what}: the signature is not valid")
    if payload.get("exp", 0) < (now or time.time()):
        raise PortalError(f"{what}: expired")
    return header, payload


PLUGIN_TYP = "vnd.backstage.plugin"
USER_TYPS = ("vnd.backstage.user", "vnd.backstage.limited-user")


def verify_backstage_token(token, auth_jwks, scaffolder_jwks=None, now=None):
    """The user name ("alice" for user:default/alice) a request is for.

    The scaffolder's `secrets.backstageToken` is, on the new backend, a
    plugin token: signed by the scaffolder's own key (its JWKS at
    /api/scaffolder/.backstage/auth/v1/jwks.json), typ vnd.backstage.plugin,
    sub "scaffolder", aud "catalog", carrying the user in `obo`, a limited
    user token signed by the auth backend (/api/auth/.well-known/jwks.json).
    Both are verified. A full user token (older backends) is verified
    against the auth backend's keys alone."""
    header, _, _, _ = decode_jwt(token)
    user_token = token
    if header.get("typ") == PLUGIN_TYP:
        if scaffolder_jwks is None:
            raise PortalError("a plugin token needs the scaffolder's JWKS")
        _, outer = verify_jwt(token, scaffolder_jwks, "the scaffolder token", now)
        if outer.get("sub") != "scaffolder" or outer.get("aud") != "catalog":
            raise PortalError(f"the plugin token is from {outer.get('sub')!r} for {outer.get('aud')!r}, "
                              "not the scaffolder for the catalog")
        user_token = outer.get("obo") or ""
        if not user_token:
            raise PortalError("the scaffolder token does not act for a user (no obo)")
    uheader, payload = verify_jwt(user_token, auth_jwks, "the user token", now)
    if uheader.get("typ", USER_TYPS[0]) not in USER_TYPS:
        raise PortalError(f"the user token has type {uheader.get('typ')!r}")
    sub = payload.get("sub", "")
    if not sub.startswith("user:default/"):
        raise PortalError(f"the token is not for a user (sub {sub!r})")
    return sub.split("/", 1)[1]


# -- Kubernetes and Vault over HTTPS ---------------------------------------------

class Http:
    def __init__(self, base, token="", cafile=None, insecure=False):
        self.base = base.rstrip("/")
        self.token = token
        self.ctx = ssl.create_default_context(cafile=cafile) if base.startswith("https") else None
        if self.ctx and insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def call(self, method, path, body=None, headers=None, ok404=False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and ok404:
                return None
            detail = exc.read().decode(errors="replace")[:300]
            raise PortalError(f"{method} {path}: HTTP {exc.code} {detail}") from None


def kube():
    host, port = env("KUBERNETES_SERVICE_HOST"), env("KUBERNETES_SERVICE_PORT", "443")
    with open(f"{SA_DIR}/token", encoding="utf-8") as f:
        token = f.read().strip()
    return Http(f"https://{host}:{port}", token, cafile=f"{SA_DIR}/ca.crt")


def fetch_json(url, insecure=False):
    return Http(url, insecure=insecure).call("GET", "")


class Vault:
    """KV v2 through the Kubernetes auth method, as this pod's service account."""

    def __init__(self, addr, mount, role, kv="secret"):
        self.http = Http(addr, insecure=os.environ.get("VAULT_SKIP_VERIFY") == "true",
                         cafile=os.environ.get("VAULT_CACERT") or None)
        with open(f"{SA_DIR}/token", encoding="utf-8") as f:
            jwt = f.read().strip()
        auth = self.http.call("POST", f"/v1/auth/{mount}/login", {"role": role, "jwt": jwt})
        self.token = auth["auth"]["client_token"]
        self.kv = kv

    def _h(self):
        return {"X-Vault-Token": self.token}

    def write(self, path, data):
        self.http.call("POST", f"/v1/{self.kv}/data/{path}", {"data": data}, headers=self._h())

    def destroy(self, path):
        self.http.call("DELETE", f"/v1/{self.kv}/metadata/{path}", headers=self._h(), ok404=True)


# -- requests ---------------------------------------------------------------------

def load_catalog(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)["profiles"]


def check_user(user):
    if not NAME_RE.match(user) or len(user) > NAME_LIMIT:
        raise PortalError(
            f"user name {user!r} cannot name a workspace: it must be a lowercase DNS label of at "
            f"most {NAME_LIMIT} characters (it names the VM and the namespace saw-{user})")
    if user.endswith(RESERVED_SUFFIXES):
        raise PortalError(f"user name {user!r} cannot name a workspace: its Argo CD applications "
                          "would take another user's names (-bom, -secrets)")
    return user


def parse_request(data, catalog):
    """The chosen profile and, for each Secret it reads, the field values.

    `data` is the request Secret's decoded data: `profile`, and one key per
    form field, `<secret>.<field>`. Fields of other profiles are ignored; a
    required field left empty is refused."""
    profile = data.get("profile", "")
    if profile not in catalog:
        raise PortalError(f"unknown profile {profile!r}; available: {', '.join(sorted(catalog))}")
    secrets, missing = {}, []
    for name, spec in sorted(catalog[profile].get("secrets", {}).items()):
        values = {}
        for field in spec.get("fields", []):
            value = (data.get(f"{name}.{field['key']}") or "").strip()
            if not value and field.get("default"):
                value = field["default"]
            if not value:
                if field.get("required"):
                    missing.append(f"{name}.{field['key']}")
                continue
            if field.get("kind") == "url" and not re.match(r"^https?://[^\s/?#@]+(/[^\s?#]*)?$", value):
                raise PortalError(f"{name}.{field['key']} must be an http(s) URL without credentials")
            values[field["key"]] = value
        if spec.get("provider"):
            values["provider"] = spec["provider"]
        secrets[name] = values
    if missing:
        raise PortalError(f"profile {profile!r} needs: {', '.join(missing)}")
    return profile, secrets


def decode_secret(obj):
    return {k: base64.b64decode(v).decode("utf-8") for k, v in (obj.get("data") or {}).items()}


def request_path(ns, name):
    if not REQUEST_NAME_RE.match(name):
        raise PortalError(f"{name!r} is not a request name (saw-req-*)")
    return f"/api/v1/namespaces/{ns}/secrets/{urllib.parse.quote(name, safe='')}"


def read_request(k8s, ns, name):
    """The request's data. A Secret that is not a request is refused and
    left alone; a request is deleted by handle() whatever happens."""
    obj = k8s.call("GET", request_path(ns, name), ok404=True)
    if obj is None:
        raise PortalError(f"request {name} not found (already used?)")
    if (obj["metadata"].get("labels") or {}).get(REQUEST_LABEL) != "true":
        raise NotARequest(f"secret {name} is not a portal request")
    created = obj["metadata"].get("creationTimestamp", "")
    if created:
        age = time.time() - calendar.timegm(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ"))
        if age > REQUEST_MAX_AGE:
            raise PortalError(f"request {name} is older than {REQUEST_MAX_AGE // 60} minutes")
    return decode_secret(obj)


def requester(data):
    if os.environ.get("VERIFY_TOKEN", "true") != "true":
        # Test setups only: trusts the owner the template wrote.
        log("WARN: VERIFY_TOKEN=false, the request's owner is not checked")
        return check_user(data.get("owner", ""))
    rhdh = env("RHDH_INTERNAL_URL").rstrip("/")
    insecure = os.environ.get("RHDH_SKIP_VERIFY") == "true"
    auth_jwks = fetch_json(f"{rhdh}/api/auth/.well-known/jwks.json", insecure=insecure)
    token = data.get("token", "")
    scaffolder_jwks = None
    if decode_jwt(token)[0].get("typ") == PLUGIN_TYP:
        scaffolder_jwks = fetch_json(f"{rhdh}/api/scaffolder/.backstage/auth/v1/jwks.json", insecure=insecure)
    return check_user(verify_backstage_token(token, auth_jwks, scaffolder_jwks))


def vault_prefix(user):
    return f"{env('VAULT_PREFIX_BASE', 'hub')}/saw-{user}"


def registry_entry(user, profile):
    """The saw-users list entry for a portal workspace."""
    return {"name": user, "profiles": [profile], "ownerSubject": "",
            "vaultPrefix": f"{env('VAULT_KV_MOUNT', 'secret')}/data/{vault_prefix(user)}",
            "pruneOnRemove": os.environ.get("PRUNE_ON_REMOVE", "true") == "true"}


def put_configmap(k8s, ns, name, data, labels=None):
    body = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": ns, "labels": labels or {}}, "data": data}
    path = f"/api/v1/namespaces/{ns}/configmaps"
    if k8s.call("GET", f"{path}/{name}", ok404=True) is None:
        k8s.call("POST", path, body)
    else:
        k8s.call("PUT", f"{path}/{name}", body)


def list_workspaces(k8s, ns):
    items = k8s.call("GET", f"/api/v1/namespaces/{ns}/configmaps?labelSelector="
                     + urllib.parse.quote(f"{WORKSPACE_LABEL}=true")).get("items", [])
    out = []
    for cm in items:
        # A broken entry fails the whole answer: skipping it would read as
        # "this workspace is gone".
        try:
            entry = json.loads((cm.get("data") or {}).get("user.json", ""))
        except ValueError:
            raise PortalError(f"registry entry {cm['metadata']['name']} has no valid user.json") from None
        if not (isinstance(entry, dict) and NAME_RE.match(str(entry.get("name", "")))
                and cm["metadata"]["name"] == f"saw-ws-{entry['name']}"):
            raise PortalError(f"registry entry {cm['metadata']['name']} is malformed")
        out.append(entry)
    return sorted(out, key=lambda e: e["name"])


def entities_yaml(workspaces, catalog, domain, rhdh_url):
    """RHDH catalog entities: one Resource per workspace, owned by its user,
    linking the OpenShell web UI and each sandbox UI route. JSON documents
    (valid YAML) separated by ---."""
    docs = []
    for ws in workspaces:
        user = ws["name"]
        links = []
        if domain:
            links.append({"url": f"https://{user}-webui-saw-{user}.apps.{domain}",
                          "title": "OpenShell web UI", "icon": "dashboard"})
            for profile in ws.get("profiles", []):
                for w in catalog.get(profile, {}).get("workspaces", []):
                    for sb in w.get("sandboxes", []):
                        if w.get("enabled") and sb.get("enabled") and sb.get("uiRoute"):
                            links.append({"url": f"https://{user}-{w['name']}-{sb['name']}-ui.apps.{domain}",
                                          "title": f"{sb['name']} UI ({w['name']})", "icon": "web"})
        if rhdh_url:
            links.append({"url": f"{rhdh_url}/create/templates/default/delete-saw-workspace",
                          "title": "Delete workspace", "icon": "delete"})
        docs.append({"apiVersion": "backstage.io/v1alpha1", "kind": "Resource",
                     "metadata": {"name": f"saw-{user}", "title": f"Agent workspace: {user}",
                                  "description": "Secure Agent Workspace (profiles: "
                                                 + ", ".join(ws.get("profiles", [])) + ")",
                                  "annotations": {"openshell.pattern/namespace": f"saw-{user}"},
                                  "links": links},
                     "spec": {"type": "agent-workspace", "owner": f"user:default/{user}",
                              "lifecycle": "production"}})
    if not docs:
        return "# no workspaces yet\n"
    return "\n---\n".join(json.dumps(d, indent=2, sort_keys=True) for d in docs) + "\n"


PORTAL_NS_LABEL = "saw.redhat.com/portal"


def check_applications_are_ours(k8s, user):
    """None of the Applications this user's workspace needs may belong to
    someone else (a name that collides). A Git-declared user's own apps
    carry their label too; check_namespace_is_ours refuses those."""
    argo = env("ARGO_NAMESPACE")
    for app in (f"saw-{user}", f"saw-{user}-bom", f"saw-{user}-secrets", f"portal-ws-{user}"):
        obj = k8s.call("GET", f"/apis/argoproj.io/v1alpha1/namespaces/{argo}/applications/{app}", ok404=True)
        if obj is not None and (obj["metadata"].get("labels") or {}).get("openshell.pattern/owner") != user:
            raise PortalError(f"Argo CD application {app} exists and is not {user}'s")


def check_namespace_is_ours(k8s, user):
    """A user whose workspace is declared in Git (overrides/saw-users.yaml)
    already has namespace saw-<user> without the portal's label: a portal
    entry for them would fight over the same Applications."""
    ns = k8s.call("GET", f"/api/v1/namespaces/saw-{user}", ok404=True)
    if ns is not None and (ns["metadata"].get("labels") or {}).get(PORTAL_NS_LABEL) != "true":
        raise PortalError(f"namespace saw-{user} exists and is not managed by the portal "
                          "(is the workspace declared in overrides/saw-users.yaml?)")


def delete_application(k8s, user):
    """The ApplicationSet only creates and updates (a registry hiccup must
    not delete VMs), so delete removes the user's Application itself; its
    finalizer takes the user's apps (and, with pruneOnRemove, the VM) along."""
    argo = env("ARGO_NAMESPACE")
    path = f"/apis/argoproj.io/v1alpha1/namespaces/{argo}/applications/portal-ws-{user}"
    if k8s.call("DELETE", path, ok404=True) is None:
        log(f"no Application portal-ws-{user} (not built yet?)")
    else:
        log(f"Application portal-ws-{user} deleted; Argo CD removes the workspace")


def handle(action, request_name):
    ns = env("NAMESPACE")
    k8s = kube()
    catalog = load_catalog(env("CATALOG_PATH"))
    if action not in ("create", "delete"):
        raise PortalError(f"unknown action {action}")
    path = request_path(ns, request_name)
    try:
        data = read_request(k8s, ns, request_name)
        if data.get("action", "") != action:
            raise PortalError(f"request {request_name} is a {data.get('action') or '?'} request, "
                              f"not {action}")
        user = requester(data)
        log(f"{action} request {request_name} from {user}")
        name = f"saw-ws-{user}"
        if action == "create":
            profile, secrets = parse_request(data, catalog)
            check_namespace_is_ours(k8s, user)
            check_applications_are_ours(k8s, user)
            vault = Vault(env("VAULT_ADDR"), env("VAULT_AUTH_MOUNT"), env("VAULT_ROLE"),
                          env("VAULT_KV_MOUNT", "secret"))
            for secret, values in secrets.items():
                vault.write(f"{vault_prefix(user)}/{secret}", values)
                log(f"Vault: {vault_prefix(user)}/{secret} ({', '.join(sorted(values))})")
            entry = registry_entry(user, profile)
            put_configmap(k8s, ns, name, {"user.json": json.dumps(entry, sort_keys=True)},
                          {WORKSPACE_LABEL: "true", "openshell.pattern/owner": user})
            log(f"workspace saw-{user} registered with profile {profile}; Argo CD builds it next")
        else:
            argo_app = f"/apis/argoproj.io/v1alpha1/namespaces/{env('ARGO_NAMESPACE')}/applications/portal-ws-{user}"
            if (k8s.call("GET", f"/api/v1/namespaces/{ns}/configmaps/{name}", ok404=True) is None
                    and k8s.call("GET", argo_app, ok404=True) is None):
                raise PortalError(f"{user} has no portal workspace")
            # The entry first: if deleting the Application then fails, the
            # ApplicationSet (create and update only) leaves it alone and a
            # re-run finishes; the other way round, a surviving entry would
            # rebuild a fresh VM after the old one was deleted.
            k8s.call("DELETE", f"/api/v1/namespaces/{ns}/configmaps/{name}", ok404=True)
            log(f"workspace saw-{user} removed from the registry")
            delete_application(k8s, user)
            if os.environ.get("DELETE_VAULT_SECRETS", "true") == "true":
                vault = Vault(env("VAULT_ADDR"), env("VAULT_AUTH_MOUNT"), env("VAULT_ROLE"),
                              env("VAULT_KV_MOUNT", "secret"))
                for secret in sorted({s for p in catalog.values() for s in p.get("secrets", {})}):
                    vault.destroy(f"{vault_prefix(user)}/{secret}")
                log(f"Vault: {vault_prefix(user)}/* deleted")
    except NotARequest:
        raise
    except BaseException:
        k8s.call("DELETE", path, ok404=True)
        raise
    k8s.call("DELETE", path, ok404=True)


def cleanup(max_age=REQUEST_MAX_AGE):
    """Delete request Secrets nobody handled (a failed or never-started run,
    or a request posted without a run), which still hold keys."""
    ns = env("NAMESPACE")
    k8s = kube()
    items = k8s.call("GET", f"/api/v1/namespaces/{ns}/secrets?labelSelector="
                     + urllib.parse.quote(f"{REQUEST_LABEL}=true")).get("items", [])
    now = time.time()
    for obj in items:
        name = obj["metadata"]["name"]
        created = obj["metadata"].get("creationTimestamp", "")
        if not REQUEST_NAME_RE.match(name) or not created:
            continue
        if now - calendar.timegm(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ")) > max_age:
            k8s.call("DELETE", request_path(ns, name), ok404=True)
            log(f"deleted stale request {name}")


# -- ApplicationSet plugin generator --------------------------------------------

def generator_params(workspaces, defaults):
    """One parameter set per workspace: `name`, and `values`, the saw-users
    chart values for that user alone (JSON, which is YAML)."""
    out = []
    for ws in workspaces:
        values = {**defaults, "users": [ws]}
        out.append({"name": ws["name"], "values": json.dumps(values, sort_keys=True)})
    return out


def serve():
    token = open(env("GENERATOR_TOKEN_FILE"), encoding="utf-8").read().strip()
    ns = env("NAMESPACE")
    defaults = json.loads(os.environ.get("SAW_USERS_VALUES", "{}"))
    catalog = load_catalog(env("CATALOG_PATH"))

    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, code, body):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(200, {"ok": True})
            if self.path != "/catalog.yaml":
                return self._send(404, {"error": "not found"})
            try:
                text = entities_yaml(list_workspaces(kube(), ns), catalog,
                                     os.environ.get("CLUSTER_DOMAIN", ""),
                                     os.environ.get("RHDH_BASE_URL", ""))
            except PortalError as exc:
                log(f"ERROR: {exc}")
                return self._send(500, {"error": str(exc)})
            raw = text.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/yaml")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            if self.path != "/api/v1/getparams.execute":
                return self._send(404, {"error": "not found"})
            if self.headers.get("Authorization", "") != f"Bearer {token}":
                return self._send(403, {"error": "forbidden"})
            try:
                params = generator_params(list_workspaces(kube(), ns), defaults)
            except PortalError as exc:
                log(f"ERROR: {exc}")
                return self._send(500, {"error": str(exc)})
            self._send(200, {"output": {"parameters": params}})

        def log_message(self, fmt, *args):
            log(fmt % args)

    port = int(os.environ.get("PORT", "4355"))
    log(f"plugin generator listening on :{port}")
    http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


def main(argv):
    try:
        if argv[:1] == ["serve"]:
            serve()
        elif argv[:1] == ["cleanup"]:
            cleanup()
        elif len(argv) == 2 and argv[0] in ("create", "delete"):
            handle(argv[0], argv[1])
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except PortalError as exc:
        log(f"ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
