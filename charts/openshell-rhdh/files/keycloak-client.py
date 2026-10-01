#!/usr/bin/env python3
"""Create or update RHDH's confidential OIDC client in the openshell realm.

Runs as an Argo CD PostSync hook, so it also fixes a realm that existed
before the portal (a realm import only runs once). The client secret comes
from the rhdh-oidc Secret (from Vault); the Keycloak admin credentials from
the operator's <keycloak>-initial-admin Secret, read through the Kubernetes
API with a Role limited to that Secret.

Env: KC_URL, KC_NAMESPACE, KC_NAME, REALM, CLIENT_ID, CLIENT_SECRET,
     RHDH_URL, INSECURE (true to skip TLS verification of Keycloak).
"""
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

SA = "/var/run/secrets/kubernetes.io/serviceaccount"


def call(url, method="GET", body=None, token=None, form=None, ctx=None):
    data = None
    req = urllib.request.Request(url, method=method)
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    elif body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, data=data, context=ctx, timeout=30) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def admin_credentials():
    host, port = os.environ["KUBERNETES_SERVICE_HOST"], os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    token = open(f"{SA}/token", encoding="utf-8").read().strip()
    ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")
    name = f"{os.environ['KC_NAME']}-initial-admin"
    secret = call(f"https://{host}:{port}/api/v1/namespaces/{os.environ['KC_NAMESPACE']}/secrets/{name}",
                  token=token, ctx=ctx)
    return {k: base64.b64decode(v).decode() for k, v in secret["data"].items()}


def main():
    kc, realm = os.environ["KC_URL"].rstrip("/"), os.environ["REALM"]
    client_id, rhdh = os.environ["CLIENT_ID"], os.environ["RHDH_URL"].rstrip("/")
    secret = os.environ["CLIENT_SECRET"]
    if not secret:
        print("rhdh-oidc has no client secret yet (load it into Vault)", file=sys.stderr)
        return 1
    ctx = ssl.create_default_context()
    if os.environ.get("INSECURE") == "true":
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    creds = admin_credentials()
    token = call(f"{kc}/realms/master/protocol/openid-connect/token", method="POST", ctx=ctx,
                 form={"grant_type": "password", "client_id": "admin-cli",
                       "username": creds["username"], "password": creds["password"]})["access_token"]
    want = {
        "clientId": client_id, "name": "Red Hat Developer Hub (agent workspaces)", "enabled": True,
        "protocol": "openid-connect", "publicClient": False, "clientAuthenticatorType": "client-secret",
        "secret": secret, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": [f"{rhdh}/api/auth/oidc/handler/frame"], "webOrigins": [rhdh],
        "attributes": {"post.logout.redirect.uris": f"{rhdh}/*"},
    }
    base = f"{kc}/admin/realms/{realm}/clients"
    found = call(f"{base}?clientId={urllib.parse.quote(client_id)}", token=token, ctx=ctx) or []
    if found:
        current = found[0]
        current.update({k: v for k, v in want.items() if k != "attributes"})
        current["attributes"] = {**(current.get("attributes") or {}), **want["attributes"]}
        call(f"{base}/{current['id']}", method="PUT", body=current, token=token, ctx=ctx)
        print(f"Updated Keycloak client {client_id} in realm {realm}")
    else:
        call(base, method="POST", body=want, token=token, ctx=ctx)
        print(f"Created Keycloak client {client_id} in realm {realm}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.HTTPError as exc:
        print(f"Keycloak: HTTP {exc.code} {exc.read().decode(errors='replace')[:300]}", file=sys.stderr)
        sys.exit(1)
