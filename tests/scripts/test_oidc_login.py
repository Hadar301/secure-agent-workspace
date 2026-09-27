"""scripts/oidc-login.sh browser flow against a fake curl and a fake `open`
that plays the browser: it calls the local callback like Keycloak's redirect."""
import base64
import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "oidc-login.sh"

FAKE_CURL = r'''#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
url = next(a for a in args if a.startswith("http"))
if url.endswith("/.well-known/openid-configuration"):
    print(json.dumps({"authorization_endpoint": "https://kc.example/auth",
                      "token_endpoint": "https://kc.example/token"}))
elif url == "https://kc.example/token":
    open(__import__("os").environ["TOKEN_REQ"], "w").write(" ".join(args))
    print(__import__("os").environ["TOKEN_RESPONSE"])
else:
    sys.exit(22)
'''

# Plays the browser: after the listener is up, call the redirect URI with the
# state from the auth URL (or BROWSER_STATE) and a code.
FAKE_OPEN = r'''#!/usr/bin/env python3
import os, sys, time, urllib.parse, urllib.request, urllib.error
q = urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query)
state = os.environ.get("BROWSER_STATE") or q["state"][0]
redirect = q["redirect_uri"][0]
if os.fork():
    sys.exit(0)
devnull = os.open(os.devnull, os.O_RDWR)   # don't hold the test's pipes open
for fd in (0, 1, 2):
    os.dup2(devnull, fd)
for _ in range(50):
    time.sleep(0.1)
    try:
        urllib.request.urlopen(f"{redirect}?code=the-code&state={state}", timeout=2)
        break
    except urllib.error.HTTPError:
        break
    except OSError:
        continue
'''


def jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def env(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("curl", FAKE_CURL), ("open", FAKE_OPEN)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    port = free_port()
    return {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path),
            "OIDC_ISSUER": "https://kc.example/realms/openshell", "OIDC_CALLBACK_PORT": str(port),
            "OIDC_TOKEN_DIR": str(tmp_path / "oidc"), "TOKEN_REQ": str(tmp_path / "token-req"),
            "TOKEN_RESPONSE": json.dumps({"access_token": jwt({"preferred_username": "alice"}),
                                          "expires_in": 600})}


def login(env, **extra):
    return subprocess.run(["bash", str(SCRIPT), "login"], env={**env, **extra},
                          capture_output=True, text=True, timeout=30)


def test_browser_login_saves_the_token(env, tmp_path):
    r = login(env)
    assert r.returncode == 0, r.stderr
    assert "Logged in as: alice" in r.stdout
    assert json.loads((tmp_path / "oidc" / "token.json").read_text())["issuer_url"] == env["OIDC_ISSUER"]
    req = (tmp_path / "token-req").read_text()
    assert "code=the-code" in req and "code_verifier=" in req


def test_a_callback_from_another_login_is_refused(env, tmp_path):
    """Found live: two `make login` runs; the browser answered the older one,
    whose token exchange then failed with no explanation."""
    r = login(env, BROWSER_STATE="state-of-another-run")
    assert r.returncode == 1
    assert "state mismatch" in r.stderr
    assert not (tmp_path / "token-req").exists()      # no token request with a foreign code
    assert not (tmp_path / "oidc" / "token.json").exists()


def test_a_busy_callback_port_is_reported(env):
    with socket.socket() as s:
        s.bind(("127.0.0.1", int(env["OIDC_CALLBACK_PORT"])))
        s.listen()
        r = login(env, BROWSER_STATE="x")
    assert r.returncode == 1
    assert "cannot listen on localhost" in r.stderr and "another `make login`" in r.stderr
