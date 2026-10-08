"""OpenShell 0.1.x: what the installer does differently from 0.0.x.

- the BOM carries the sandbox runtime image (required, image only, nothing
  extracted), and every component comes from the same release;
- a 0.0.x -> 0.1.x gateway change recreates gateway state and sandboxes,
  because 0.1.0 cannot upgrade 0.0.x state in place, and a retry after an
  interrupted run still does it (tests/installer/test_cli.py);
- gateway.env drops keys 0.1.x no longer reads;
- the 0.1.x "profile was not found" error still skips the provider;
- a 0.0.x inference route left in the ledger is forgotten, not deleted.
"""
import json

import pytest

from test_apply_profiles import creds, make_applier, profiles  # noqa: F401 (fixtures)

SANDBOX_IMAGE = "quay.io/opendatahub/odh-openshell-sandbox@sha256:" + "5" * 64


@pytest.fixture
def installer(ab, tmp_path, fake_env):
    return ab.ComponentInstaller(ab.Shell(), tmp_path / "bin", tmp_path / "state" / "installed.json",
                                 podman="podman", opt_dir=tmp_path / "opt")


def with_sandbox(bom):
    bom["spec"]["openshell"]["sandbox"] = {
        "version": bom["spec"]["openshell"]["gateway"]["version"], "image": SANDBOX_IMAGE}
    return bom


def test_the_sandbox_runtime_image_is_required(ab, bom):
    del bom["spec"]["openshell"]["sandbox"]
    with pytest.raises(ab.InstallerError, match="missing sandbox"):
        ab.validate_bom(bom)


def test_components_from_different_releases_are_refused(ab, bom):
    bom["spec"]["openshell"]["cli"]["version"] = "0.1.1"
    with pytest.raises(ab.InstallerError, match="same version"):
        ab.validate_bom(bom)


def test_the_sandbox_runtime_image_is_image_only(ab, installer, bom, fake_env):
    with_sandbox(bom)
    ab.validate_bom(bom)
    fake_env.images_for_bom(bom)
    assert "sandbox" in installer.install(bom)
    assert not (installer.bin_dir / "sandbox").exists()
    assert ["pull", "--quiet", SANDBOX_IMAGE] in fake_env.podman_calls()
    state = json.loads(installer.state_file.read_text())
    assert state["components"]["sandbox"]["image"] == SANDBOX_IMAGE
    assert "sandbox" not in installer.install(bom), "an unchanged image is not pulled again"


def test_the_sandbox_image_must_be_pinned(ab, bom):
    with_sandbox(bom)["spec"]["openshell"]["sandbox"]["image"] = "quay.io/x/sandbox:latest"
    with pytest.raises(ab.InstallerError, match="spec.openshell.sandbox.image must be pinned"):
        ab.validate_bom(bom)


@pytest.mark.parametrize("old,new,reset", [
    ("0.0.116-rhaiv.0", "0.1.2-rhaiv.0", True),
    ("0.1.1", "0.1.2-rhaiv.0", False),
    ("0.0.115", "0.0.116-rhaiv.0", False),
    (None, "0.1.2-rhaiv.0", False),            # first install: nothing to reset
])
def test_only_a_new_release_series_resets_state(ab, old, new, reset):
    assert ab.needs_state_reset(old, new) is reset


def test_reset_removes_sandboxes_and_keeps_a_backup(ab, tmp_path, fake_env, monkeypatch):
    home = tmp_path / "home"
    state = home / ".local" / "state" / "openshell" / "gateway"
    state.mkdir(parents=True, exist_ok=True)
    (state / "openshell.db").write_text("old")
    tls = home / ".local" / "state" / "openshell" / "tls"
    tls.mkdir(exist_ok=True)
    calls = []

    class Recorder(ab.Shell):
        def run(self, argv, **kw):
            calls.append(argv)
            if "ps" in argv:
                return ab.Result(0, "openshell-default--notebook-1\nopenshell-cuda-dev--cuda-sandbox-2\n")
            if "volume" in argv:
                return ab.Result(0, "openshell-sandbox-1-workspace\nother\n")
            return ab.Result(0)

    ab.reset_gateway_state(Recorder(), lambda argv: argv, home, "0.0.116-rhaiv.0", "0.1.2-rhaiv.0")
    assert ["systemctl", "--user", "stop", "openshell-gateway.service"] in calls
    assert ["podman", "rm", "-f", "openshell-default--notebook-1",
            "openshell-cuda-dev--cuda-sandbox-2"] in calls
    ps = next(c for c in calls if "ps" in c)
    assert "label=openshell.ai/sandbox-name" in ps
    assert not state.exists() and tls.exists()
    backups = list(state.parent.glob("gateway.0.0.116-rhaiv.0.*"))
    assert len(backups) == 1 and (backups[0] / "openshell.db").read_text() == "old"


def test_retired_env_keys_are_dropped(ab):
    chart = "OPENSHELL_COMPUTE_DRIVER=podman\nOPENSHELL_SERVER_PORT=17670\n"
    current = ("OPENSHELL_DRIVERS=podman\nOPENSHELL_SERVER_PORT=17670\n"
               "OPENSHELL_CONFIG_FILE=/etc/openshell/gateway.toml\nOPENSHELL_SSH_GATEWAY_PORT=17670\n"
               "OPENSHELL_PODMAN_SOCKET=/run/user/1000/podman/podman.sock\n")
    merged = ab.merge_user_env(chart, current)
    assert "OPENSHELL_DRIVERS" not in merged and "OPENSHELL_CONFIG_FILE" not in merged
    assert "OPENSHELL_SSH_GATEWAY_PORT" not in merged
    assert "OPENSHELL_PODMAN_SOCKET=/run/user/1000/podman/podman.sock" in merged


def test_the_01_missing_profile_message_is_recognized(ab):
    assert ab.NO_PROFILE_RE.search(
        "provider profile 'brave' was not found in the requested scope; import a matching "
        "profile before creating this provider")


def test_a_00x_inference_route_in_the_ledger_is_forgotten(ab, tmp_path):
    path = tmp_path / "managed.json"
    path.write_text(json.dumps({"version": 1, "adopted": True, "objects": [
        {"kind": "inference", "workspace": "default", "name": "route", "profile": "p"},
        {"kind": "provider", "workspace": "default", "name": "nvidia", "profile": "p"}]}))
    ledger = ab.Ledger(path)
    assert [o["kind"] for o in ledger.data["objects"]] == ["provider"]


@pytest.mark.parametrize("url", ['http://h/v1$(id)', 'http://h/v1"`id`"', "http://h/v1;id"])
def test_a_base_url_with_shell_characters_is_refused(ab, url):
    with pytest.raises(ValueError):
        ab.check_base_url(url)


def test_onboarding_quotes_what_comes_from_profiles(ab, fake_env, config, profiles, creds):
    for _, ws in ab.enabled_workspaces(profiles):
        for sb in ws.sandboxes:
            if sb.name == "notebook":
                sb.model = "my model's/v1"
    make_applier(ab, config, creds).apply(profiles)
    onboard = next(c[-1] for c in fake_env.openshell_calls()
                   if c[:2] == ["sandbox", "exec"] and "onboard" in c[-1] and "notebook" in c)
    assert "--custom-model-id 'my model'\"'\"'s/v1'" in onboard


def test_an_unknown_provider_type_still_gets_the_keepalive(ab, fake_env, config, profiles, creds):
    for _, ws in ab.enabled_workspaces(profiles):
        for p in ws.providers:
            if p.name == "nvidia":
                p.type = "gemini"
    creds = {ws: {n: v for n, v in c.items()} for ws, c in creds.items()}
    make_applier(ab, config, creds).apply(profiles)
    units = [c for c in fake_env.other_calls("sudo") if "tee" in c["args"]]
    assert any("openshell-sandbox-notebook" in " ".join(c["args"]) for c in units)


# -- caBundle: extra CAs for the OIDC issuer -----------------------------------------

PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"


def _ca_shell(ab, calls):
    class Recorder(ab.Shell):
        def run(self, argv, **kw):
            calls.append(argv)
            return ab.Result(0)
    return Recorder()


def test_ca_bundle_is_trusted_and_the_store_rebuilt(ab, tmp_path):
    """The gateway verifies the OIDC issuer with the system trust store and
    exits when it cannot: a cluster whose apps certificate is its own ingress
    CA needs that CA trusted."""
    calls, anchor = [], tmp_path / "anchors" / "saw-ca-bundle.crt"
    assert ab.trust_ca_bundle(_ca_shell(ab, calls), PEM, anchor=anchor) is True
    assert anchor.read_text() == PEM + "\n"
    assert calls == [["update-ca-trust", "extract"]]
    # Unchanged: nothing to do, no restart owed.
    assert ab.trust_ca_bundle(_ca_shell(ab, calls), PEM, anchor=anchor) is False
    assert len(calls) == 1


def test_an_emptied_ca_bundle_is_removed(ab, tmp_path):
    calls, anchor = [], tmp_path / "saw-ca-bundle.crt"
    anchor.write_text(PEM + "\n")
    assert ab.trust_ca_bundle(_ca_shell(ab, calls), "", anchor=anchor) is True
    assert not anchor.exists() and calls == [["update-ca-trust", "extract"]]
    assert ab.trust_ca_bundle(_ca_shell(ab, calls), "", anchor=anchor) is False


def test_a_ca_bundle_that_is_not_pem_is_refused(ab, tmp_path):
    with pytest.raises(ab.InstallerError, match="not a PEM"):
        ab.trust_ca_bundle(_ca_shell(ab, []), "not a cert", anchor=tmp_path / "x.crt")


def test_the_ca_bundle_comes_from_config_or_the_cluster_ca_secret(ab, tmp_path):
    """caBundle wins; else caBundleSecret's ca-bundle.crt (the cluster's
    ingress CA, mounted like a provider Secret); else nothing."""
    secrets = tmp_path / "secrets"
    (secrets / "saw-ingress-ca").mkdir(parents=True)
    (secrets / "saw-ingress-ca" / "ca-bundle.crt").write_text(PEM + "\n")
    assert ab.configured_ca_bundle({"caBundleSecret": "saw-ingress-ca"}, secrets) == PEM
    assert ab.configured_ca_bundle({"caBundle": "X", "caBundleSecret": "saw-ingress-ca"}, secrets) == "X"
    assert ab.configured_ca_bundle({}, secrets) == ""


def test_a_missing_cluster_ca_secret_fails_install(ab, tmp_path):
    """Not mounted yet: fail (install retries at the next boot) rather than
    start a gateway that cannot verify the issuer."""
    with pytest.raises(ab.InstallerError, match="saw-ingress-ca is not mounted"):
        ab.configured_ca_bundle({"caBundleSecret": "saw-ingress-ca"}, tmp_path)
    with pytest.raises(ab.InstallerError, match="invalid caBundleSecret"):
        ab.configured_ca_bundle({"caBundleSecret": "../etc"}, tmp_path)


def test_sandbox_ui_proxies_get_the_vm_trust_store(ab, tmp_path):
    """oauth2-proxy sees the VM's trust store (with oidc.caBundle), so it can
    verify the issuer when insecureSkipIssuerTlsVerify is false."""
    cfg = {"oidcIssuer": "https://kc.example.com/realms/openshell",
           "sandboxUi": [{"workspace": "ws", "sandbox": "sb", "host": "h.example.com",
                          "proxyPort": 18800, "forwardPort": 18900, "portName": "ui-0"}],
           "sandboxUiProxy": {"allowedUsers": ["alice"]}}
    units, _ = ab.sandbox_ui_units(cfg, tmp_path, "cookie", "saw-installer")
    (proxy,) = [t for n, t in units.items() if n.startswith("saw-ui-proxy-")]
    assert f"-v {ab.TRUST_BUNDLE}:/etc/ssl/certs/ca-certificates.crt:ro " in proxy


def test_an_untrusted_issuer_fails_install_with_the_fix(ab):
    """The gateway only says "OIDC discovery request failed" and exits, and
    install then times out on its port. Check first and name the fix."""
    import ssl
    from urllib.error import URLError

    def untrusted(url, timeout):
        err = ssl.SSLCertVerificationError(1, "certificate verify failed")
        err.verify_message = "self-signed certificate in certificate chain"
        raise URLError(err)

    with pytest.raises(ab.InstallerError) as exc:
        ab.check_issuer_trusted("https://kc.apps.example.com/realms/openshell", opener=untrusted)
    msg = str(exc.value)
    assert "\n" not in msg      # install's status keeps the first line only
    assert "self-signed certificate in certificate chain" in msg
    assert "oidc.caBundle" in msg and "default-ingress-cert" in msg


def test_other_issuer_failures_only_warn(ab, capsys):
    from urllib.error import URLError

    def unreachable(url, timeout):
        raise URLError("Name or service not known")

    class Ok:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b"{"

    ab.check_issuer_trusted("https://kc.example.com/realms/openshell", opener=unreachable)
    assert "WARN: cannot reach the OIDC issuer" in capsys.readouterr().out
    seen = []
    ab.check_issuer_trusted("https://kc.example.com/realms/openshell/",
                            opener=lambda url, timeout: seen.append(url) or Ok())
    assert seen == ["https://kc.example.com/realms/openshell/.well-known/openid-configuration"]
    ab.check_issuer_trusted("", opener=unreachable)     # no issuer: nothing to check
