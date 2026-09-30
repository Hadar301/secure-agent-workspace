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
