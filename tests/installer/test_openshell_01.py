"""OpenShell 0.1.x: what the installer does differently from 0.0.x.

- the BOM carries the sandbox runtime image (image only, nothing extracted);
- a 0.0.x -> 0.1.x gateway change recreates gateway state and sandboxes,
  because 0.1.0 cannot upgrade 0.0.x state in place;
- gateway.env drops the retired OPENSHELL_DRIVERS key;
- the 0.1.x "profile was not found" error still skips the provider;
- a 0.0.x inference route left in the ledger is forgotten, not deleted.
"""
import json

import pytest

SANDBOX_IMAGE = "quay.io/opendatahub/odh-openshell-sandbox@sha256:" + "5" * 64


@pytest.fixture
def installer(ab, tmp_path, fake_env):
    return ab.ComponentInstaller(ab.Shell(), tmp_path / "bin", tmp_path / "state" / "installed.json",
                                 podman="podman", opt_dir=tmp_path / "opt")


def with_sandbox(bom):
    bom["spec"]["openshell"]["sandbox"] = {
        "version": bom["spec"]["openshell"]["gateway"]["version"], "image": SANDBOX_IMAGE}
    return bom


def test_the_sandbox_runtime_image_is_optional_and_image_only(ab, installer, bom, fake_env):
    ab.validate_bom(bom)                       # a 0.0.x BOM has none
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
            return ab.Result(0)

    monkeypatch.setattr(ab, "as_user", lambda user, env, argv: argv)
    ab.reset_gateway_state(Recorder(), "cloud-user", {}, home, "0.0.116-rhaiv.0", "0.1.2-rhaiv.0")
    assert ["systemctl", "--user", "stop", "openshell-gateway.service"] in calls
    assert ["podman", "rm", "-f", "openshell-default--notebook-1",
            "openshell-cuda-dev--cuda-sandbox-2"] in calls
    ps = next(c for c in calls if "ps" in c)
    assert "label=openshell.ai/sandbox-name" in ps
    assert not state.exists() and tls.exists()
    backups = list(state.parent.glob("gateway.0.0.116-rhaiv.0.*"))
    assert len(backups) == 1 and (backups[0] / "openshell.db").read_text() == "old"


def test_the_retired_drivers_key_is_dropped(ab):
    chart = "OPENSHELL_COMPUTE_DRIVER=podman\nOPENSHELL_SERVER_PORT=17670\n"
    current = ("OPENSHELL_DRIVERS=podman\nOPENSHELL_SERVER_PORT=17670\n"
               "OPENSHELL_PODMAN_SOCKET=/run/user/1000/podman/podman.sock\n")
    merged = ab.merge_user_env(chart, current)
    assert "OPENSHELL_DRIVERS" not in merged
    assert "OPENSHELL_PODMAN_SOCKET=/run/user/1000/podman/podman.sock" in merged


def test_the_01_missing_profile_message_is_recognized(ab):
    assert ab.NO_PROFILE_RE.search(
        "provider profile 'brave' was not found in the requested scope; import a matching "
        "profile before creating this provider")
