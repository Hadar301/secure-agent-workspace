"""Applying SAW-BOM profiles through the (fake) OpenShell CLI over mTLS."""

import pytest


@pytest.fixture
def profiles(ab, shipped_profile_files):
    return ab.parse_profiles(shipped_profile_files)


@pytest.fixture
def creds(ab, profiles, secrets_dir):
    return ab.resolve_credentials(profiles, secrets_dir)


def make_applier(ab, config, creds, **overrides):
    return ab.ProfileApplier(ab.Shell(), {**config, **overrides}, creds)


def cli_ops(fake_env):
    """Calls as 'noun verb' strings, e.g. 'workspace create'."""
    return [" ".join(c[:2]) for c in fake_env.openshell_calls()]


def test_fresh_apply_creates_everything(ab, fake_env, config, profiles, creds):
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()

    # Local mTLS gateway only: no OIDC login, no token files.
    assert state["gateways"] == [{"name": "openshell", "endpoint": "https://127.0.0.1:17670", "local": True}]
    assert state["selected"] == "openshell"
    assert all("oidc" not in " ".join(c).lower() for c in fake_env.openshell_calls())

    assert state["workspaces"] == ["default", "cuda-dev"]
    assert set(state["providers"]) == {"default/nvidia", "default/brave", "cuda-dev/nvidia"}
    assert state["providers"]["default/nvidia"] == {
        "type": "nvidia", "credential": "NVIDIA_API_KEY=nvapi-TEST-KEY-123"}
    assert state["providers"]["default/brave"]["credential"] == "BRAVE_API_KEY=brave-TEST-KEY-456"

    # Per-workspace inference; the system route is set once, from 'default'
    # (cuda-dev sorts first but must not set it: its provider isn't in 'default').
    model = "nvidia/nemotron-3-super-120b-a12b"
    assert state["inference"] == {"cuda-dev": ["nvidia", model], "default": ["nvidia", model]}
    assert state["system_inference"] == ["nvidia", model]
    system_sets = [c for c in fake_env.openshell_calls() if c[:2] == ["inference", "set"] and "--system" in c]
    assert len(system_sets) == 1
    set_calls = [c for c in fake_env.openshell_calls() if c[:2] == ["inference", "set"]]
    assert set_calls.index(system_sets[0]) > set_calls.index(
        next(c for c in set_calls if "--workspace" in c and c[c.index("--workspace") + 1] == "default"))

    # Enabled sandboxes only.
    assert set(state["sandboxes"]) == {"default/notebook", "cuda-dev/cuda-sandbox"}
    assert state["sandboxes"]["default/notebook"]["providers"] == ["nvidia"]
    assert applier.verify(profiles) == []


def test_system_inference_skipped_without_default_workspace_model(ab, fake_env, config, profiles, creds):
    for _, ws in ab.enabled_workspaces(profiles):
        if ws.name == "default":
            for p in ws.providers:
                p.model = None
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    assert state["system_inference"] is None
    assert "cuda-dev" in state["inference"] and "default" not in state["inference"]
    assert not [c for c in fake_env.openshell_calls() if "--system" in c]



def test_nemoclaw_gets_the_provider_key_via_environment(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds).apply(profiles)
    calls = fake_env.other_calls("nemoclaw")
    assert len(calls) == 1
    assert calls[0]["args"][:2] == ["onboard", "--fresh"] and "cuda-sandbox" in calls[0]["args"]
    assert calls[0]["has_key"]


def test_keepalive_units_are_written_for_agent_sandboxes(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds).apply(profiles)
    tees = [c for c in fake_env.other_calls("sudo") if c["args"][:2] == ["-n", "tee"]]
    units = {c["args"][2]: c["stdin"] for c in tees}
    assert set(units) == {"/etc/systemd/system/openshell-sandbox-notebook.service",
                          "/etc/systemd/system/openshell-sandbox-cuda-sandbox.service"}
    cuda = units["/etc/systemd/system/openshell-sandbox-cuda-sandbox.service"]
    assert "--workspace cuda-dev" in cuda and "User=cloud-user" in cuda


def test_second_apply_is_idempotent(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds).apply(profiles)
    before = fake_env.openshell_state()
    make_applier(ab, config, creds).apply(profiles)
    after = fake_env.openshell_state()
    assert after["workspaces"] == before["workspaces"]
    assert after["providers"] == before["providers"]
    assert after["sandboxes"] == before["sandboxes"]
    creates = [c for c in fake_env.openshell_calls() if c[:2] == ["sandbox", "create"]]
    assert len(creates) == 2          # existing Ready sandboxes are not recreated


def test_owner_subject_becomes_admin_of_each_workspace(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds, ownerSubject="f3c1-owner-subject").apply(profiles)
    members = fake_env.openshell_state()["members"]
    assert members == [["cuda-dev", "f3c1-owner-subject", "admin"],
                       ["default", "f3c1-owner-subject", "admin"]]
    # Re-running does not fail on the existing membership.
    make_applier(ab, config, creds, ownerSubject="f3c1-owner-subject").apply(profiles)


def test_no_owner_subject_adds_no_members(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds).apply(profiles)
    assert fake_env.openshell_state()["members"] == []


def test_mtls_client_without_admin_fails_clearly(ab, fake_env, config, profiles, creds):
    fake_env.deny("workspace create")
    with pytest.raises(ab.InstallerError, match="platform admin; check the mTLS identity has the openshell-admin role"):
        make_applier(ab, config, creds).apply(profiles)


def test_gateway_unreachable_fails_before_any_change(ab, fake_env, config, profiles, creds):
    fake_env.deny("workspace list")
    with pytest.raises(ab.InstallerError, match="cannot list workspaces"):
        make_applier(ab, config, creds).apply(profiles)
    assert "workspace create" not in cli_ops(fake_env)


def test_provider_failure_stops_the_apply(ab, fake_env, config, profiles, creds):
    fake_env.deny("provider create")
    with pytest.raises(ab.InstallerError, match="provider create"):
        make_applier(ab, config, creds).apply(profiles)
    assert "sandbox create" not in cli_ops(fake_env)


def test_credentials_never_appear_in_logs(ab, fake_env, config, profiles, creds, capsys):
    make_applier(ab, config, creds).apply(profiles)
    out = capsys.readouterr().out
    assert "nvapi-TEST-KEY-123" not in out and "brave-TEST-KEY-456" not in out
    assert "--credential NVIDIA_API_KEY" in out      # the CLI reads the key from $NVIDIA_API_KEY


def test_errored_sandbox_is_recreated(ab, fake_env, config, profiles, creds):
    make_applier(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/notebook"]["phase"] = "Error"
    fake_env.set_openshell_state(state)
    make_applier(ab, config, creds).apply(profiles)
    ops = fake_env.openshell_calls()
    assert ["sandbox", "delete", "notebook"] in ops
    assert fake_env.openshell_state()["sandboxes"]["default/notebook"]["phase"] == "Ready"


def test_verify_reports_missing_resources(ab, fake_env, config, profiles, creds):
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()
    del state["providers"]["default/brave"]
    state["sandboxes"]["default/notebook"]["providers"] = []
    state["workspaces"].remove("cuda-dev")
    fake_env.set_openshell_state(state)
    failures = applier.verify(profiles)
    assert "provider 'brave' in 'default' is missing" in failures
    assert "sandbox 'notebook' is missing provider 'nvidia'" in failures
    assert "workspace 'cuda-dev' is missing" in failures


def test_workspace_name_match_is_exact(ab, fake_env, config, creds, profiles):
    # A workspace called "cuda-dev-old" must not satisfy "cuda-dev".
    applier = make_applier(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()
    state["workspaces"] = ["default", "cuda-dev-old"]
    fake_env.set_openshell_state(state)
    assert "workspace 'cuda-dev' is missing" in applier.verify(profiles)


def test_dry_run_calls_nothing(ab, fake_env, config, profiles, creds):
    applier = ab.ProfileApplier(ab.Shell(dry_run=True), config, creds)
    applier.apply(profiles)
    assert fake_env.openshell_calls() == []
