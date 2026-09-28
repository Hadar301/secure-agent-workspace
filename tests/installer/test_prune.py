"""Profile pruning removes only objects the installer recorded."""

import json

import pytest


@pytest.fixture
def profiles(ab, shipped_profile_files):
    return ab.parse_profiles(shipped_profile_files)


@pytest.fixture
def creds(ab, profiles, secrets_dir):
    return ab.resolve_credentials(profiles, secrets_dir)


def test_first_apply_adopts_and_deletes_nothing(ab, fake_env, config, profiles, creds, tmp_path, capsys):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    saved = json.loads(ledger.read_text())
    assert saved["adopted"] is True
    assert saved["lastPrune"] == {"pruned": [], "wouldPrune": []}
    assert "cuda-dev/cuda-sandbox" in fake_env.openshell_state()["sandboxes"]
    assert "pruning nothing" in capsys.readouterr().out


def test_report_mode_keeps_a_removed_sandbox(ab, fake_env, config, profiles, creds, tmp_path, capsys):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "report", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    for profile in profiles:
        for ws in profile.workspaces:
            ws.sandboxes = [sb for sb in ws.sandboxes if sb.name != "cuda-sandbox"]
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    assert "cuda-dev/cuda-sandbox" in fake_env.openshell_state()["sandboxes"]
    assert "would delete sandbox cuda-dev/cuda-sandbox" in capsys.readouterr().out


def test_on_mode_deletes_a_removed_sandbox_and_empty_workspace(ab, fake_env, config, profiles, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    for profile in profiles:
        profile.workspaces = [ws for ws in profile.workspaces if ws.name != "cuda-dev"]
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    state = fake_env.openshell_state()
    assert "cuda-dev/cuda-sandbox" not in state["sandboxes"]
    assert "cuda-dev" not in state["workspaces"]
    assert "default" in state["workspaces"]


def test_sandboxes_stay_when_prune_sandboxes_is_false(ab, fake_env, config, profiles, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": False, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    for profile in profiles:
        profile.workspaces = [ws for ws in profile.workspaces if ws.name != "cuda-dev"]
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    state = fake_env.openshell_state()
    assert "cuda-dev/cuda-sandbox" in state["sandboxes"]
    assert "cuda-dev" in state["workspaces"]


def test_a_hand_created_sandbox_is_never_deleted(ab, fake_env, config, profiles, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/mine"] = {"image": "base", "providers": [], "phase": "Ready"}
    fake_env.set_openshell_state(state)
    for profile in profiles:
        for ws in profile.workspaces:
            ws.sandboxes = [sb for sb in ws.sandboxes if sb.name != "notebook"]
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    assert "default/mine" in fake_env.openshell_state()["sandboxes"]


def test_empty_profiles_delete_nothing(ab, fake_env, config, profiles, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    before = fake_env.openshell_state()["sandboxes"].keys()
    with pytest.raises(ab.InstallerError, match="missing or empty"):
        ab.ProfileApplier(ab.Shell(), cfg, creds).apply([])
    assert set(fake_env.openshell_state()["sandboxes"]) == set(before)


def test_default_workspace_is_never_deleted(ab, fake_env, config, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    # Seed an adopted ledger entry and prune directly. apply refuses an empty
    # profile list, so this does not go through apply.
    applier = ab.ProfileApplier(ab.Shell(), cfg, creds)
    applier.ledger.data = {
        "version": 1, "adopted": True,
        "objects": [{"kind": "workspace", "workspace": "", "name": "default",
                     "profile": "data-science", "adopted": True, "createdAt": "t"}],
    }
    applier.desired = set()
    applier.prune()
    assert any(obj["name"] == "default" for obj in applier.ledger.data["objects"])


def _drop_provider(profiles, workspace, name):
    for profile in profiles:
        for ws in profile.workspaces:
            if ws.name == workspace:
                ws.providers = [p for p in ws.providers if p.name != name]


def test_removing_a_provider_deletes_it_only_when_on(ab, fake_env, config, profiles, creds, tmp_path, capsys):
    ledger = tmp_path / "managed.json"
    report = {**config, "prune": {"mode": "report", "sandboxes": False, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), report, creds).apply(profiles)
    _drop_provider(profiles, "default", "brave")
    before = [c for c in fake_env.openshell_calls() if "delete" in c]
    ab.ProfileApplier(ab.Shell(), report, creds).apply(profiles)
    assert "default/brave" in fake_env.openshell_state()["providers"]
    assert [c for c in fake_env.openshell_calls() if "delete" in c] == before
    assert "would delete provider default/brave" in capsys.readouterr().out
    on = {**config, "prune": {"mode": "on", "sandboxes": False, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), on, creds).apply(profiles)
    assert "default/brave" not in fake_env.openshell_state()["providers"]


def test_hand_made_workspace_and_provider_are_never_deleted(ab, fake_env, config, profiles, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["workspaces"].append("notes")
    state["providers"]["default/mine"] = {"type": "openai", "credential": "local"}
    fake_env.set_openshell_state(state)
    for profile in profiles:
        profile.workspaces = [ws for ws in profile.workspaces if ws.name != "cuda-dev"]
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    state = fake_env.openshell_state()
    assert "notes" in state["workspaces"]
    assert "default/mine" in state["providers"]
