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
