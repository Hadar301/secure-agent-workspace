"""Unit tests for the pure-Python pieces of apply_bom.py — profile parsing,
credential resolution, and provider selection/validation. None of these need
a live gateway VM or cluster.

Run with:
    pip install pytest pyyaml
    pytest charts/saw-bom/scripts/test_apply_bom.py -v
"""
import os
import sys
import json
import subprocess
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, os.path.dirname(__file__))

from apply_bom import (  # noqa: E402
    Provider,
    Sandbox,
    Workspace,
    check_provider_type_mismatch,
    find_provider,
    parse_profiles,
    resolve_configured_type,
    resolve_credential,
    runtime_command,
    WorkspaceDeployer,
    custom_endpoint,
    validate_custom_profile,
    eligible_resources,
    Profile,
    Verifier,
    Shell,
)


def _write_profile(root, profile="data-science", workspace="default",
                    workspace_yaml=None, providers_yaml=None, sandbox_yaml=None):
    """Write a minimal BOM profile directory tree under `root`."""
    ws_dir = root / profile / workspace
    ws_dir.mkdir(parents=True, exist_ok=True)

    default_workspace_yaml = {
        "apiVersion": "saw.redhat.com/v1alpha1",
        "kind": "Workspace",
        "metadata": {"name": workspace},
        "spec": {"enabled": True},
    }
    (ws_dir / "workspace.yaml").write_text(
        yaml.safe_dump(workspace_yaml or default_workspace_yaml))

    if providers_yaml is not None:
        (ws_dir / "providers.yaml").write_text(yaml.safe_dump(providers_yaml))
    if sandbox_yaml is not None:
        (ws_dir / "sandbox.yaml").write_text(yaml.safe_dump(sandbox_yaml))

    return ws_dir


# ---------------------------------------------------------------------------
# parse_profiles()
# ---------------------------------------------------------------------------

def test_parse_profiles_basic(tmp_path):
    _write_profile(
        tmp_path,
        providers_yaml={"spec": {"providers": [
            {"name": "nvidia", "type": "nvidia", "nemoclawProvider": "build",
             "credentialSecret": "inference", "credentialSecretKey": "api_key"},
        ]}},
        sandbox_yaml={"spec": {"sandboxes": [
            {"name": "notebook", "type": "openclaw", "enabled": True,
             "providers": ["nvidia"]},
        ]}},
    )
    profiles = parse_profiles(tmp_path)
    assert len(profiles) == 1
    ws = profiles[0].workspaces[0]
    assert ws.name == "default"
    assert [p.name for p in ws.providers] == ["nvidia"]
    assert ws.providers[0].nemoclaw_provider == "build"
    assert [sb.name for sb in ws.sandboxes] == ["notebook"]
    assert ws.sandboxes[0].providers == ["nvidia"]


def test_parse_profiles_skips_workspace_dir_missing_workspace_yaml(tmp_path):
    # A directory with no workspace.yaml at all should be skipped, not crash.
    bogus_dir = tmp_path / "data-science" / "not-a-workspace"
    bogus_dir.mkdir(parents=True)
    (bogus_dir / "sandbox.yaml").write_text("spec:\n  sandboxes: []\n")
    profiles = parse_profiles(tmp_path)
    assert profiles == []


def test_parse_profiles_no_profiles_dir_entries(tmp_path):
    assert parse_profiles(tmp_path) == []


def test_parse_profiles_disabled_workspace_still_parsed(tmp_path):
    _write_profile(
        tmp_path,
        workspace_yaml={"metadata": {"name": "cuda-dev"},
                         "spec": {"enabled": False}},
        providers_yaml={"spec": {"providers": []}},
        sandbox_yaml={"spec": {"sandboxes": []}},
    )
    profiles = parse_profiles(tmp_path)
    ws = profiles[0].workspaces[0]
    assert ws.enabled is False


# ---------------------------------------------------------------------------
# resolve_credential()
# ---------------------------------------------------------------------------

def test_resolve_credential_prefers_provider_specific_env(monkeypatch):
    monkeypatch.setenv("PROV_NVIDIA_KEY", "specific-key")
    monkeypatch.setenv("NVIDIA_API_KEY", "generic-key")
    p = Provider(name="nvidia", type="nvidia")
    assert resolve_credential(p) == "specific-key"


def test_resolve_credential_falls_back_to_type_map(monkeypatch):
    monkeypatch.delenv("PROV_NVIDIA_KEY", raising=False)
    monkeypatch.setenv("NVIDIA_API_KEY", "generic-key")
    p = Provider(name="nvidia", type="nvidia")
    assert resolve_credential(p) == "generic-key"


def test_resolve_credential_none_when_unset(monkeypatch):
    monkeypatch.delenv("PROV_NVIDIA_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    p = Provider(name="nvidia", type="nvidia")
    assert resolve_credential(p) is None


def test_resolve_credential_handles_hyphenated_names(monkeypatch):
    monkeypatch.setenv("PROV_GOOGLE_VERTEX_AI_KEY", "vertex-key")
    p = Provider(name="google-vertex-ai", type="google-vertex-ai")
    assert resolve_credential(p) == "vertex-key"


# ---------------------------------------------------------------------------
# find_provider() — regression test for the ws.providers[0] bug (finding #5):
# reordering providers.yaml must never change which provider a sandbox that
# declares its own `providers:` list actually gets.
# ---------------------------------------------------------------------------

def _ws_with_providers(*names_and_types):
    ws = Workspace(name="default")
    for name, ptype in names_and_types:
        ws.providers.append(Provider(name=name, type=ptype))
    return ws


def test_find_provider_selects_by_declared_name_not_index():
    ws = _ws_with_providers(("brave", "brave"), ("nvidia", "nvidia"))
    prov = find_provider(ws, ["nvidia"])
    assert prov.name == "nvidia"


def test_find_provider_order_independent():
    # Same providers, opposite order — result must be identical.
    ws_a = _ws_with_providers(("nvidia", "nvidia"), ("brave", "brave"))
    ws_b = _ws_with_providers(("brave", "brave"), ("nvidia", "nvidia"))
    assert find_provider(ws_a, ["nvidia"]).name == "nvidia"
    assert find_provider(ws_b, ["nvidia"]).name == "nvidia"


def test_find_provider_falls_back_to_first_when_no_names_declared():
    ws = _ws_with_providers(("nvidia", "nvidia"))
    assert find_provider(ws, []).name == "nvidia"
    assert find_provider(ws, None).name == "nvidia"


def test_find_provider_falls_back_when_declared_name_not_found():
    ws = _ws_with_providers(("nvidia", "nvidia"))
    prov = find_provider(ws, ["does-not-exist"])
    assert prov.name == "nvidia"  # falls back to index 0, not None


def test_find_provider_none_when_workspace_has_no_providers():
    ws = Workspace(name="default")
    assert find_provider(ws, ["nvidia"]) is None


# ---------------------------------------------------------------------------
# check_provider_type_mismatch() — regression test for finding #14.
# ---------------------------------------------------------------------------

def test_provider_type_mismatch_none_when_no_configured_type(monkeypatch):
    monkeypatch.delenv("PROV_NVIDIA_TYPE", raising=False)
    p = Provider(name="nvidia", type="nvidia", nemoclaw_provider="build")
    assert check_provider_type_mismatch(p) is None


def test_provider_type_mismatch_accepts_nemoclaw_alias(monkeypatch):
    # values-secret.yaml.template documents NVIDIA's provider identifier as
    # "build", distinct from the OpenShell provider type "nvidia" — this
    # must NOT be flagged as a mismatch for the bundled default profile.
    monkeypatch.setenv("PROV_NVIDIA_TYPE", "build")
    p = Provider(name="nvidia", type="nvidia", nemoclaw_provider="build")
    assert check_provider_type_mismatch(p) is None


def test_provider_type_mismatch_detects_real_mismatch(monkeypatch):
    monkeypatch.setenv("PROV_NVIDIA_TYPE", "gemini")
    p = Provider(name="nvidia", type="nvidia", nemoclaw_provider="build")
    msg = check_provider_type_mismatch(p)
    assert msg is not None
    assert "gemini" in msg


def test_resolve_configured_type_reads_env(monkeypatch):
    monkeypatch.setenv("PROV_NVIDIA_TYPE", "build")
    p = Provider(name="nvidia", type="nvidia")
    assert resolve_configured_type(p) == "build"


def test_resolve_configured_type_none_when_unset(monkeypatch):
    monkeypatch.delenv("PROV_NVIDIA_TYPE", raising=False)
    p = Provider(name="nvidia", type="nvidia")
    assert resolve_configured_type(p) is None


# ---------------------------------------------------------------------------
# Container runtime selection
# ---------------------------------------------------------------------------

def test_runtime_command_uses_rootless_podman(monkeypatch):
    monkeypatch.setenv("CONTAINER_RUNTIME", "podman")
    assert runtime_command("pull", "example/image:latest") == [
        "podman", "pull", "example/image:latest"
    ]


def test_runtime_command_uses_podman_default(monkeypatch):
    monkeypatch.delenv("CONTAINER_RUNTIME", raising=False)
    assert runtime_command("pull", "example/image:latest") == [
        "podman", "pull", "example/image:latest"
    ]


def test_sandbox_fallback_keeps_workload_alive():
    class RecordingShell:
        dry_run = False

        def __init__(self):
            self.calls = []

        def run(self, cmd, **kwargs):
            self.calls.append(cmd)
            if cmd[:3] == ["openshell", "sandbox", "get"]:
                return 1, "", "sandbox not found"
            return 0, "", ""

    shell = RecordingShell()
    deployer = WorkspaceDeployer(shell, gateway_setup=None)
    deployer.create_sandbox_generic(
        Sandbox(name="cuda-sandbox", image="quay.io/example/sandbox:latest"),
        workspace_name="cuda-dev",
    )

    create = next(cmd for cmd in shell.calls
                  if cmd[:3] == ["openshell", "sandbox", "create"])
    assert "--detach" in create
    assert create[-3:] == ["sh", "-c", "sleep infinity"]


def test_completed_sandbox_is_recreated_for_fallback():
    class ExistingCompletedShell:
        dry_run = False

        def __init__(self):
            self.calls = []

        def run(self, cmd, **kwargs):
            self.calls.append(cmd)
            if cmd[:3] == ["openshell", "sandbox", "get"]:
                return 0, "Phase: Completed", ""
            return 0, "", ""

    shell = ExistingCompletedShell()
    WorkspaceDeployer(shell, gateway_setup=None).create_sandbox_generic(
        Sandbox(name="cuda-sandbox"), workspace_name="cuda-dev")

    assert ["openshell", "sandbox", "delete", "cuda-sandbox",
            "--workspace", "cuda-dev"] in shell.calls


def custom_provider(**kwargs):
    return Provider(name="custom-inference", type="custom-inference", nemoclaw_provider="custom",
                    url=kwargs.get("url", "https://inference.example.com/v1"),
                    model=kwargs.get("model", "tinyllama:latest"))


def catalog(scheme="https", port=443):
    return {"id": "custom-inference", "credentials": [{"env_vars": ["OPENAI_API_KEY"],
            "required": True, "auth_style": "bearer", "header_name": "authorization"}],
            "endpoints": [{"host": "inference.example.com", "port": port, "protocol": "rest",
                           "enforcement": "enforce", "access": "read-write",
                           "tls": "terminate" if scheme == "https" else "passthrough"}]}


@pytest.mark.parametrize("url", ["", "inference.example.com/v1", "ftp://inference.example.com",
    "https://u:p@inference.example.com/v1", "https://inference.example.com/v1?q=secret",
    "https://inference.example.com/#fragment", "https://inference.example.com/?",
    "https://inference.example.com:0/v1", "https://inference.example.com:65536",
    "https://inference.example.com/a b", "https://inference.example.com:bad"])
def test_reject_custom_url(url):
    with pytest.raises(ValueError):
        custom_endpoint(url)


@pytest.mark.parametrize("url,scheme,port", [
    ("https://INFERENCE.example.com.:443/v1", "https", 443),
    ("http://inference.example.com:8080/api/v1", "http", 8080)])
def test_custom_endpoint_approved(url, scheme, port):
    validate_custom_profile(custom_provider(url=url), "key", catalog(scheme, port))


@pytest.mark.parametrize("change", ["host", "port", "tls", "credentials", "id"])
def test_custom_policy_mismatch(change):
    profile = catalog()
    if change in {"host", "port", "tls"}:
        profile["endpoints"][0][change] = "wrong"
    else:
        profile[change] = [] if change == "credentials" else "openai"
    with pytest.raises(ValueError):
        validate_custom_profile(custom_provider(), "key", profile)


@pytest.mark.parametrize("model,key", [("", "key"), ("  ", "key"), ("model", ""), ("model", None)])
def test_custom_required_fields(model, key):
    with pytest.raises(ValueError):
        validate_custom_profile(custom_provider(model=model), key, catalog())


@pytest.mark.parametrize("configured,eligible", [("custom", True), ("openai", False),
    ("build", False), ("nvidia", False), ("gemini", False), ("", False)])
def test_custom_eligibility_consistent(monkeypatch, configured, eligible):
    monkeypatch.setenv("PROV_CUSTOM_INFERENCE_TYPE", configured)
    monkeypatch.setenv("PROV_NVIDIA_TYPE", configured)
    ws = Workspace(name="vllm", providers=[custom_provider(), Provider("nvidia", "nvidia", nemoclaw_provider="build")],
                   sandboxes=[Sandbox("notebook", providers=["custom-inference"]),
                              Sandbox("mixed", providers=["custom-inference", "nvidia"])])
    providers, sandboxes = eligible_resources(ws)
    assert ("custom-inference" in [p.name for p in providers]) == eligible
    assert ("notebook" in [s.name for s in sandboxes]) == eligible
    assert "mixed" not in [s.name for s in sandboxes]
    fake = CustomShell()
    if not providers:
        assert Verifier(fake).verify_profiles([Profile("example", [ws])])
        assert not fake.calls


class CustomShell:
    dry_run = False

    def __init__(self, existing=None, fail=None, phase="Ready", attached=True):
        self.calls = []
        self.existing = existing or []
        self.fail = fail
        self.phase = phase
        self.attached = attached

    def run(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if self.fail and self.fail(cmd):
            return 1, "", "deliberate failure"
        if cmd[:4] == ["openshell", "provider", "profile", "export"]:
            return 0, json.dumps(catalog()), ""
        if cmd[:3] == ["openshell", "provider", "list"]:
            return 0, json.dumps(self.existing), ""
        if cmd[:3] == ["openshell", "sandbox", "get"]:
            if self.phase is None:
                return 1, "", "sandbox not found"
            return 0, json.dumps({"name": "notebook", "workspace": "vllm", "phase": self.phase,
                "policy_source": "sandbox", "policy": {"network_policies": {"_provider_custom_inference": {}}}}), ""
        if cmd[:4] == ["openshell", "sandbox", "provider", "list"]:
            return 0, "NAME TYPE CREDENTIAL_KEYS CONFIG_KEYS\ncustom-inference custom-inference 1 2" if self.attached else "No providers attached", ""
        if "ps" in cmd:
            return 0, "openshell-other--notebook-abc\nopenshell-vllm--notebook-123", ""
        return 0, "", ""


def test_provider_creation_uses_env_and_preserves_url(monkeypatch):
    monkeypatch.setenv("PROV_CUSTOM_INFERENCE_TYPE", "custom")
    sh = CustomShell()
    assert WorkspaceDeployer(sh, None).create_provider(custom_provider(), "private-key", "vllm")
    cmd, args = sh.calls[-1]
    assert cmd[:3] == ["openshell", "provider", "create"]
    assert "private-key" not in " ".join(cmd)
    assert args["env"] == {"OPENAI_API_KEY": "private-key"}
    assert "base_url=https://inference.example.com/v1" in cmd
    assert "model=tinyllama:latest" in cmd
    assert args["allow_existing"] is False


@pytest.mark.parametrize("field,value", [("type", "openai"), ("workspace", "other"),
    ("credential_keys", ["API_KEY"]), ("config_keys", ["base_url", "unapproved"])])
def test_conflicting_provider_not_modified(field, value):
    row = {"name": "custom-inference", "workspace": "vllm", "type": "custom-inference",
           "credential_keys": ["OPENAI_API_KEY"], "config_keys": ["base_url", "model"]}
    row[field] = value
    sh = CustomShell(existing=[row])
    assert not WorkspaceDeployer(sh, None).create_custom_provider(custom_provider(), "k", "vllm")
    assert not any(cmd[2] in {"update", "create"} for cmd, _ in sh.calls)


def test_existing_provider_reconciles_required_values():
    row = {"name": "custom-inference", "workspace": "vllm", "type": "custom-inference",
           "credential_keys": ["OPENAI_API_KEY"], "config_keys": ["base_url", "model"]}
    sh = CustomShell(existing=[row])
    deployer = WorkspaceDeployer(sh, None)
    for _ in range(2):
        assert deployer.create_custom_provider(custom_provider(), "new-key", "vllm")
    assert sum(cmd[:3] == ["openshell", "provider", "update"] for cmd, _ in sh.calls) == 2


def test_provider_failure_propagated():
    sh = CustomShell(fail=lambda c: c[:3] == ["openshell", "provider", "create"])
    assert not WorkspaceDeployer(sh, None).create_custom_provider(custom_provider(), "key", "vllm")


@pytest.mark.parametrize("phase,attached", [("Error", True), ("Completed", True), ("Ready", False)])
def test_sandbox_conflict_preserves_data(phase, attached):
    sh = CustomShell(phase=phase, attached=attached)
    sb = Sandbox("notebook", providers=["custom-inference"])
    assert not WorkspaceDeployer(sh, None).provision_custom_sandbox(sb, custom_provider(), "vllm")
    assert not any("delete" in cmd or "pull" in cmd for cmd, _ in sh.calls)


def test_failed_creation_does_not_poll_or_onboard():
    sh = CustomShell(phase=None, fail=lambda c: c[:3] == ["openshell", "sandbox", "create"])
    assert not WorkspaceDeployer(sh, None).provision_custom_sandbox(
        Sandbox("notebook", providers=["custom-inference"]), custom_provider(), "vllm")
    assert sum(cmd[:3] == ["openshell", "sandbox", "get"] for cmd, _ in sh.calls) == 1
    assert not any("exec" in cmd for cmd, _ in sh.calls)


def test_sandbox_timeout_does_not_onboard(monkeypatch):
    monkeypatch.setattr("apply_bom.time.sleep", lambda _: None)
    sh = CustomShell(phase="Provisioning")
    assert not WorkspaceDeployer(sh, None).provision_custom_sandbox(
        Sandbox("notebook", providers=["custom-inference"]), custom_provider(), "vllm")
    assert not any("exec" in cmd for cmd, _ in sh.calls)


@pytest.mark.parametrize("stage", ["placeholder", "onboard", "health", None])
def test_custom_openclaw_failure_and_repeat_setup(monkeypatch, stage):
    monkeypatch.setattr("apply_bom.time.sleep", lambda _: None)
    def fail(cmd):
        text = " ".join(cmd)
        return ((stage == "placeholder" and cmd[-1].startswith('case "${OPENAI_API_KEY'))
                or (stage == "onboard" and "openclaw onboard" in text)
                or (stage == "health" and "http://127.0.0.1:18789/health" in cmd))
    sh = CustomShell(fail=fail)
    deployer = WorkspaceDeployer(sh, None)
    for _ in range(2):
        assert deployer.provision_custom_sandbox(Sandbox("notebook", providers=["custom-inference"]),
                                                custom_provider(), "vllm") == (stage is None)
    texts = [" ".join(c) for c, _ in sh.calls]
    repairs = [c for c, _ in sh.calls if "chown" in c]
    assert all("openshell-vllm--notebook-123" in c for c in repairs)
    assert not any("openshell-other--notebook-abc" in c for c in repairs)
    if stage != "placeholder":
        onboard = next(t for t in texts if "openclaw onboard" in t)
        assert 'CUSTOM_API_KEY="$OPENAI_API_KEY"' in onboard
        assert "https://inference.example.com/v1" in onboard
        assert "tinyllama:latest" in onboard
        assert "inference.local" not in onboard and "nvidia/" not in onboard


def test_shell_redacts_credential_output(monkeypatch, capsys):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=1, stdout="echo private-key", stderr="error private-key"))
    result = Shell().run(["openshell", "provider", "create", "--credential", "OPENAI_API_KEY"],
                         env={"OPENAI_API_KEY": "private-key"})
    assert result[0] == 1
    assert "private-key" not in capsys.readouterr().out


def test_secret_redaction_preserves_json_for_callers(monkeypatch, capsys):
    output = '{"credential_keys": ["OPENAI_API_KEY"]}'
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=output, stderr=""))
    _, actual, _ = Shell().run(["openshell", "provider", "list"], env={"OPENAI_API_KEY": "k"})
    assert json.loads(actual) == json.loads(output)
    assert "credential_keys" not in capsys.readouterr().out


def test_onboarding_home_is_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    sh = CustomShell()
    WorkspaceDeployer(sh, None).onboard_nemoclaw(Sandbox("example"), Provider("gemini", "gemini"), "test-key")
    assert (tmp_path / "gateway-management.json").exists()


@pytest.mark.parametrize("kind,alias", [("gemini", "gemini"), ("nvidia", "build"),
                                       ("codex", "openai"), ("claude-code", "anthropic")])
def test_cloud_aliases_remain_eligible(monkeypatch, kind, alias):
    monkeypatch.setenv("PROV_CLOUD_TYPE", alias)
    provider = Provider("cloud", kind, nemoclaw_provider=alias)
    assert check_provider_type_mismatch(provider) is None
    monkeypatch.delenv("PROV_CLOUD_TYPE")
    assert check_provider_type_mismatch(provider) is None


def test_parse_custom_secret_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("PROV_CUSTOM_INFERENCE_URL", "http://inference.example.com:8080/v1")
    monkeypatch.setenv("PROV_CUSTOM_INFERENCE_MODEL", "model-from-secret")
    _write_profile(tmp_path, providers_yaml={"spec": {"providers": [{
        "name": "custom-inference", "type": "custom-inference",
        "urlSecretKey": "url", "modelSecretKey": "model"}]}})
    provider = parse_profiles(tmp_path)[0].workspaces[0].providers[0]
    assert provider.url == "http://inference.example.com:8080/v1"
    assert provider.model == "model-from-secret"


def test_workspace_failure_stops_membership_setup():
    sh = CustomShell(fail=lambda c: c[:3] == ["openshell", "workspace", "create"])
    gw = SimpleNamespace(_with_oidc=lambda fn: fn())
    assert not WorkspaceDeployer(sh, gw).create_workspace(Workspace("vllm"))
    assert len(sh.calls) == 1


def test_provider_failure_stops_main_before_sandbox(tmp_path, monkeypatch):
    import apply_bom
    _write_profile(tmp_path, workspace="vllm", providers_yaml={"spec": {"providers": [{
        "name": "custom-inference", "type": "custom-inference", "nemoclawProvider": "custom",
        "url": "https://inference.example.com/v1", "model": "model"}]}},
        sandbox_yaml={"spec": {"sandboxes": [{"name": "notebook", "type": "openclaw",
                                               "providers": ["custom-inference"]}]}})
    monkeypatch.setenv("PROV_CUSTOM_INFERENCE_TYPE", "custom")
    monkeypatch.setenv("PROV_CUSTOM_INFERENCE_KEY", "test-key")
    monkeypatch.setattr(sys, "argv", ["apply_bom.py", "--profiles-dir", str(tmp_path)])
    sh = CustomShell(fail=lambda c: c[:3] == ["openshell", "provider", "create"])
    monkeypatch.setattr(apply_bom, "Shell", lambda **kw: sh)
    gw = SimpleNamespace(configure_oidc=lambda *a: None, register_mtls_gateway=lambda: None,
                         grant_default_workspace_access=lambda: None,
                         enable_providers_v2=lambda: None, _with_oidc=lambda fn: fn())
    monkeypatch.setattr(apply_bom, "GatewaySetup", lambda *a: gw)
    with pytest.raises(SystemExit, match="Provider provisioning failed"):
        apply_bom.main()
    assert not any(cmd[:2] == ["openshell", "sandbox"] or "pull" in cmd for cmd, _ in sh.calls)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
