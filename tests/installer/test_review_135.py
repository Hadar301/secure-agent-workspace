"""The cases the review of PR #135 reproduced, each now covered.

1. An existing sandbox is held to the same env rules as a new one
   (validation runs in preflight, before any gateway change).
2. A changed (or removed) env variable recreates the sandbox, carrying its
   /sandbox files over, so every process sees exactly the profile's env.
3. A custom, profile-backed provider type (vllm-prod) drives inference
   through the sandbox's typed `inference:` block (protocol, not type).
4. An empty default is one the form and the installer agree on: the field
   is optional, and absent means the default.
"""
import importlib.util
import json

import pytest

from conftest import ROOT

GH_PROFILE = ("id: github\ncredentials:\n  - name: api_token\n"
              "    env_vars: [GITHUB_TOKEN, GH_TOKEN]\n")
VLLM_PROFILE = ("id: vllm-prod\ncredentials:\n  - name: api_key\n"
                "    env_vars: [VLLM_API_KEY]\nendpoints:\n"
                "  - host: vllm.models.example\n    port: 443\n")


def _secret(dirpath, name, **keys):
    base = dirpath / name
    base.mkdir(parents=True, exist_ok=True)
    for key, value in keys.items():
        (base / key).write_text(value)


def _profiles(ab, sandbox, *providers):
    workspace = ab.Workspace(name="default", providers=list(providers), sandboxes=[sandbox])
    return [ab.Profile(name="test", workspaces=[workspace])]


# --- 1. preflight ------------------------------------------------------------------

def test_an_existing_sandbox_is_held_to_the_env_rules_too(ab, fake_env, config, tmp_path):
    github = ab.Provider(name="gh", type="github", credential_secret="gh",
                         credential_secret_key="token")
    sandbox = ab.Sandbox(name="tools", type="generic", providers=["gh"])
    profiles = _profiles(ab, sandbox, github)
    _secret(tmp_path, "gh", token="ghp-x")
    creds = ab.resolve_credentials(profiles, tmp_path)
    docs = {"github": GH_PROFILE}
    ab.ProfileApplier(ab.Shell(), config, creds, provider_profile_docs=docs).apply(profiles)
    assert "default/tools" in fake_env.openshell_state()["sandboxes"]

    # The sandbox exists; a later apply adds GH_TOKEN to its env.
    sandbox.env = {"GH_TOKEN": {"value": "plain"}}
    creds = ab.resolve_credentials(profiles, tmp_path)
    before = len(fake_env.openshell_calls())
    with pytest.raises(ab.InstallerError, match="credential variable of provider 'gh'"):
        ab.ProfileApplier(ab.Shell(), config, creds, provider_profile_docs=docs).apply(profiles)
    # Refused before anything touched the gateway.
    assert fake_env.openshell_calls()[before:] == []


def test_a_named_credential_must_exist_in_the_profile(ab, config, tmp_path):
    github = ab.Provider(name="gh", type="github", credential_secret="gh",
                         credentials_spec={"token": {"secretKey": "token"}})   # profile: api_token
    profiles = _profiles(ab, ab.Sandbox(name="tools", type="generic", providers=["gh"]), github)
    _secret(tmp_path, "gh", token="ghp-x")
    creds = ab.resolve_credentials(profiles, tmp_path)
    with pytest.raises(ab.InstallerError, match="credential 'token' is not one the 'github' "
                                                "profile declares \\(api_token\\)"):
        ab.ProfileApplier(ab.Shell(), config, creds,
                          provider_profile_docs={"github": GH_PROFILE}).apply(profiles)


# --- 2. env updates recreate the sandbox, keeping /sandbox -----------------------------

def _env_sandbox(ab, env):
    provider = ab.Provider(name="inference", type="openai", model="gpt-4o",
                           credential_secret="inference", credential_secret_key="api_key")
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=["inference"], env=env)
    return provider, sandbox, _profiles(ab, sandbox, provider)


def _apply(ab, config, tmp_path, profiles):
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)


def test_a_changed_env_recreates_the_sandbox_with_its_files(ab, fake_env, config, tmp_path):
    _, sandbox, profiles = _env_sandbox(ab, {"HF_HUB_OFFLINE": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    _apply(ab, config, tmp_path, profiles)
    state = fake_env.openshell_state()
    first = state["sandboxes"]["default/chat"]
    assert first["env"] == ["HF_HUB_OFFLINE=1"]
    label = next(l for l in state["labels"]["sandbox/default/chat"] if l.startswith("saw.redhat.com/env="))
    # The user's files in /sandbox.
    first["files"] = {"notes.md": "keep me"}
    fake_env.set_openshell_state(state)

    sandbox.env = {"HF_HUB_OFFLINE": {"value": "0"}}
    _apply(ab, config, tmp_path, profiles)
    state = fake_env.openshell_state()
    second = state["sandboxes"]["default/chat"]
    assert second["env"] == ["HF_HUB_OFFLINE=0"]                       # every process sees it
    assert second["files"] == {"notes.md": "keep me"}                 # carried over
    assert "archives" not in second or not second["archives"]         # cleaned up
    new_label = next(l for l in state["labels"]["sandbox/default/chat"]
                     if l.startswith("saw.redhat.com/env="))
    assert new_label != label
    ops = [" ".join(c[:2]) for c in fake_env.openshell_calls()]
    assert ops.count("sandbox create") == 2 and ops.count("sandbox delete") == 1
    assert "sandbox download" in ops and "sandbox upload" in ops


def test_removing_a_variable_recreates_too(ab, fake_env, config, tmp_path):
    _, sandbox, profiles = _env_sandbox(ab, {"HF_HUB_OFFLINE": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    _apply(ab, config, tmp_path, profiles)
    sandbox.env = {}
    _apply(ab, config, tmp_path, profiles)
    second = fake_env.openshell_state()["sandboxes"]["default/chat"]
    assert "env" not in second                                       # no stale value left
    assert [" ".join(c[:2]) for c in fake_env.openshell_calls()].count("sandbox create") == 2


def test_an_unchanged_env_leaves_the_sandbox_alone(ab, fake_env, config, tmp_path):
    _, _, profiles = _env_sandbox(ab, {"HF_HUB_OFFLINE": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    _apply(ab, config, tmp_path, profiles)
    _apply(ab, config, tmp_path, profiles)
    ops = [" ".join(c[:2]) for c in fake_env.openshell_calls()]
    assert ops.count("sandbox create") == 1 and "sandbox delete" not in ops


def test_a_failed_archive_still_recreates_but_says_so(ab, fake_env, config, tmp_path, capsys):
    _, sandbox, profiles = _env_sandbox(ab, {"A": {"value": "1"}})
    _secret(tmp_path, "inference", api_key="k")
    _apply(ab, config, tmp_path, profiles)
    (fake_env.state / "preserve-fail").write_text("")
    sandbox.env = {"A": {"value": "2"}}
    _apply(ab, config, tmp_path, profiles)
    assert fake_env.openshell_state()["sandboxes"]["default/chat"]["env"] == ["A=2"]
    assert "not carried over" in capsys.readouterr().out


# --- 3. a custom provider type drives inference by protocol -----------------------------

def test_a_custom_profile_type_onboards_through_the_inference_block(ab, fake_env, config, tmp_path):
    vllm = ab.Provider(name="internal-llm", type="vllm-prod", credential_secret="vllm",
                       credential_secret_key="api_key")
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=["internal-llm"], inference={
        "providerRef": "internal-llm", "protocol": "openai",
        "baseUrl": "https://vllm.models.example/v1", "model": "llama-3.1-8b",
        "timeoutSeconds": "300"})
    profiles = _profiles(ab, sandbox, vllm)
    ab.validate_profiles(profiles, known_profiles={"vllm-prod"})
    _secret(tmp_path, "vllm", api_key="vk")
    creds = ab.resolve_credentials(profiles, tmp_path)
    assert sandbox.inference_values == {"providerRef": "internal-llm", "protocol": "openai",
                                        "baseUrl": "https://vllm.models.example/v1",
                                        "model": "llama-3.1-8b", "timeoutSeconds": 300}
    ab.ProfileApplier(ab.Shell(), config, creds,
                      provider_profile_docs={"vllm-prod": VLLM_PROFILE}).apply(profiles)
    state = fake_env.openshell_state()
    # The credential went through the profile's env var...
    assert state["providers"]["default/internal-llm"]["credential"] == "VLLM_API_KEY=vk"
    # ...and the agent was onboarded against the endpoint, not skipped.
    onboard = next(c[-1] for c in fake_env.openshell_calls()
                   if c[:2] == ["sandbox", "exec"] and "openclaw onboard " in c[-1])
    assert "--auth-choice custom-api-key " in onboard
    assert "--custom-base-url https://vllm.models.example/v1 " in onboard
    assert "--custom-model-id llama-3.1-8b " in onboard
    assert 'CUSTOM_API_KEY="$VLLM_API_KEY"' in onboard


def test_provider_ref_picks_the_inference_provider(ab, fake_env, config, tmp_path):
    """Two providers on the sandbox; providerRef decides, not order or a
    provider-level model."""
    nvidia = ab.Provider(name="nvidia", type="nvidia", model="nvidia/x",
                         credential_secret="inference", credential_secret_key="api_key")
    openai = ab.Provider(name="openai", type="openai",
                         credential_secret="inference-openai", credential_secret_key="api_key")
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=["nvidia", "openai"],
                         inference={"providerRef": "openai", "protocol": "openai", "model": "gpt-4o"})
    profiles = _profiles(ab, sandbox, nvidia, openai)
    _secret(tmp_path, "inference", api_key="nv")
    _secret(tmp_path, "inference-openai", api_key="sk")
    creds = ab.resolve_credentials(profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    onboard = next(c[-1] for c in fake_env.openshell_calls()
                   if c[:2] == ["sandbox", "exec"] and "openclaw onboard " in c[-1])
    assert "--auth-choice openai-api-key" in onboard                  # the official API, natively


def test_inference_block_is_validated(ab):
    nvidia = ab.Provider(name="nvidia", type="nvidia", credential_secret="inference")
    bad = {"providerRef": "missing", "protocol": "grpc", "baseUrl": {"secretKeyRef": {"name": "x"}}}
    sandbox = ab.Sandbox(name="chat", type="openclaw", providers=["nvidia"], inference=bad)
    with pytest.raises(ab.InstallerError) as err:
        ab.validate_profiles(_profiles(ab, sandbox, nvidia))
    text = str(err.value)
    assert "providerRef 'missing' is not an enabled provider" in text
    assert "protocol must be one of anthropic, openai" in text
    assert "inference needs model" in text
    assert "inference baseUrl secretKeyRef.key must be a valid Secret key" in text


# --- 4. empty default: optional in the form, default in the installer -------------------

def _catalog():
    spec = importlib.util.spec_from_file_location(
        "saw_profile_catalog", ROOT / "scripts" / "saw-profile-catalog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_an_empty_default_is_optional_in_the_form_and_the_installer(ab, tmp_path):
    cat = _catalog()
    src = {"secretKeyRef": {"name": "inference", "key": "org"}, "default": ""}
    field = cat.input_field(src, "text", "Org")
    assert field["required"] is False and field["default"] == ""
    # A default means "not required" unless said otherwise; no default means required.
    ref = {"secretKeyRef": {"name": "s", "key": "k"}}
    assert cat.input_field(ref, "text", "t")["required"] is True
    assert cat.input_field({**ref, "default": "x", "required": True}, "text", "t")["required"] is True
    # The installer: absent with an empty default is "" (no error).
    assert ab.resolve_input(src, tmp_path, "org") == ""
    with pytest.raises(ab.InstallerError, match="not found"):
        ab.resolve_input({"secretKeyRef": {"name": "inference", "key": "org"}}, tmp_path, "org")


def test_the_portal_accepts_an_absent_optional_field(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "portal", ROOT / "charts" / "openshell-rhdh" / "files" / "portal.py")
    portal = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(portal)
    catalog = {"p": {"secrets": {"inference": {"provider": "openai", "fields": [
        {"key": "api_key", "kind": "secret", "required": True, "title": "API key"},
        {"key": "org", "kind": "text", "required": False, "default": "", "title": "Org"},
        {"key": "url", "kind": "url", "required": False, "default": "", "title": "URL"}]}}}}
    profile, secrets = portal.parse_request({"profile": "p", "inference.api_key": "sk"}, catalog)
    assert secrets == {"inference": {"api_key": "sk", "provider": "openai"}}
    with pytest.raises(portal.PortalError, match="needs: inference.api_key"):
        portal.parse_request({"profile": "p"}, catalog)


def test_the_shipped_form_fields_match_the_profiles():
    cat = json.loads((ROOT / "charts" / "openshell-rhdh" / "files" /
                      "profile-catalog.json").read_text())["profiles"]
    custom = {f["key"]: f for f in cat["custom-inference"]["secrets"]["inference"]["fields"]}
    assert set(custom) == {"api_key", "url", "model"}
    assert custom["url"]["kind"] == "url" and custom["url"]["required"]
    ds = {f["key"]: f for f in cat["data-science"]["secrets"]["inference"]["fields"]}
    # One model field per sandbox: selections are not coupled.
    assert {"model", "cuda_model"} <= set(ds)
    assert ds["model"]["title"] != ds["cuda_model"]["title"]
    assert not ds["model"]["required"] and ds["model"]["default"].startswith("nvidia/")
