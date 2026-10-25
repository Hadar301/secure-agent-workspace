"""Typed provider config must preserve the VM credential boundary."""
from copy import deepcopy

import pytest

from conftest import marker, proxy_for, resolve


def named(ab, tmp_path):
    p = ab.Provider(name="keys", type="github", credential_secret="keys",
                    credentials_spec={"api_token": {"secretKey": "token"},
                                      "other": {"secretKey": "app_secret"}})
    (tmp_path / "keys").mkdir()
    profiles = [ab.Profile(name="test", workspaces=[ab.Workspace(name="default", providers=[p])])]
    return p, profiles


@pytest.mark.parametrize("key", ["token", "app_secret"])
def test_every_named_key_is_refused_on_vm_disk(ab, tmp_path, key):
    _, profiles = named(ab, tmp_path)
    (tmp_path / "keys" / key).write_text("must-stay-in-proxy")
    with pytest.raises(ab.InstallerError, match="present on a VM disk"):
        resolve(ab, profiles, tmp_path)


def test_named_credentials_have_distinct_markers_and_require_each_binding(ab, tmp_path):
    p, profiles = named(ab, tmp_path)
    proxy = proxy_for(ab, profiles)
    ab.resolve_credentials(profiles, tmp_path, proxy)
    assert p.credential_values == {"api_token": marker("keys", "token"),
                                    "other": marker("keys", "app_secret")}
    proxy["secrets"] = [b for b in proxy["secrets"] if b["key"] != "app_secret"]
    with pytest.raises(ab.InstallerError, match="has no binding"):
        ab.resolve_credentials(profiles, tmp_path, proxy)


def test_secondary_named_binding_must_allow_the_provider(ab, tmp_path):
    _, profiles = named(ab, tmp_path)
    proxy = proxy_for(ab, profiles)
    next(b for b in proxy["secrets"] if b["key"] == "app_secret")["providers"] = ["openai"]
    with pytest.raises(ab.InstallerError, match="provider type is not allowed"):
        ab.resolve_credentials(profiles, tmp_path, proxy)


@pytest.mark.parametrize("typ", ["nvidia", "build"])
def test_shared_secret_without_provider_uses_authoritative_binding(ab, tmp_path, typ):
    p = ab.Provider(name="nvidia", type=typ, credential_secret="inference")
    sb = ab.Sandbox(name="chat", type="openclaw", providers=[p.name],
                    inference={"providerRef": p.name, "model": "model"})
    (tmp_path / "inference").mkdir()
    profiles = [ab.Profile(name="test", workspaces=[ab.Workspace(
        name="default", providers=[p], sandboxes=[sb])])]
    proxy = proxy_for(ab, profiles)
    assert ab.resolve_credentials(profiles, tmp_path, proxy)["default"]["nvidia"] == marker("inference")
    proxy["secrets"][0]["providers"] = ["openai"]
    with pytest.raises(ab.InstallerError, match="provider type is not allowed"):
        ab.resolve_credentials(profiles, tmp_path, proxy)


@pytest.mark.parametrize("port", ["443", "8443"])
def test_typed_custom_endpoint_requires_supported_port(ab, tmp_path, port):
    p = ab.Provider(name="custom-inference", type="custom-inference", credential_secret="inference")
    sb = ab.Sandbox(name="chat", type="openclaw", providers=[p.name], inference={
        "providerRef": p.name, "protocol": "openai", "model": "model",
        "baseUrl": {"secretKeyRef": {"name": "inference", "key": "url"}}})
    ws = ab.Workspace(name="default", providers=[p], sandboxes=[sb])
    (tmp_path / "inference").mkdir()
    (tmp_path / "inference" / "url").write_text(f"https://models.example.test:{port}/v1")
    profiles = [ab.Profile(name="test", workspaces=[ws])]
    if port == "8443":
        with pytest.raises(ab.InstallerError, match="port 443 only"):
            resolve(ab, profiles, tmp_path)
    else:
        assert resolve(ab, profiles, tmp_path)["default"][p.name] == marker("inference")


@pytest.mark.parametrize("src", ["https://models.example.test/v1",
                               {"secretKeyRef": {"name": "elsewhere", "key": "url"}}])
def test_deployment_profile_endpoint_must_come_from_credential_secret_url(ab, tmp_path, src):
    p = ab.Provider(name="custom-inference", type="custom-inference", credential_secret="inference")
    sb = ab.Sandbox(name="chat", type="openclaw", providers=[p.name], inference={
        "providerRef": p.name, "protocol": "openai", "model": "model", "baseUrl": src})
    for name in ("inference", "elsewhere"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "url").write_text("https://models.example.test/v1")
    profiles = [ab.Profile(name="test", workspaces=[ab.Workspace(
        name="default", providers=[p], sandboxes=[sb])])]
    with pytest.raises(ab.InstallerError, match="no shipped proxy host profile"):
        resolve(ab, profiles, tmp_path)


@pytest.mark.parametrize("change", ["proxy", "gateway"])
def test_proxy_rotation_preserves_files_but_gateway_rotation_recreates(
        ab, tmp_path, fake_env, config, change):
    p = ab.Provider(name="nvidia", type="nvidia", credential_secret="inference")
    sb = ab.Sandbox(name="tools", type="generic", providers=[p.name])
    profiles = [ab.Profile(name="test", workspaces=[ab.Workspace(
        name="default", providers=[p], sandboxes=[sb])])]
    (tmp_path / "inference").mkdir()
    creds = resolve(ab, profiles, tmp_path)
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/tools"]["files"] = {"notes.md": "preserve me"}
    fake_env.set_openshell_state(state)
    cfg = deepcopy(config)
    cfg["credentialProxy" if change == "proxy" else "gatewayPki"]["caFingerprint"] = "rotated-ca"
    ab.ProfileApplier(ab.Shell(), cfg, creds).apply(profiles)
    files = fake_env.openshell_state()["sandboxes"]["default/tools"].get("files", {})
    assert files == ({"notes.md": "preserve me"} if change == "proxy" else {})
