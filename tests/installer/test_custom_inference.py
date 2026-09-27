"""Custom inference regressions migrated to the in-VM installer."""
import json
import pytest
@pytest.fixture(autouse=True)
def installer_symbols(ab):
    globals().update(Provider=ab.Provider, Sandbox=ab.Sandbox,
                     ProfileApplier=ab.ProfileApplier, Result=ab.Result,
                     custom_endpoint=ab.custom_endpoint,
                     validate_custom_profile=ab.validate_custom_profile)

def custom_provider(**kwargs):
    return Provider(name="custom-inference", type="custom-inference", nemoclaw_provider="custom",
                    url=kwargs.get("url", "https://inference.example.com/v1"),
                    model=kwargs.get("model", "tinyllama:latest"))


def catalog(scheme="https", port=443):
    return {"id": "custom-inference", "binaries": ["/usr/bin/node-26"], "credentials": [{"env_vars": ["OPENAI_API_KEY"],
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


class CustomShell:
    dry_run = False

    def __init__(self, existing=None, fail=None, phase="Ready", attached=True):
        self.calls = []
        self.existing = existing or []
        self.fail = fail
        self.phase = phase
        self.attached = attached

    def add_secret(self, value):
        pass

    def run(self, cmd, **kwargs):
        return Result(*self._run(cmd, **kwargs))

    def _run(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if self.fail and self.fail(cmd):
            return 1, "", "deliberate failure"
        if cmd[:4] == ["openshell", "provider", "profile", "export"]:
            return 0, json.dumps(catalog()), ""
        if cmd[:3] == ["openshell", "provider", "list"]:
            return 0, json.dumps(self.existing), ""
        if cmd[:3] == ["openshell", "workspace", "list"]:
            return 0, "NAME\ndefault\nvllm", ""
        if cmd[:3] == ["openshell", "sandbox", "create"] and self.phase is None:
            self.phase = "Ready"
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
    assert ProfileApplier(sh, {"mtlsGateway": "saw-installer"}, {}).create_custom_provider(custom_provider(), "private-key", "vllm")
    cmd, args = sh.calls[-1]
    assert cmd[:3] == ["openshell", "provider", "create"]
    assert "private-key" not in " ".join(cmd)
    assert args["env"] == {"OPENAI_API_KEY": "private-key"}
    assert "base_url=https://inference.example.com/v1" in cmd
    assert "model=tinyllama:latest" in cmd
    assert args["ok_if_exists"] is False


@pytest.mark.parametrize("field,value", [("type", "openai"), ("workspace", "other"),
    ("credential_keys", ["API_KEY"]), ("config_keys", ["base_url", "unapproved"])])
def test_conflicting_provider_not_modified(field, value):
    row = {"name": "custom-inference", "workspace": "vllm", "type": "custom-inference",
           "credential_keys": ["OPENAI_API_KEY"], "config_keys": ["base_url", "model"]}
    row[field] = value
    sh = CustomShell(existing=[row])
    assert not ProfileApplier(sh, {"mtlsGateway": "saw-installer"}, {}).create_custom_provider(custom_provider(), "k", "vllm")
    assert not any(cmd[2] in {"update", "create"} for cmd, _ in sh.calls)


def test_existing_provider_reconciles_required_values():
    row = {"name": "custom-inference", "workspace": "vllm", "type": "custom-inference",
           "credential_keys": ["OPENAI_API_KEY"], "config_keys": ["base_url", "model"]}
    sh = CustomShell(existing=[row])
    deployer = ProfileApplier(sh, {"mtlsGateway": "saw-installer"}, {})
    for _ in range(2):
        assert deployer.create_custom_provider(custom_provider(), "new-key", "vllm")
    assert sum(cmd[:3] == ["openshell", "provider", "update"] for cmd, _ in sh.calls) == 2


def test_provider_failure_propagated():
    sh = CustomShell(fail=lambda c: c[:3] == ["openshell", "provider", "create"])
    assert not ProfileApplier(sh, {"mtlsGateway": "saw-installer"}, {}).create_custom_provider(custom_provider(), "key", "vllm")


@pytest.mark.parametrize("phase,attached", [("Error", True), ("Completed", True), ("Ready", False)])
def test_sandbox_conflict_preserves_data(phase, attached):
    sh = CustomShell(phase=phase, attached=attached)
    sb = Sandbox("notebook", providers=["custom-inference"])
    assert not ProfileApplier(sh, {"mtlsGateway": "saw-installer"}, {}).provision_custom_sandbox(sb, custom_provider(), "vllm")
    assert not any("delete" in cmd or "pull" in cmd for cmd, _ in sh.calls)


def test_failed_creation_does_not_poll_or_onboard():
    sh = CustomShell(phase=None, fail=lambda c: c[:3] == ["openshell", "sandbox", "create"])
    assert not ProfileApplier(sh, {"mtlsGateway": "saw-installer"}, {}).provision_custom_sandbox(
        Sandbox("notebook", providers=["custom-inference"]), custom_provider(), "vllm")
    assert sum(cmd[:3] == ["openshell", "sandbox", "get"] for cmd, _ in sh.calls) == 1
    assert not any("exec" in cmd for cmd, _ in sh.calls)


def test_sandbox_timeout_does_not_onboard(monkeypatch):
    monkeypatch.setattr("apply_bom.time.sleep", lambda _: None)
    sh = CustomShell(phase="Provisioning")
    assert not ProfileApplier(sh, {"mtlsGateway": "saw-installer"}, {}).provision_custom_sandbox(
        Sandbox("notebook", providers=["custom-inference"]), custom_provider(), "vllm")
    assert not any("exec" in cmd for cmd, _ in sh.calls)


@pytest.mark.parametrize("stage", ["placeholder", "onboard", "health", None])
def test_custom_openclaw_failure_and_repeat_setup(monkeypatch, stage):
    monkeypatch.setattr("apply_bom.time.sleep", lambda _: None)
    def fail(cmd):
        text = " ".join(cmd)
        return ((stage == "placeholder" and cmd[-1].startswith('case "${OPENAI_API_KEY'))
                or (stage == "onboard" and "openclaw onboard" in text)
                or (stage == "health" and "http://127.0.0.1:18789/health" in text))
    sh = CustomShell(fail=fail)
    deployer = ProfileApplier(sh, {"mtlsGateway": "saw-installer"}, {})
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



@pytest.mark.parametrize('configured', ['custom', 'openai', 'build', 'nvidia', 'gemini', ''])
def test_mounted_secret_eligibility_and_plan(ab, tmp_path, configured):
    base = tmp_path / 'inference'
    base.mkdir()
    key = "private-key with spaces; $(touch SHOULD_NOT_EXIST) 'quoted'"
    for name, value in dict(provider=configured, api_key=key,
                            url='https://inference.example.com/v1', model='organization/model').items():
        (base / name).write_text(value)
    custom = ab.Provider('custom-inference', 'custom-inference', credential_secret='inference')
    cloud = ab.Provider('nvidia', 'nvidia', nemoclaw_provider='build', credential_secret='inference')
    ws = ab.Workspace('vllm', providers=[custom, cloud], sandboxes=[
        ab.Sandbox('notebook', providers=['custom-inference']),
        ab.Sandbox('mixed', providers=['custom-inference', 'nvidia'])])
    profiles = [ab.Profile('p', [ws])]
    creds = ab.resolve_credentials(profiles, tmp_path)
    applier = ab.ProfileApplier(CustomShell(), {"mtlsGateway": "saw-installer"}, creds)
    assert ab.eligible_sandbox(ws, ws.sandboxes[0]) == (configured == 'custom')
    assert not ab.eligible_sandbox(ws, ws.sandboxes[1])
    if configured == 'custom':
        assert creds == {'vllm': {'custom-inference': key}}
        assert custom.url.endswith('/v1') and custom.model == 'organization/model'
        # The root-to-user JSON plan preserves literal values without shell expansion.
        from dataclasses import asdict
        restored = ab.profiles_from_plan(json.loads(json.dumps({"profiles": [asdict(p) for p in profiles]})))
        assert restored[0].workspaces[0].providers[0] == custom
    assert not (tmp_path / 'SHOULD_NOT_EXIST').exists()

@pytest.mark.parametrize('field,value', [('api_key', ''), ('url', ''), ('model', ''), ('url', 'ftp://example.com')])
def test_custom_mounted_required_fields(ab, tmp_path, field, value):
    base = tmp_path / 'inference'
    base.mkdir()
    data = dict(provider='custom', api_key='secret-key', url='https://example.com/v1', model='m')
    data[field] = value
    for name, text in data.items():
        (base / name).write_text(text)
    p = ab.Provider('custom-inference', 'custom-inference', credential_secret='inference')
    with pytest.raises(ab.InstallerError):
        ab.resolve_credentials([ab.Profile('p', [ab.Workspace('vllm', providers=[p])])], tmp_path)

def test_failed_custom_provider_stops_apply(ab, monkeypatch):
    sh = CustomShell(fail=lambda c: c[:3] == ['openshell', 'provider', 'create'])
    app = ab.ProfileApplier(sh, {"mtlsGateway": "saw-installer"}, {'vllm': {'custom-inference': 'secret-key'}})
    monkeypatch.setattr(app, 'register_gateway', lambda: None)
    ws = ab.Workspace('vllm', providers=[custom_provider()], sandboxes=[
        ab.Sandbox('notebook', providers=['custom-inference'])])
    with pytest.raises(ab.InstallerError, match='custom provider provisioning failed'):
        app.apply([ab.Profile('p', [ws])])
    assert not any(c[:2] == ['openshell', 'sandbox'] for c, _ in sh.calls)

@pytest.mark.parametrize('key', ['private-key', 'k'])
def test_secret_output_is_redacted(ab, monkeypatch, capsys, key):
    from types import SimpleNamespace
    monkeypatch.setattr(ab.subprocess, 'run', lambda *a, **k: SimpleNamespace(
        returncode=0, stdout='credential=' + key, stderr=''))
    sh = ab.Shell()
    sh.add_secret(key)
    result = sh.run(['test'])
    assert result.out == 'credential=' + key
    assert 'credential=' + key not in capsys.readouterr().out


def test_full_custom_apply_and_verify(ab, monkeypatch):
    sh = CustomShell(phase=None)
    app = ab.ProfileApplier(sh, {'mtlsGateway': 'saw-installer'},
                           {'vllm': {'custom-inference': 'secret-key'}})
    monkeypatch.setattr(app, 'register_gateway', lambda: None)
    ws = ab.Workspace('vllm', providers=[custom_provider()], sandboxes=[
        ab.Sandbox('notebook', type='openclaw', providers=['custom-inference'])])
    profiles = [ab.Profile('p', [ws])]
    app.apply(profiles)
    assert app.verify(profiles) == []
    assert any(c[:3] == ['openshell', 'sandbox', 'create'] for c, _ in sh.calls)
    assert not any(c[:2] == ['openshell', 'inference'] for c, _ in sh.calls)
    assert not any('import' in c for c, _ in sh.calls)
    sh.attached = False
    assert any('attachment' in f for f in app.verify(profiles))


@pytest.mark.parametrize('kind,alias', [('gemini', 'gemini'), ('nvidia', 'build'),
                                       ('openai', 'openai'), ('nvidia', 'nvidia')])
def test_cloud_secret_without_url_remains_compatible(ab, tmp_path, kind, alias):
    base = tmp_path / 'inference'
    base.mkdir()
    for key, value in {'provider': alias, 'api_key': 'cloud-key'}.items():
        (base / key).write_text(value)
    provider = ab.Provider(kind, kind, nemoclaw_provider=alias, credential_secret='inference')
    profiles = [ab.Profile('p', [ab.Workspace('w', providers=[provider])])]
    assert ab.resolve_credentials(profiles, tmp_path) == {'w': {kind: 'cloud-key'}}
    assert not provider.skip_reason


def test_custom_catalog_unavailable_never_imports_or_creates(ab, monkeypatch):
    monkeypatch.setattr(ab.time, 'sleep', lambda _: None)
    sh = CustomShell(fail=lambda c: c[:4] == ['openshell', 'provider', 'profile', 'export'])
    app = ab.ProfileApplier(sh, {'mtlsGateway': 'saw-installer'}, {})
    assert not app.create_custom_provider(custom_provider(), 'secret-key', 'vllm')
    assert len(sh.calls) == 24
    assert not any('import' in c or 'create' in c for c, _ in sh.calls)


def test_skipped_custom_workspace_is_not_created_or_verified(ab, monkeypatch):
    provider = custom_provider()
    provider.skip_reason = 'incompatible type'
    profiles = [ab.Profile('p', [ab.Workspace('vllm', providers=[provider], sandboxes=[
        ab.Sandbox('notebook', providers=[provider.name])])])]
    sh = CustomShell()
    app = ab.ProfileApplier(sh, {'mtlsGateway': 'saw-installer'}, {})
    monkeypatch.setattr(app, 'register_gateway', lambda: None)
    app.apply(profiles)
    assert app.verify(profiles) == []
    assert [c for c, _ in sh.calls] == [['openshell', 'workspace', 'list']]


PROFILE_ID = 'custom-inference:setup-81feb9b8-691c-4597-a455-34665ad7a841'
REPLACEMENT = ('Replacement credential saved but inactive. Your connection is unchanged. '
               'Test and activate it with:\nopenclaw models auth activate ' + PROFILE_ID + ' --agent main')


@pytest.mark.parametrize('activation_rc,output,success', [
    (0, 'Activated', True), (1, 'network connection error', False),
    (0, 'Credentials saved; default unchanged.', False)])
def test_repeat_onboard_activates_saved_profile(ab, monkeypatch, activation_rc, output, success):
    monkeypatch.setattr(ab.time, 'sleep', lambda _: None)

    class ReplacementShell(CustomShell):
        def run(self, cmd, **kwargs):
            text = ' '.join(cmd)
            if 'openclaw onboard' in text or 'models auth activate' in text:
                self.calls.append((cmd, kwargs))
                if 'openclaw onboard' in text:
                    return ab.Result(1, '', REPLACEMENT)
                return ab.Result(activation_rc, output, '')
            return super().run(cmd, **kwargs)

    sh = ReplacementShell()
    app = ab.ProfileApplier(sh, {'mtlsGateway': 'saw-installer'}, {})
    assert app.start_custom_openclaw(ab.Sandbox('notebook'), custom_provider(), 'vllm') == success
    calls = [' '.join(c) for c, _ in sh.calls]
    activated = [c for c in calls if 'models auth activate' in c]
    assert len(activated) == 1 and PROFILE_ID in activated[0]
    assert 'OPENCLAW_HOME=/sandbox' in activated[0]
    assert any('nohup openclaw' in c for c in calls) == success
    health = [c for c, _ in sh.calls if ab.CUSTOM_HEALTH_JS in c]
    assert bool(health) == success
    assert all(ab.CUSTOM_NODE in c and 'curl' not in c for c in health)


@pytest.mark.parametrize('output', [
    REPLACEMENT.replace('custom-inference:setup-', 'other:setup-'),
    REPLACEMENT.replace('--agent main', '--agent other'),
    REPLACEMENT.replace('--agent main', '--agent main; touch /tmp/unwanted'),
    REPLACEMENT + '\n' + REPLACEMENT,
    'unrelated error',
])
def test_replacement_response_is_strict(ab, output):
    assert ab.replacement_profile(ab.Result(1, '', output)) is None


@pytest.mark.parametrize('status', [200, 503])
def test_node_health_probe_http_status(ab, status):
    import http.server
    import shutil
    import subprocess
    import threading
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is needed to execute the sandbox health probe')

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        script = ab.CUSTOM_HEALTH_JS.replace(':18789/', f':{server.server_port}/')
        result = subprocess.run([node, '-e', script], capture_output=True, timeout=10)
        assert (result.returncode == 0) == (status == 200)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
