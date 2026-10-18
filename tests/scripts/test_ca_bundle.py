"""ca-bundle.py: the bundle gets the API and service CAs from SA_DIR."""
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "charts/openshell-rhdh/files/ca-bundle.py"
PEM = "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n"


def load(monkeypatch, sa_dir):
    if sa_dir is None:
        monkeypatch.delenv("SA_DIR", raising=False)
    else:
        monkeypatch.setenv("SA_DIR", str(sa_dir))
    for var in ("TRUSTED_CA_FILE", "EXTRA_CA_FILE", "KUBERNETES_SERVICE_HOST"):
        monkeypatch.delenv(var, raising=False)
    spec = importlib.util.spec_from_file_location("ca_bundle", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # The test machine's own service account (none, normally) stays out.
    mod.SA_DIRS = tuple(d for d in mod.SA_DIRS if d != "/var/run/secrets/kubernetes.io/serviceaccount")
    mod.SYSTEM = ("",)
    return mod


def test_sa_dir_supplies_the_api_and_service_cas(monkeypatch, tmp_path, capsys):
    sa = tmp_path / "sa"
    sa.mkdir()
    (sa / "ca.crt").write_text(PEM.format("API"))
    (sa / "service-ca.crt").write_text(PEM.format("SVC"))
    mod = load(monkeypatch, sa)
    out = tmp_path / "bundle.crt"
    mod.main(str(out))
    bundle = out.read_text()
    assert "API" in bundle and "SVC" in bundle
    log = capsys.readouterr().out
    assert "added: Kubernetes API CA" in log and "added: service CA" in log


def test_without_any_service_account_the_api_ca_is_missing(monkeypatch, tmp_path, capsys):
    # What happened in RHDH's pod before: no mount, no API CA.
    mod = load(monkeypatch, None)
    out = tmp_path / "bundle.crt"
    mod.main(str(out))
    assert "note: no Kubernetes API CA" in capsys.readouterr().out
    assert out.read_text() == ""


def test_router_ca_needs_the_token_and_ca(monkeypatch, tmp_path):
    sa = tmp_path / "sa"
    sa.mkdir()
    (sa / "ca.crt").write_text(PEM.format("API"))
    mod = load(monkeypatch, sa)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    assert mod.ingress_ca() == ""          # no token: no call
    (sa / "token").write_text("t")
    calls = []

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return b'{"data": {"ca-bundle.crt": "ROUTER"}}'

    def urlopen(req, context, timeout):
        calls.append(req.get_header("Authorization"))
        return Resp()

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(mod.ssl, "create_default_context", lambda cafile: cafile)
    monkeypatch.setattr(mod.json, "load", lambda r: {"data": {"ca-bundle.crt": "ROUTER"}})
    assert mod.ingress_ca() == "ROUTER"
    assert calls == ["Bearer t"]
