"""Helm/secret/env boundary regressions; no cluster resources are accessed."""
import json
import os
from pathlib import Path
import shlex
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def render(chart, *settings):
    cmd = ["helm", "template", "test", str(ROOT / "charts" / chart)]
    for setting in settings:
        cmd += ["--set", setting]
    return list(yaml.safe_load_all(subprocess.check_output(cmd, text=True)))


def profiles(*settings):
    return next(d["data"] for d in render("governance-policy", *settings)
                if d and d["metadata"]["name"] == "governance-interceptor-profiles")


@pytest.mark.parametrize("scheme,port,tls", [("https", 443, "terminate"),
                                            ("https", 8443, "terminate"),
                                            ("http", 8080, "passthrough")])
def test_profile_rendering_preserves_cloud_profiles(scheme, port, tls):
    baseline = profiles()
    configured = profiles("customInference.enabled=true", "customInference.host=Inference.example.com",
                          f"customInference.scheme={scheme}", f"customInference.port={port}")
    assert "custom-inference.yaml" not in baseline
    assert "openai.yaml" not in configured
    assert all(configured[key] == value for key, value in baseline.items())
    custom = yaml.safe_load(configured["custom-inference.yaml"])
    assert custom["id"] == "custom-inference"
    endpoint = custom["endpoints"][0]
    assert endpoint["host"] == "inference.example.com"
    assert endpoint["port"] == port and endpoint["tls"] == tls
    assert custom["credentials"][0]["env_vars"] == ["OPENAI_API_KEY"]
    assert custom["binaries"] == ["/usr/local/bin/node", "/usr/bin/curl"]


@pytest.mark.parametrize("setting", ["customInference.host=", "customInference.host=https://example.com",
    "customInference.host=example.com/path", "customInference.port=0", "customInference.port=65536",
    "customInference.scheme=ftp", "customInference.port=443.5"])
def test_invalid_governance_configuration_fails(setting):
    result = subprocess.run(["helm", "template", "test", str(ROOT / "charts/governance-policy"),
                             "--set", "customInference.enabled=true", "--set",
                             "customInference.host=example.com", "--set", setting], capture_output=True)
    assert result.returncode != 0


def test_bom_contains_custom_workspace():
    data = next(d["data"] for d in render("saw-bom") if d)
    provider = yaml.safe_load(data["profiles__data-science__custom__providers.yaml"])["spec"]["providers"][0]
    assert provider["type"] == "custom-inference"
    assert provider["urlSecretKey"] == "url" and provider["modelSecretKey"] == "model"
    sb = yaml.safe_load(data["profiles__data-science__custom__sandbox.yaml"])["spec"]["sandboxes"][0]
    assert sb["providers"] == [provider["name"]]


@pytest.mark.parametrize("missing_key", [False, True])
def test_bom_secret_extraction_is_quoted_and_type_survives_missing_key(tmp_path, missing_key):
    mount = tmp_path / "profiles"
    mount.mkdir()
    source = ROOT / "charts/saw-bom/profiles/data-science/custom/providers.yaml"
    (mount / "profiles__data-science__custom__providers.yaml").write_text(source.read_text())
    secrets = tmp_path / "secrets" / "inference"
    secrets.mkdir(parents=True)
    payload = "key with spaces; $(touch SHOULD_NOT_EXIST) 'quotes'"
    if not missing_key:
        (secrets / "api_key").write_text(payload)
    (secrets / "provider").write_text("custom")
    (secrets / "url").write_text("https://inference.example.com/v1")
    (secrets / "model").write_text("organization/model-name")
    script = (ROOT / "charts/openshell-saw/files/setup-bom-profiles.sh").read_text()
    section = script[script.index('BOM_ENV="'):script.index("# Fetch OIDC token")]
    section = section.replace("/ws-secrets", str(tmp_path / "secrets"))
    harness = (f"set -eu\nWORK_DIR={shlex.quote(str(tmp_path))}\n"
               f"BOM_MOUNT={shlex.quote(str(mount))}\n" + section +
               '\nset -a; source "$BOM_ENV"; set +a\n' +
               "python3 -c 'import json,os; print(json.dumps({k:v for k,v in os.environ.items() if k.startswith(\"PROV_\")}))'")
    # Execute twice to ensure stale credentials cannot survive a repeated run.
    for _ in range(2):
        result = subprocess.run(["bash", "-c", harness], cwd=tmp_path, text=True,
                                capture_output=True, check=True)
    env = json.loads(result.stdout.splitlines()[-1])
    assert env["PROV_CUSTOM_INFERENCE_TYPE"] == "custom"
    assert env["PROV_CUSTOM_INFERENCE_URL"] == "https://inference.example.com/v1"
    assert env["PROV_CUSTOM_INFERENCE_MODEL"] == "organization/model-name"
    assert env.get("PROV_CUSTOM_INFERENCE_KEY") == (None if missing_key else payload)
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()
    assert (tmp_path / "bom.env").stat().st_mode & 0o777 == 0o600


def test_inference_template_optional_url(tmp_path):
    spec = next(d["spec"] for d in render("pattern-secrets")
                if d and d["metadata"]["name"] == "inference")
    assert "data" not in spec
    template = spec["target"]["template"]
    assert set(template["data"]) == {"provider", "model", "api_key", "url"}
    # Execute Go templates with strict missing-key behavior, as ESO does.
    program = tmp_path / "main.go"
    program.write_text('''package main
import("encoding/json";"os";"text/template")
func main(){var v struct{Template string; Data map[string]interface{}}; json.NewDecoder(os.Stdin).Decode(&v)
t:=template.Must(template.New("secret").Option("missingkey=error").Funcs(template.FuncMap{"default":func(a,b interface{})interface{}{if b==nil || b=="" {return a};return b}}).Parse(v.Template))
if e:=t.Execute(os.Stdout,v.Data);e!=nil{os.Exit(1)}}''')
    executable = tmp_path / "render"
    subprocess.run(["go", "build", "-o", str(executable), str(program)], check=True,
                   env=dict(os.environ, GOCACHE=str(tmp_path / "go-cache")))
    for data in [dict(provider="gemini", model="gemini-2.5-flash", api_key="k"),
                 dict(provider="custom", model="m", api_key="k", url="https://example.com/v1"),
                 dict(provider="gemini", model="m", api_key="k", url="")]:
        for key, value in template["data"].items():
            result = subprocess.run([str(executable)], input=json.dumps(dict(Template=value, Data=data)),
                                    text=True, capture_output=True)
            assert result.returncode == 0
            assert result.stdout == data.get(key, "")
    for key in ["provider", "model", "api_key"]:
        result = subprocess.run([str(executable)],
                                input=json.dumps(dict(Template=template["data"][key], Data={})),
                                text=True, capture_output=True)
        assert result.returncode != 0
