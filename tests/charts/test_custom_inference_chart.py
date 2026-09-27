"""Helm/secret/env boundary regressions; no cluster resources are accessed."""
import json
import os
from pathlib import Path
import shlex
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


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
    assert custom["binaries"] == ["/usr/bin/node-26"]


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
