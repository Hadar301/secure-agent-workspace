"""scripts/openshell-saw-create.sh with fake oc/helm: ENDPOINT_URL goes into
the inference Secret's `url`, PROFILES selects the SAW-BOM profiles."""
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "openshell-saw-create.sh"

FAKE_OC = r'''#!/usr/bin/env bash
echo "oc $*" >> "$FAKE_LOG"
case "$1" in
  whoami) echo admin ;;
  # Secrets in the namespace: EXISTING_SECRETS, plus those this run creates.
  get) [[ "$2" == secret ]] || exit 0
       grep -qx "$3" "$FAKE_DIR/secrets" 2>/dev/null || [[ " ${EXISTING_SECRETS:-} " == *" $3 "* ]] ;
       exit $? ;;
  create) echo "kind: Secret # $*"      # --dry-run=client -o yaml
          [[ "$2" == secret ]] && echo "$4" >> "$FAKE_DIR/secrets" ;;
  apply) cat >> "$FAKE_LOG" ;;
esac
exit 0
'''
FAKE_HELM = r'''#!/usr/bin/env bash
echo "helm $*" >> "$FAKE_LOG"
prev=""
for a in "$@"; do
  if [[ "$prev" == "-f" ]]; then cp "$a" "$FAKE_DIR/bom-values.yaml"; fi
  prev="$a"
done
exit 0
'''


@pytest.fixture
def run(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("oc", FAKE_OC), ("helm", FAKE_HELM)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "keycloak-host.sh").write_text("#!/bin/sh\nexit 1\n")
    (scripts / "keycloak-host.sh").chmod(0o755)
    log = tmp_path / "log"

    def _run(**env):
        full = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_LOG": str(log),
                "FAKE_DIR": str(tmp_path), "OPENSHELL_SAW_NAME": "cinf", "SAW_CHART": "charts/openshell-saw",
                "OWNER": "alice", "OIDC_ISSUER": "none", "SCRIPTS_DIR": str(scripts), **env}
        result = subprocess.run(["bash", str(SCRIPT)], env=full, cwd=ROOT, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        return log.read_text(), tmp_path / "bom-values.yaml"
    return _run


def test_custom_endpoint_and_profile(run):
    log, bom_values = run(PROVIDER="openai", MODEL="m", API_KEY="k",
                          ENDPOINT_URL="https://vllm.models.svc:8443/v1", PROFILES="custom-inference")
    secret = next(line for line in log.splitlines() if line.startswith("oc create secret generic inference"))
    assert "--from-literal=url=https://vllm.models.svc:8443/v1" in secret
    assert "--from-literal=provider=openai" in secret
    assert yaml.safe_load(bom_values.read_text()) == {"profiles": ["custom-inference"]}


def test_several_profiles(run):
    _, bom_values = run(PROVIDER="build", MODEL="m", API_KEY="k", PROFILES="data-science, custom-inference")
    assert yaml.safe_load(bom_values.read_text()) == {"profiles": ["data-science", "custom-inference"]}


def test_defaults_are_unchanged(run):
    log, bom_values = run(PROVIDER="build", MODEL="m", API_KEY="k")
    secret = next(line for line in log.splitlines() if line.startswith("oc create secret generic inference"))
    assert "url=" not in secret
    assert not bom_values.exists()
    bom = next(line for line in log.splitlines() if line.startswith("helm upgrade --install saw-bom"))
    assert " -f " not in bom


def _saw_helm(log):
    return next(line for line in log.splitlines() if line.startswith("helm upgrade --install cinf "))


def test_without_a_web_search_key_the_vm_does_not_wait_for_that_secret(run):
    log, _ = run(PROVIDER="build", MODEL="m", API_KEY="k")
    helm = _saw_helm(log)
    assert "additionalProviderSecrets=null" in helm
    assert "inference.secretName=" not in helm


def test_without_an_api_key_the_vm_does_not_wait_for_inference(run):
    log, _ = run(PROVIDER="build", MODEL="m")
    assert not any(line.startswith("oc create secret generic inference") for line in log.splitlines())
    helm = _saw_helm(log)
    assert "inference.secretName=" in helm
    assert "additionalProviderSecrets=null" in helm


def test_a_rerun_without_keys_keeps_the_secrets_already_there(run):
    # Re-running for an existing workspace must not detach its credentials.
    log, _ = run(PROVIDER="build", MODEL="m", EXISTING_SECRETS="inference web-search")
    assert not any(line.startswith("oc create secret") for line in log.splitlines())
    helm = _saw_helm(log)
    assert "inference.secretName=" not in helm
    assert "additionalProviderSecrets=null" not in helm
