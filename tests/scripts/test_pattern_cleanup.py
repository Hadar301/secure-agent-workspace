"""Ownership checks for the pattern teardown scripts."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def fake_oc(tmp_path, namespaces, resources, objects):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "namespaces.json").write_text(json.dumps({"items": namespaces}))
    (fixtures / "resources.txt").write_text("\n".join(resources) + "\n")
    for name, items in objects.items():
        (fixtures / f"{name}.json").write_text(json.dumps({"items": items}))
    oc = bindir / "oc"
    oc.write_text('''#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  api-resources) cat "${OC_FIXTURES}/resources.txt" ;;
  get)
    if [[ "$2" == namespaces ]]; then
      cat "${OC_FIXTURES}/namespaces.json"
    else
      cat "${OC_FIXTURES}/$2.json"
    fi ;;
  delete|wait) printf '%s\\n' "$*" >> "${OC_LOG}" ;;
  *) printf 'unexpected oc call: %s\\n' "$*" >&2; exit 9 ;;
esac
''')
    oc.chmod(0o755)
    log = tmp_path / "oc.log"
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
               OC_FIXTURES=str(fixtures), OC_LOG=str(log))
    return env, log


def test_pre_uninstall_deletes_only_pattern_owned_gateway(tmp_path):
    namespaces = [
        {"metadata": {"name": "saw-alice", "labels": {
            "openshell.pattern/saw": "true", "openshell.pattern/owner": "alice",
            "argocd.argoproj.io/managed-by": "vp-gitops"}}},
        {"metadata": {"name": "saw-bob", "labels": {
            "openshell.pattern/saw": "true", "openshell.pattern/owner": "bob"}}},
    ]
    vm = {"metadata": {"name": "alice", "labels": {
        "app.kubernetes.io/instance": "alice"}}}
    env, log = fake_oc(tmp_path, namespaces,
                       ["virtualmachines.kubevirt.io", "datavolumes.cdi.kubevirt.io",
                        "virtualmachineinstances.kubevirt.io"],
                       {"vm": [vm], "vmi": []})
    result = subprocess.run(["bash", str(ROOT / "scripts/pattern-pre-uninstall.sh")],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    calls = log.read_text().splitlines()
    assert len(calls) == 2
    assert any("delete vm alice -n saw-alice" in call for call in calls)
    assert any("delete dv alice-root -n saw-alice" in call for call in calls)
    assert all("--all" not in call and "saw-bob" not in call for call in calls)


def test_operator_cleanup_keeps_unowned_resources(tmp_path):
    owned = {"metadata": {"name": "owned", "labels": {
        "argocd.argoproj.io/instance": "openshift-cnv"}}}
    other = {"metadata": {"name": "other", "labels": {}}}
    kinds = ["hyperconvergeds.hco.kubevirt.io",
             "subscriptions.operators.coreos.com",
             "clusterserviceversions.operators.coreos.com",
             "installplans.operators.coreos.com"]
    env, log = fake_oc(tmp_path, [{"metadata": {"name": "openshift-cnv"}}],
                       kinds, {kind: [owned, other] for kind in kinds})
    result = subprocess.run(["bash", str(ROOT / "scripts/pattern-operator-cleanup.sh")],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    calls = log.read_text().splitlines()
    assert len(calls) == len(kinds)
    assert all(" owned -n openshift-cnv " in call for call in calls)
    assert all("--all" not in call and " other " not in call for call in calls)
