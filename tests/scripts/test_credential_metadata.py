"""Quickstart metadata must retain typed settings and exclude every bound key."""
import json
import os
from pathlib import Path
import shlex
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def test_quickstart_metadata_drops_all_bound_credentials(tmp_path):
    script = (ROOT / "scripts/openshell-saw-create.sh").read_text()
    function = "sync_provider_metadata() {" + script.split("sync_provider_metadata() {", 1)[1].split("\n}", 1)[0] + "\n}"
    secret = {"metadata": {"namespace": "saw-test"}, "data": {
        "provider": "cA==", "model": "bQ==", "cuda_model": "Y3VkYQ==", "url": "dQ==",
        "api_key": "aw==", "client_secret": "cw=="}}
    bindir = tmp_path / "bin"
    bindir.mkdir()
    oc = bindir / "oc"
    oc.write_text("#!/usr/bin/env python3\nimport json,os,pathlib,sys\n"
                  "if sys.argv[1] == 'get': print(os.environ['TEST_SOURCE'])\n"
                  "elif sys.argv[1] == 'apply': pathlib.Path(os.environ['TEST_CAPTURE']).write_text(sys.stdin.read())\n"
                  "else: raise SystemExit(2)\n")
    oc.chmod(0o755)
    bindings = [{"name": "inference", "key": key, "providers": ["openai"]}
                for key in ("api_key", "client_secret")]
    capture = tmp_path / "metadata.json"
    command = ("DEPLOY_NS=saw-test\nproxy_bindings=" + shlex.quote(json.dumps(bindings)) +
               "\n" + function + "\nsync_provider_metadata inference\n")
    subprocess.run(["bash", "-euo", "pipefail", "-c", command], check=True,
                   env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
                        "TEST_SOURCE": json.dumps(secret), "TEST_CAPTURE": str(capture)})
    projected = json.loads(capture.read_text())
    assert projected["metadata"] == {"name": "inference-meta", "namespace": "saw-test"}
    assert projected["data"] == {key: secret["data"][key]
                                 for key in ("provider", "model", "cuda_model", "url")}
