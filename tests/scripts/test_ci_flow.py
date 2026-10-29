"""The existing matrix checks must fail when their shared dependency fails."""
import os
from pathlib import Path
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_matrix_check_propagates_shared_result():
    workflow = yaml.safe_load((ROOT / ".github/workflows/installer-tests.yml").read_text())
    job = workflow["jobs"]["test"]
    assert job["needs"] == "shared-checks"
    assert job["if"] == "always()"
    gate = job["steps"][0]
    assert gate["env"]["SHARED_RESULT"] == "${{ needs.shared-checks.result }}"
    for result, returncode in (("success", 0), ("failure", 1), ("cancelled", 1), ("skipped", 1)):
        completed = subprocess.run(["bash", "-eu", "-c", gate["run"]],
                                   env={**os.environ, "SHARED_RESULT": result},
                                   capture_output=True, text=True)
        assert completed.returncode == returncode, result
