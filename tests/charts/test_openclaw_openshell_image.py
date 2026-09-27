"""The openclaw-openshell sandbox image must start under OpenShell's supervisor.

Live: `USER 65532` with no passwd entry made every notebook sandbox exit with
"OCI USER '65532' uses a numeric UID without an explicit group, but
/etc/passwd has no matching primary GID" (OpenShell 0.0.116).
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "image-builder-charts" / "helm" / "openclaw-openshell-image"
HELM = shutil.which("helm")


def user_lines(dockerfile):
    return [l.strip() for l in dockerfile.splitlines() if l.strip().startswith("USER ")]


def test_final_user_has_an_explicit_group():
    users = user_lines((CHART / "Dockerfile").read_text())
    assert users[-1] == "USER 65532:65532"


def test_passwd_and_group_entries_are_checked_at_build_time():
    text = (CHART / "Dockerfile").read_text()
    assert "|| true" not in text.split("USER root", 1)[1].split("RUN mkdir", 1)[0]
    assert "grep '^[^:]*:[^:]*:65532:65532:' /etc/passwd" in text


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_buildconfig_inline_dockerfile_matches_the_dockerfile():
    out = subprocess.run([HELM, "template", "img", str(CHART)], capture_output=True, text=True, check=True).stdout
    bc = next(d for d in yaml.safe_load_all(out) if d and d["kind"] == "BuildConfig")
    inline = bc["spec"]["source"]["dockerfile"]
    base = yaml.safe_load((CHART / "values.yaml").read_text())["build"]["baseImage"]
    expected = re.sub(r"^FROM .*$", f"FROM {base}", (CHART / "Dockerfile").read_text(), count=1, flags=re.M)
    assert inline.strip() == expected.strip()
