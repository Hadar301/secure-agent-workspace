"""The openclaw-openshell sandbox image must start under OpenShell's supervisor.

Found live with OpenShell 0.0.116:
- `USER 65532` with no passwd entry: "OCI USER '65532' uses a numeric UID
  without an explicit group, but /etc/passwd has no matching primary GID".
- The aipcc agentic OpenClaw base has no nsenter: "Network namespace creation
  failed ... trusted nsenter helper not found".
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


def dockerfile():
    return (CHART / "Dockerfile").read_text()


def test_base_image_is_pinned_by_digest_and_matches_values():
    base = re.search(r"^FROM (\S+)$", dockerfile(), re.M).group(1)
    assert re.fullmatch(r"quay\.io/aipcc/base-images/agentic/openclaw@sha256:[0-9a-f]{64}", base)
    assert yaml.safe_load((CHART / "values.yaml").read_text())["build"]["baseImage"] == base


def test_final_user_is_the_base_images_sandbox_user_with_explicit_group():
    assert user_lines(dockerfile())[-1] == "USER 1000:1000"
    assert "grep '^sandbox:[^:]*:1000:1000:' /etc/passwd" in dockerfile()


def test_supervisor_tools_are_installed_and_checked_at_build_time():
    text = dockerfile()
    for package in ("util-linux", "nftables", "iproute"):
        assert package in text
    assert "command -v nsenter && command -v nft && command -v ip" in text
    assert "|| true" not in text


def test_openshell_plugin_is_installed():
    assert "openclaw plugins install @openclaw/openshell-sandbox" in dockerfile()


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_buildconfig_inline_dockerfile_matches_the_dockerfile():
    out = subprocess.run([HELM, "template", "img", str(CHART)], capture_output=True, text=True, check=True).stdout
    bc = next(d for d in yaml.safe_load_all(out) if d and d["kind"] == "BuildConfig")
    inline = bc["spec"]["source"]["dockerfile"]
    base = yaml.safe_load((CHART / "values.yaml").read_text())["build"]["baseImage"]
    expected = re.sub(r"^FROM .*$", f"FROM {base}", (CHART / "Dockerfile").read_text(), count=1, flags=re.M)
    assert inline.strip() == expected.strip()
