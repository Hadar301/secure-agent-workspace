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
    # The final stage (no "AS <name>") is the runtime image.
    finals = re.findall(r"^FROM (\S+)$", dockerfile(), re.M)
    assert len(finals) == 1
    base = finals[0]
    assert re.fullmatch(r"quay\.io/aipcc/base-images/agentic/openclaw@sha256:[0-9a-f]{64}", base)
    assert yaml.safe_load((CHART / "values.yaml").read_text())["build"]["baseImage"] == base


def test_final_user_is_the_base_images_sandbox_user_with_explicit_group():
    """By name: the base image's sandbox UID changed between builds (1000, 1001)."""
    assert user_lines(dockerfile())[-1] == "USER sandbox:sandbox"
    assert "grep -q '^sandbox:' /etc/passwd && grep -q '^sandbox:' /etc/group" in dockerfile()


def test_supervisor_tools_are_bundled_and_checked_at_build_time():
    """nsenter and nft come from the tools stage with their own loader, at
    paths in OpenShell's trusted search lists."""
    text = dockerfile()
    tools = re.search(r"^FROM (\S+) AS tools$", text, re.M).group(1)
    # Same Hummingbird builder the aipcc base is built with, pinned.
    assert re.fullmatch(r"registry\.access\.redhat\.com/hi/nodejs:26-builder@sha256:[0-9a-f]{64}", tools)
    assert "util-linux-core nftables" in text
    assert "COPY --from=tools /out /usr/local/lib/openshell-tools" in text
    assert "nsenter:/usr/bin/nsenter nft:/usr/sbin/nft" in text
    assert "nsenter --version && nft --version && command -v ip" in text
    assert "|| true" not in text


def test_openshell_plugin_is_installed():
    assert "openclaw plugins install @openclaw/openshell-sandbox" in dockerfile()


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_buildconfig_inline_dockerfile_matches_the_dockerfile():
    out = subprocess.run([HELM, "template", "img", str(CHART)], capture_output=True, text=True, check=True).stdout
    bc = next(d for d in yaml.safe_load_all(out) if d and d["kind"] == "BuildConfig")
    inline = bc["spec"]["source"]["dockerfile"]
    base = yaml.safe_load((CHART / "values.yaml").read_text())["build"]["baseImage"]
    text = (CHART / "Dockerfile").read_text()
    final = re.findall(r"^FROM (\S+)$", text, re.M)[0]
    expected = text.replace(f"FROM {final}\n", f"FROM {base}\n", 1)
    assert inline.strip() == expected.strip()


def test_everything_the_sandbox_runs_is_on_a_path_the_policy_allows():
    """Found live: OpenClaw under /opt/openclaw was 'Permission denied' inside
    the sandbox. Only these paths are readable there (OpenShell default policy
    and charts/governance-policy/policy.yaml)."""
    policy = yaml.safe_load((ROOT / "charts" / "governance-policy" / "policy.yaml").read_text())
    allowed = policy["filesystem_policy"]["read_only"] + policy["filesystem_policy"]["read_write"]
    assert "/opt" not in allowed and "/usr" in allowed
    text = dockerfile()
    assert "mv /opt/openclaw /usr/local/lib/openclaw" in text
    assert "ln -sfn /usr/local/lib/openclaw/node_modules/.bin/openclaw /usr/local/bin/openclaw" in text
    # anything this image adds lives under /usr
    for path in re.findall(r"(?:COPY --from=\S+ \S+|ln -sfn \S+) (/\S+)", text):
        assert path.startswith("/usr/"), path
    # the move happens before the plugin install, which writes into OpenClaw's tree
    assert text.index("mv /opt/openclaw") < text.index("openclaw plugins install")
