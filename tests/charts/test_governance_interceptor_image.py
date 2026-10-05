"""The governance-interceptor image is built twice -- once by the GitHub
workflow from image-builder-charts/governance-interceptor/Dockerfile, once by
the OpenShift BuildConfig from its own inline copy. Both patch upstream
OpenShell's example interceptor before building it, so both must carry the
same patches or a cluster-built image silently loses them.
"""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "image-builder-charts" / "governance-interceptor" / "Dockerfile"
CHART = ROOT / "image-builder-charts" / "helm" / "governance-interceptor-image"
HELM = shutil.which("helm")

# Every line the build edits into upstream's src/main.rs. The two builders
# differ in their base images and in how they fetch OpenShell, so the files
# cannot be compared whole; these are the parts that must not drift.
PATCH_LINES = [
    # Existing workaround for NVIDIA/OpenShell#3929.
    "! grep -q 'insert(PROFILE_HASH_ANNOTATION' src/main.rs",
    # Harness driver-config guard: admin-only driver config, read-only mounts.
    '&& grep -q \'"govern-create-sandbox-template"\' src/main.rs',
    "&& grep -q 'let gate = validate_driver_config(' src/main.rs",
    "'fn validate_driver_config('",
    "'const HARNESS_ADMIN_ROLE: &str = \"openshell-admin\";'",
    "'        return deny(\"driver config may only be submitted by a platform admin identity\");'",
    "'            return deny(\"driver config mounts must each set read_only: true\");'",
]


def inline_dockerfile():
    out = subprocess.run([HELM, "template", "img", str(CHART)],
                         capture_output=True, text=True, check=True).stdout
    bc = next(d for d in yaml.safe_load_all(out) if d and d["kind"] == "BuildConfig")
    return bc["spec"]["source"]["dockerfile"]


@pytest.mark.parametrize("line", PATCH_LINES)
def test_dockerfile_carries_every_source_patch(line):
    assert line in DOCKERFILE.read_text()


@pytest.mark.skipif(not HELM, reason="helm is not installed")
@pytest.mark.parametrize("line", PATCH_LINES)
def test_buildconfig_carries_every_source_patch(line):
    assert line in inline_dockerfile()


def test_the_guard_runs_before_the_build():
    """A patch appended after `cargo build` would never reach the binary."""
    text = DOCKERFILE.read_text()
    assert text.index("validate_driver_config") < text.index("RUN cargo build")


def test_the_guard_admin_role_is_the_role_the_saw_gateways_grant():
    """The guard hardcodes the role name; the gateway takes it from values
    (oidc.adminRole, and the OU of the installer's mTLS certificate). They
    must not drift, or the installer loses the right to mount a harness."""
    values = yaml.safe_load((ROOT / "charts" / "openshell-saw" / "values.yaml").read_text())
    role = values["oidc"]["adminRole"]
    assert f"'const HARNESS_ADMIN_ROLE: &str = \"{role}\";'" in DOCKERFILE.read_text()
    installer = (ROOT / "charts" / "openshell-saw" / "files" / "installer" / "apply_bom.py").read_text()
    assert f'ADMIN_CERT_SUBJECT = "/O=openshell/OU={role}/CN=saw-installer"' in installer
