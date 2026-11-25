"""Verify shared source links produce portable, self-contained Helm artifacts."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELM = shutil.which("helm")


@pytest.mark.skipif(not HELM, reason="helm is not installed")
@pytest.mark.parametrize("chart", ["saw-users", "openshell-rhdh", "saw-portal-container"])
def test_packaged_chart_contains_shared_attestation_without_source_checkout(tmp_path, chart):
    source = ROOT / "kubernetes-runtime/saw_kubernetes/attestation.py"
    asset = ROOT / "charts" / chart / "files/attestation.py"
    assert asset.is_symlink() and asset.resolve() == source
    subprocess.run([HELM, "package", str(ROOT / "charts" / chart),
                    "--destination", str(tmp_path)], capture_output=True, text=True, check=True)
    package, = tmp_path.glob("*.tgz")
    unpacked = tmp_path / "unpacked"
    with tarfile.open(package) as archive:
        member = archive.getmember(f"{chart}/files/attestation.py")
        assert member.isfile()
        assert archive.extractfile(member).read() == source.read_bytes()
        archive.extractall(unpacked, filter="data")
    helper = ROOT / "charts" / chart / "templates/_attestation.tpl"
    canonical = ROOT / "deploy/confidential/helm/_attestation.tpl"
    assert helper.is_symlink() and helper.resolve() == canonical
    assert (unpacked / chart / "templates/_attestation.tpl").read_bytes() == canonical.read_bytes()
    crio_link = ROOT / "charts" / chart / "files/crio_policy.py"
    assert crio_link.is_symlink()
    assert (unpacked / chart / "files/crio_policy.py").read_bytes() == crio_link.resolve().read_bytes()
    # The chart runs after packaging without the canonical repository path.
    preflight_link = ROOT / "charts" / chart / "files/preflight.py"
    assert preflight_link.is_symlink()
    assert preflight_link.resolve() == ROOT / "kubernetes-runtime/saw_kubernetes/preflight.py"
    preflight = unpacked / chart / "files/preflight.py"
    spec = importlib.util.spec_from_file_location("packaged_preflight", preflight)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.verify_attestation({}, "container", lambda _: pytest.fail("unexpected API read")) is None
