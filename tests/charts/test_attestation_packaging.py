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
    # The chart runs after packaging without the canonical repository path.
    preflight = unpacked / chart / "files/preflight.py"
    spec = importlib.util.spec_from_file_location("packaged_preflight", preflight)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.verify_attestation({}, "container", lambda _: pytest.fail("unexpected API read")) is None
