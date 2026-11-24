#!/usr/bin/env -S uv run --script
"""Render public Trustee policy from reviewed measurement approvals. Never apply it."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "kubernetes-runtime"))
from saw_kubernetes.trustee_policy import PolicyError, render


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approvals", required=True)
    args = parser.parse_args()
    try:
        policy = render(json.loads(Path(args.approvals).read_text()))
    except (OSError, ValueError, PolicyError):
        print("TrusteeMeasurementApprovalRejected", file=sys.stderr)
        return 1
    print(policy, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
