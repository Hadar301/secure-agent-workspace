#!/usr/bin/env -S uv run --script
"""Plan or perform controlled confidential credential rotation as an administrator.

The Vault value must already be updated. This command never reads a Secret.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "kubernetes-runtime"))
from saw_kubernetes import rotation


class Cluster:
    def __init__(self, context):
        self.context = context

    def __call__(self, method, path, body=None):
        # Public objects only. Never add a credential inspection fallback.
        if not path.startswith(("/api/v1/", "/apis/")) or re.search(r"/secrets(?:/|$)", path):
            raise rotation.RotationError("RotationApiScopeRejected")
        if method == "GET":
            args = ["get", "--raw", path]
        elif method == "POST" and (path.endswith("/selfsubjectaccessreviews") or path.endswith("/eviction")
                                   or re.fullmatch(r"/apis/coordination.k8s.io/v1/namespaces/[a-z0-9-]+/leases", path)):
            args = ["create", "--raw", path, "-f", "-"]
        elif method == "PATCH":
            match = re.fullmatch(r"/(?:api/v1|apis/(?:external-secrets.io|coordination.k8s.io)/v1)/namespaces/([a-z0-9-]+)/(configmaps|externalsecrets|leases)/([a-z0-9-]+)", path)
            if not match:
                raise rotation.RotationError("RotationApiScopeRejected")
            ns, kind, name = match.groups()
            args = ["patch", kind, name, "-n", ns, "--type=json", "--patch-file=/dev/stdin", "-o", "json"]
        else:
            raise rotation.RotationError("RotationApiScopeRejected")
        try:
            result = subprocess.run(["oc", "--context", self.context, "--request-timeout=15s", *args],
                                    input=json.dumps(body) if body is not None else None,
                                    capture_output=True, text=True, timeout=25)
        except (OSError, subprocess.TimeoutExpired):
            raise rotation.RotationError("RotationApiUnavailable") from None
        if result.returncode:
            reason = "RotationApiFailed"
            for marker, safe in [("Forbidden", "PermissionDenied"), ("NotFound", "ObjectUnavailable"),
                                 ("Conflict", "Conflict"), ("AlreadyExists", "Conflict"),
                                 ("TooManyRequests", "DisruptionBudgetBlocked"),
                                 ("disruption budget", "DisruptionBudgetBlocked")]:
                if marker in result.stderr:
                    reason = "Rotation" + safe
                    break
            raise rotation.RotationError(reason)
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise rotation.RotationError("RotationApiResponseRejected") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", default=os.environ.get("SAW_CONTEXT"))
    parser.add_argument("--owner", default=os.environ.get("OPENSHELL_SAW_NAME"))
    parser.add_argument("--registration", default=os.environ.get("SAW_REGISTRATION"))
    parser.add_argument("--secret-store", default=os.environ.get("SAW_TRUSTEE_SECRET_STORE"))
    parser.add_argument("--portal-namespace", default="saw-portal")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not all([args.context, args.owner, args.registration, args.secret_store]):
        parser.error("context, owner, registration and Trustee SecretStore are required")
    try:
        if not 60 <= args.timeout <= 1800:
            raise rotation.RotationError("RotationTimeoutRejected")
        cluster = Cluster(args.context)
        scope, lifecycle, verify = rotation.prepare(cluster, args.owner, args.registration,
                                                   args.secret_store, args.portal_namespace)
        if not args.apply:
            print("RotationChecksPassed: reload Trustee, then stop/start the selected registration; PVCs retained.")
            return 0
        ns = scope["trustee"]["path"].split("/")[5]
        with rotation.maintenance_lock(cluster, ns):
            rotation.rotate(cluster, scope, lifecycle, verify, timeout=args.timeout, report=print)
        return 0
    except rotation.RotationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception:
        # Never expose API stderr, manifest input, or compiler exception text.
        print("RotationConfigurationRejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
