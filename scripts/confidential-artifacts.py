#!/usr/bin/env -S uv run --script
"""Render public confidential artifacts. Never reads credentials or applies objects."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("saw_attestation", ROOT/"kubernetes-runtime/saw_kubernetes/attestation.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

def site_for_profile(site, profile):
    """Return a copy of a site with only the selected profile's Vault paths."""
    refs = site.get("credentialReferences") if isinstance(site, dict) else None
    if (not isinstance(profile, str) or not profile
            or not isinstance(refs, dict) or not isinstance(refs.get(profile), dict)):
        raise a.AttestationError("CredentialReferenceRejected")
    selected = dict(site)
    selected["credentialReferences"] = refs[profile]
    return selected

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=["initdata","trustee-resources","launch-input","launch-policy"])
    parser.add_argument("--values")
    parser.add_argument("--owner")
    parser.add_argument("--registration")
    parser.add_argument("--installation")
    parser.add_argument("--slot")
    parser.add_argument("--role",choices=["supervisor","workload"])
    parser.add_argument("--profile")
    parser.add_argument("--secret-store")
    parser.add_argument("--policy")
    parser.add_argument("--pod")
    parser.add_argument("--output")
    args=parser.parse_args()
    if args.action in ("launch-input", "launch-policy"):
        if not args.pod or not args.output or (args.action == "launch-policy" and not args.policy):
            parser.error("launch actions require --pod and --output; launch-policy also requires --policy")
    elif not args.values or not args.owner or not args.registration:
        parser.error("this action requires --values, --owner and --registration")
    try:
        if args.action in ("launch-input", "launch-policy"):
            pod = yaml.safe_load(Path(args.pod).read_text())
            if args.action == "launch-input":
                encoded = yaml.safe_dump(a.launch_policy_input(pod), sort_keys=False)
            else:
                encoded = a.compile_launch_policy(pod, Path(args.policy).read_text())
            # No manifest on stdout. Do not overwrite inputs or follow a link.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(encoded)
            print("Prepared private launch artifact; deploy the original Pod manifest.")
            return 0
        values=yaml.safe_load(Path(args.values).read_text())
        site=values["containerSites"][args.owner]
        if args.action=="initdata":
            result=a.initdata(site,args.owner,args.registration,args.installation,args.slot,args.role)
        else:
            site = site_for_profile(site, args.profile)
            result=a.trustee_resources(site,args.owner,args.registration,site["providerPolicy"],args.secret_store)
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except a.AttestationError as exc:
        print(str(exc),file=sys.stderr)
    except (OSError,ValueError,KeyError,TypeError,yaml.YAMLError):
        print("AttestationConfigurationRejected",file=sys.stderr)
    return 1

if __name__=="__main__":
    raise SystemExit(main())
