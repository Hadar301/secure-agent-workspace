#!/usr/bin/env -S uv run --script
"""Render public confidential artifacts. Never reads credentials or applies objects."""
import argparse
import importlib.util
import json
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
    parser.add_argument("action",choices=["initdata","trustee-resources"])
    parser.add_argument("--values",required=True)
    parser.add_argument("--owner",required=True)
    parser.add_argument("--registration",required=True)
    parser.add_argument("--installation")
    parser.add_argument("--slot")
    parser.add_argument("--role",choices=["supervisor","workload"])
    parser.add_argument("--profile")
    parser.add_argument("--secret-store")
    args=parser.parse_args()
    try:
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
    except (OSError,ValueError,KeyError,TypeError):
        print("AttestationConfigurationRejected",file=sys.stderr)
    return 1

if __name__=="__main__":
    raise SystemExit(main())
