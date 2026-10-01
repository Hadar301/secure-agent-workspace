#!/usr/bin/env python3
"""Generate the SAW-BOM profile catalog from charts/saw-bom/profiles.

The catalog says, for each profile, which workspaces and sandboxes it
creates (and which sandboxes ask for a UI route), and which Secrets its
providers read, with the fields each one needs. Two charts read it, since a
Helm chart can only read its own files:

  charts/saw-users/files/profile-catalog.json      UI routes and the Secrets
                                                   to sync, per user
  charts/openshell-rhdh/files/profile-catalog.json the portal pipelines
  charts/openshell-rhdh/files/create-workspace.yaml the RHDH template: the
                                                   profiles to pick from, and
                                                   the fields each one needs

    scripts/saw-profile-catalog.py            write both files
    scripts/saw-profile-catalog.py --check    fail when they are stale (CI)
"""
import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ROOT / "charts" / "saw-bom" / "profiles"
CATALOG_OUTPUTS = [ROOT / "charts" / "saw-users" / "files" / "profile-catalog.json",
                   ROOT / "charts" / "openshell-rhdh" / "files" / "profile-catalog.json"]
TEMPLATE_OUTPUT = ROOT / "charts" / "openshell-rhdh" / "files" / "create-workspace.yaml"


def load(path):
    if not path.is_file():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def secret_fields(provider):
    """The fields a provider reads from its Secret, as the installer does
    (resolve_credentials): the key, and optionally a base URL and a model."""
    fields = [{"key": provider.get("credentialSecretKey", "api_key"), "kind": "secret",
               "required": True, "title": "API key"}]
    if provider.get("baseUrlSecretKey"):
        fields.append({"key": provider["baseUrlSecretKey"], "kind": "url", "required": True,
                       "title": "Endpoint base URL (OpenAI-compatible, ending in /v1)"})
    if provider.get("modelSecretKey"):
        field = {"key": provider["modelSecretKey"], "kind": "text", "required": True,
                 "title": "Model"}
        if provider.get("model"):
            field["default"] = provider["model"]
        fields.append(field)
    return fields


def catalog():
    out = {}
    for pdir in sorted(p for p in PROFILES.iterdir() if p.is_dir()):
        workspaces, secrets, descriptions = [], {}, []
        # The default workspace first: its description is the profile's.
        for wdir in sorted((w for w in pdir.iterdir() if w.is_dir()),
                           key=lambda w: (w.name != "default", w.name)):
            ws = load(wdir / "workspace.yaml")
            meta, spec = ws.get("metadata") or {}, ws.get("spec") or {}
            name = meta.get("name", wdir.name)
            description = meta.get("description", "")
            if description:
                descriptions.append(description)
            enabled = spec.get("enabled", True)
            sandboxes = []
            for sb in (load(wdir / "sandbox.yaml").get("spec") or {}).get("sandboxes") or []:
                ui = sb.get("ui") or {}
                sandboxes.append({"name": sb["name"], "type": sb.get("type", "generic"),
                                  "enabled": sb.get("enabled", True),
                                  "uiRoute": bool(ui.get("route", False))})
            workspaces.append({"name": name, "description": description, "enabled": enabled,
                               "sandboxes": sandboxes})
            if not enabled:
                continue
            for prov in (load(wdir / "providers.yaml").get("spec") or {}).get("providers") or []:
                if not prov.get("enabled", True) or not prov.get("credentialSecret"):
                    continue
                entry = secrets.setdefault(prov["credentialSecret"],
                                           {"providers": [], "fields": []})
                entry["providers"] = sorted(set(entry["providers"]) | {prov.get("type", "")})
                for f in secret_fields(prov):
                    if f["key"] not in {x["key"] for x in entry["fields"]}:
                        entry["fields"].append(f)
        for entry in secrets.values():
            # The Secret's optional `provider` key lets the installer refuse
            # a key for another service; only set when it is unambiguous.
            entry["provider"] = entry["providers"][0] if len(entry["providers"]) == 1 else ""
        out[pdir.name] = {"description": "; ".join(dict.fromkeys(descriptions)),
                          "workspaces": workspaces, "secrets": secrets}
    return {"profiles": out}


def render():
    return json.dumps(catalog(), indent=2, sort_keys=True) + "\n"


# The signed-in user's name: user.entity is empty for users who are not in
# the catalog (they sign in without one), user.ref is always set.
USER_NAME = "${{ user.ref | parseEntityRef | pick('name') }}"


def form_name(secret, key):
    """Form property for a Secret field: letters, digits and _ only, so it
    can be read as ${{ secrets.<name> }} / ${{ parameters.<name> }}."""
    return f"{secret}__{key}".replace("-", "_").replace(".", "_")


def render_template(cat):
    """The RHDH scaffolder template for a new workspace.

    Step 1 picks a profile; step 2 asks only for the fields that profile's
    Secrets need (JSON Schema dependencies). API keys use the Secret field,
    so they reach the request as ${{ secrets.* }} and are not stored with
    the task. The steps create the request Secret (with the user's Backstage
    token, which the pipeline verifies) and start saw-workspace-create."""
    profiles = cat["profiles"]
    one_of, string_data = [], {"action": "create", "token": "${{ secrets.backstageToken }}",
                               "profile": "${{ parameters.profile }}"}
    for pname, prof in sorted(profiles.items()):
        props, required = {"profile": {"const": pname}}, []
        routes = [f"{sb['name']} ({ws['name']})" for ws in prof["workspaces"] if ws["enabled"]
                  for sb in ws["sandboxes"] if sb["enabled"] and sb["uiRoute"]]
        if routes:
            props["uiRoutes"] = {"title": "Sandbox web UIs", "type": "null",
                                 "description": "Published on their own route, signed in with "
                                                "Keycloak, for you only: " + ", ".join(routes)}
        for sname, spec in sorted(prof["secrets"].items()):
            for field in spec["fields"]:
                name = form_name(sname, field["key"])
                prop = {"title": f"{sname}: {field['title']}", "type": "string"}
                if field["kind"] == "secret":
                    prop["ui:field"] = "Secret"
                    prop["description"] = (f"Stored in Vault for your workspace only "
                                           f"(provider {spec['provider'] or '/'.join(spec['providers'])})")
                    string_data[f"{sname}.{field['key']}"] = "${{ secrets." + name + " }}"
                else:
                    if field.get("default"):
                        prop["default"] = field["default"]
                    if field["kind"] == "url":
                        prop["pattern"] = "^https?://"
                    string_data[f"{sname}.{field['key']}"] = "${{ parameters." + name + " }}"
                props[name] = prop
                if field.get("required"):
                    required.append(name)
        one_of.append({"properties": props, "required": required})
    names = sorted(profiles)
    template = {
        "apiVersion": "scaffolder.backstage.io/v1beta3",
        "kind": "Template",
        "metadata": {
            "name": "create-saw-workspace",
            "title": "Create an agent workspace",
            "description": "Your own Secure Agent Workspace: a VM with OpenShell and the OpenClaw / "
                           "NemoClaw sandboxes of a SAW-BOM profile. Keys go to Vault, not to Git.",
            "tags": ["openshell", "openclaw", "nemoclaw", "secure-agent-workspace"],
        },
        "spec": {
            "owner": "user:default/admin",
            "type": "agent-workspace",
            "parameters": [{
                "title": "Workspace profile",
                "description": "The workspace is named after you (namespace saw-<your user name>).",
                "required": ["profile"],
                "properties": {"profile": {
                    "title": "Profile", "type": "string", "enum": names,
                    "enumNames": [f"{n}: {profiles[n]['description']}" if profiles[n]["description"]
                                  else n for n in names],
                    "default": "data-science" if "data-science" in names else names[0]}},
                "dependencies": {"profile": {"oneOf": one_of}},
            }],
            "steps": [
                {"id": "request", "name": "Submit the request", "action": "http:backstage:request",
                 "input": {"method": "POST", "path": "/proxy/saw-requests",
                           "headers": {"Content-Type": "application/json"},
                           "body": {"apiVersion": "v1", "kind": "Secret",
                                    "metadata": {"generateName": "saw-req-",
                                                 "labels": {"saw.redhat.com/request": "true"}},
                                    "type": "Opaque", "stringData": string_data}}},
                {"id": "run", "name": "Create the workspace", "action": "http:backstage:request",
                 "input": {"method": "POST", "path": "/proxy/saw-pipelineruns",
                           "headers": {"Content-Type": "application/json"},
                           "body": {"apiVersion": "tekton.dev/v1", "kind": "PipelineRun",
                                    "metadata": {"generateName": "saw-create-",
                                                 "labels": {"saw.redhat.com/request": "true"}},
                                    "spec": {"pipelineRef": {"name": "saw-workspace-create"},
                                             "taskRunTemplate": {"serviceAccountName": "__PROVISIONER_SA__"},
                                             "params": [{"name": "request", "value":
                                                         "${{ steps.request.output.body.metadata.name }}"}]}}}},
            ],
            "output": {"text": [{"title": "Workspace requested", "content":
                                 "Pipeline run **${{ steps.run.output.body.metadata.name }}** registers "
                                 "your workspace; Argo CD then creates namespace saw-" + USER_NAME + " "
                                 "and its VM (about 10 minutes). It appears in the catalog as "
                                 "saw-" + USER_NAME + ", with links to its web UIs."}]},
        },
    }
    return ("# Generated by scripts/saw-profile-catalog.py from charts/saw-bom/profiles; do not edit.\n"
            + yaml.safe_dump(template, sort_keys=False, width=100))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail when an output is stale")
    args = parser.parse_args(argv)
    text = render()
    outputs = [(path, text) for path in CATALOG_OUTPUTS]
    outputs.append((TEMPLATE_OUTPUT, render_template(json.loads(text))))
    stale = []
    for path, text in outputs:
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current == text:
            continue
        if args.check:
            stale.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
    if stale:
        print("stale profile catalog (run scripts/saw-profile-catalog.py): " + ", ".join(stale),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
