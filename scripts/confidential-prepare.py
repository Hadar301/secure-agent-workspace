#!/usr/bin/env python3
"""Reserve public workspace identities and storage before policy generation.

This is not enrollment or a confidential qualification gate. It does not read
Secrets, release credentials, create workloads, or change Trustee policy.
"""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("container_installation", ROOT / "scripts/container-workspace.py")
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)
Error = install.InstallError
MARKER = "saw.redhat.com/prepared-registration"


def plan(config, user, render):
    """Use the production catalog and PVC template, not copied definitions."""
    site = config["containerSites"][user["name"]]
    automatic = site.get("automaticEnrollment")
    if (user["values"]["deployment"]["mode"] != "kata"
            or not isinstance(site.get("attestation"), dict)
            or site["attestation"].get("enabled") is not True
            or not isinstance(automatic, dict) or automatic.get("enabled") is not False
            or site.get("enrollment")):
        raise Error("ConfidentialPreparationRequiresUnenrolledKata")
    profiles = user.get("profiles", [])
    catalog = json.loads((ROOT / "charts/saw-users/files/profile-catalog.json").read_text())["profiles"]
    if not isinstance(profiles, list) or len(profiles) != 1 or profiles[0] not in catalog:
        raise Error("ConfidentialPreparationProfileRejected")
    stack = site.get("stack", {})
    audit_config = stack.get("audit", {}) if isinstance(stack, dict) else {}
    audit = copy.deepcopy(audit_config.get("values", {})) if isinstance(audit_config, dict) else {}
    if not isinstance(audit, dict):
        raise Error("ConfidentialPreparationStorageMissing")
    for field in ("storageClass", "exchangeStorageClass"):
        if not isinstance(audit.get(field), str) or not re.fullmatch(r"[a-z0-9][-a-z0-9.]*", audit[field]):
            raise Error("ConfidentialPreparationStorageMissing")
    owner, reg, installation = user["name"], user["registration"], user["installationID"]
    runtime, history = "saw-" + owner, "saw-history-" + reg
    labels = {"saw.redhat.com/runtime-owner": installation, "saw.redhat.com/registration": reg,
              "saw.redhat.com/portal-owner": owner, "pod-security.kubernetes.io/enforce": "restricted"}
    argo = config.get("global", {}).get("vpArgoNamespace", "vp-gitops")
    resources = []
    for namespace in (runtime, history):
        ns_labels = dict(labels)
        if namespace == runtime:
            ns_labels.update({"openshell.pattern/owner": owner, "argocd.argoproj.io/managed-by": argo})
        resources.append({"apiVersion": "v1", "kind": "Namespace", "metadata": {
            "name": namespace, "labels": ns_labels, "annotations": {MARKER: reg}}})
        resources.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                          "metadata": {"name": "default-deny", "namespace": namespace,
                                       "annotations": {MARKER: reg}},
                          "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"],
                                   "ingress": [], "egress": []}})
    targets = install.workspace.sandbox_targets(owner, reg, catalog[profiles[0]])
    if not targets:
        raise Error("ConfidentialPreparationProfileRejected")
    for slot in targets.values():
        values = {**audit, "enabled": True, "prepareOnly": True, "ownerID": installation,
                  "runtimeNamespace": runtime, "trustedNamespace": history,
                  "identity": {"subject": user["ownerSubject"], "username": owner,
                               "workspace": slot["workspace"], "sandbox": slot["sandbox"]}}
        claims = list(render(slot["base"], runtime, values))
        expected = {(runtime, "saw-audit-" + slot["base"]),
                    (runtime, "saw-gate-" + slot["base"]),
                    (runtime, "workspace-" + slot["base"]),
                    (history, slot["base"] + "-history")}
        if ({(r.get("metadata", {}).get("namespace"), r.get("metadata", {}).get("name")) for r in claims} != expected
                or len(claims) != 4 or any(r.get("kind") != "PersistentVolumeClaim"
                                  or r.get("apiVersion") != "v1"
                                  or r.get("metadata", {}).get("namespace") not in (runtime, history)
                                  for r in claims)):
            raise Error("ConfidentialPreparationRenderRejected")
        for claim in claims:
            claim["metadata"].setdefault("annotations", {})[MARKER] = reg
        resources.extend(claims)
    identities = [(r["kind"], r["metadata"].get("namespace"), r["metadata"]["name"]) for r in resources]
    if len(identities) != len(set(identities)):
        raise Error("ConfidentialPreparationRenderRejected")
    return resources


def check_existing(desired, observed, user):
    """Never adopt a foreign object or change an existing claim."""
    if observed is None:
        return
    meta, wanted = observed.get("metadata", {}), desired["metadata"]
    if (meta.get("deletionTimestamp") or meta.get("annotations", {}).get(MARKER) != user["registration"]
            or meta.get("annotations", {}).get("meta.helm.sh/release-name")
            or meta.get("annotations", {}).get("argocd.argoproj.io/tracking-id")
            or meta.get("ownerReferences")):
        raise Error("ConfidentialPreparationOwnershipRejected")
    if desired["kind"] == "Namespace":
        if any(meta.get("labels", {}).get(k) != v for k, v in wanted["labels"].items()):
            raise Error("ConfidentialPreparationOwnershipRejected")
    elif desired["kind"] == "PersistentVolumeClaim":
        actual = observed.get("spec", {})
        spec = desired["spec"]
        if (any(actual.get(k) != spec[k] for k in ("storageClassName", "accessModes"))
                or actual.get("resources", {}).get("requests") != spec["resources"]["requests"]
                or actual.get("volumeMode", "Filesystem") != "Filesystem"
                or any(meta.get("labels", {}).get(k) != v for k, v in wanted.get("labels", {}).items())):
            raise Error("ConfidentialPreparationStorageChanged")
    elif observed.get("spec") != desired["spec"]:
        raise Error("ConfidentialPreparationNetworkChanged")


class Cluster:
    def __init__(self, context):
        self.context = context

    def command(self, *args, obj=None):
        result = subprocess.run(["oc", "--context", self.context, "--request-timeout=30s", *args],
                                input=json.dumps(obj) if obj is not None else None,
                                text=True, capture_output=True, timeout=60)
        if result.returncode:
            # Raw API output can contain manifests or admission input. Use fixed reasons.
            reason = "ConfidentialPreparationApiFailed"
            if args[:2] == ("auth", "can-i"): reason = "ConfidentialPreparationPermissionDenied"
            elif "Forbidden" in result.stderr: reason = "ConfidentialPreparationPermissionDenied"
            elif "denied" in result.stderr.lower(): reason = "ConfidentialPreparationAdmissionDenied"
            raise Error(reason)
        return json.loads(result.stdout) if result.stdout.strip() else None

    def get(self, kind, name, namespace=None):
        args = ["get", kind, name, "--ignore-not-found", "-o", "json"]
        if namespace: args.extend(["-n", namespace])
        return self.command(*args)

    def create(self, obj, dry_run=False):
        return self.command("create", "--field-manager=saw-confidential-preparation",
                            *(["--dry-run=server"] if dry_run else []), "-f", "-", "-o", "json", obj=obj)


def prepare(cluster, config, user, resources, apply=False):
    """Validate the whole plan before writes. Keep enrollment gates closed."""
    site = config["containerSites"][user["name"]]
    ingress = cluster.get("ingress.config.openshift.io", "cluster")
    domain = config.get("global", {}).get("clusterDomain")
    if not domain or (ingress or {}).get("spec", {}).get("domain") != "apps." + domain:
        raise Error("ConfidentialPreparationClusterMismatch")
    approved = site.get("kataRuntimeClass", {})
    install.preflight_checks.check_runtime_class(approved, cluster.get("runtimeclass", approved.get("name", "")))
    storage = {r["spec"]["storageClassName"] for r in resources if r["kind"] == "PersistentVolumeClaim"}
    for name in storage:
        storage_class = cluster.get("storageclass", name)
        if not storage_class or storage_class.get("metadata", {}).get("deletionTimestamp"):
            raise Error("ConfidentialPreparationStorageUnavailable")
    existing = {}
    for obj in resources:
        meta = obj["metadata"]
        key = (obj["kind"], meta["name"], meta.get("namespace"))
        observed = cluster.get(*key)
        check_existing(obj, observed, user)
        existing[key] = observed
    permissions = {(obj["kind"], obj["metadata"].get("namespace")) for obj in resources}
    for verb in ("create", "get"):
        for kind, namespace in sorted(permissions):
            args = ["auth", "can-i", verb, kind, "--quiet"]
            if namespace: args += ["-n", namespace]
            cluster.command(*args)
    facts, pending = [], []
    namespaces = {r["metadata"]["name"]: existing[(r["kind"], r["metadata"]["name"], None)]
                  for r in resources if r["kind"] == "Namespace"}
    # Check all namespace admission before creating the first namespace.
    for obj in resources:
        if obj["kind"] == "Namespace" and namespaces[obj["metadata"]["name"]] is None:
            cluster.create(obj, dry_run=True)
    # Namespace admission must succeed before namespaced dry runs can run.
    for obj in sorted(resources, key=lambda r: r["kind"] != "Namespace"):
        meta = obj["metadata"]
        key = (obj["kind"], meta["name"], meta.get("namespace"))
        observed = existing[key]
        if observed is None:
            if not apply and meta.get("namespace") and not namespaces[meta["namespace"]]:
                pending.append({"kind": key[0], "namespace": key[2], "name": key[1]})
                continue
            if obj["kind"] != "Namespace":
                cluster.create(obj, dry_run=True)
            if apply:
                observed = cluster.create(obj)
        meta = (observed or {}).get("metadata", {})
        facts.append({"kind": key[0], "namespace": key[2], "name": key[1],
                      "uid": meta.get("uid"), "phase": (observed or {}).get("status", {}).get("phase")})
        if key[0] == "Namespace":
            annotations = meta.get("annotations", {})
            facts[-1]["uidRange"] = annotations.get("openshift.io/sa.scc.uid-range")
            facts[-1]["supplementalGroups"] = annotations.get("openshift.io/sa.scc.supplemental-groups")
    return {"phase": "StorageReserved" if apply else "PreparationChecked", "enrolled": False,
            "qualified": False, "resources": facts, "admissionPending": pending}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--values", default=os.environ.get("SAW_USERS_VALUES_FILE"))
    parser.add_argument("--name", default=os.environ.get("OPENSHELL_SAW_NAME"))
    parser.add_argument("--context", default=os.environ.get("SAW_KUBE_CONTEXT"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if not args.values or not args.name or not args.context:
            raise Error("set SAW_USERS_VALUES_FILE, OPENSHELL_SAW_NAME and SAW_KUBE_CONTEXT")
        if args.output and (args.output.exists() or args.output.is_symlink()):
            raise Error("ConfidentialPreparationOutputExists")
        config, user = install.select(yaml.safe_load(Path(args.values).read_text()), args.name)
        def render(release, namespace, values):
            return (r for r in yaml.safe_load_all(install.run(
                "helm", "template", release, str(ROOT / "charts/saw-audit-writer"),
                "-n", namespace, "-f", "-", input_text=json.dumps(values))) if r)
        resources = plan(config, user, render)
        result = prepare(Cluster(args.context), config, user, resources, apply=args.apply)
        text = json.dumps(result, indent=2) + "\n"
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(text)
        print(text, end="")
    except Error as exc:
        parser.exit(1, str(exc) + "\n")
    except install.preflight_checks.PreflightError as exc:
        parser.exit(1, exc.reason + "\n")
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError, subprocess.SubprocessError):
        # Input parsing exceptions can quote credential-like values. Never echo them.
        parser.exit(1, "Confidential preparation failed; check public configuration, ownership and API access.\n")


if __name__ == "__main__":
    main()
