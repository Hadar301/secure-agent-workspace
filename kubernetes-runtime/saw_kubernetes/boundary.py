"""Read-only checks of the administrator-approved OpenShift installation."""
import hashlib
import json
import re
import uuid

import yaml

from . import provider as governed
from . import attestation


class BoundaryError(ValueError):
    pass


def fingerprint(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(data.encode()).hexdigest()


def _confidential_context(config):
    context = config.get("confidentialAttestation")
    if context is None:
        return None
    try:
        if (not isinstance(context, dict)
                or set(context) != {"settings", "owner", "registration", "installation"}
                or config.get("mode") != "kata"):
            raise ValueError()
        settings = attestation.validate({"attestation": context["settings"]}, "kata")
        if (settings is None or context["owner"] != config.get("gateway")
                or context["installation"] != config.get("ownerID")
                or context["registration"] != config.get("trustedNamespace", "").removeprefix("saw-ctl-")):
            raise ValueError()
        attestation.resource(context["owner"], context["registration"], "inference")
        if str(uuid.UUID(context["installation"])) != context["installation"]:
            raise ValueError()
        return context
    except (attestation.AttestationError, ValueError, TypeError, KeyError, AttributeError):
        raise BoundaryError("AttestationConfigurationRejected") from None


def approval_fingerprint(key, value):
    if key == "confidentialTrusteeConfig":
        try:
            return attestation.trustee_config_digest(value)
        except attestation.AttestationError as exc:
            raise BoundaryError(str(exc)) from None
    return fingerprint(value)


def objects(config):
    ns = config["namespace"]
    trusted = config["trustedNamespace"]
    governance = config["governanceNamespace"]
    gateway = config["gateway"]
    policy = f"saw-{ns}-runtime"
    admission = "/apis/admissionregistration.k8s.io/v1"
    apps = "/apis/apps/v1/namespaces"
    net = "/apis/networking.k8s.io/v1/namespaces"
    core = "/api/v1/namespaces"
    placement = {}
    if config.get("mode") == "kata":
        placement = {
            "sandboxPlacement": (f"{admission}/validatingadmissionpolicies/{policy}-kata", "spec"),
            "sandboxPlacementBinding": (f"{admission}/validatingadmissionpolicybindings/{policy}-kata", "spec"),
        }
    result = {
        **placement,
        "validation": (f"{admission}/validatingadmissionpolicies/{policy}", "spec"),
        "podDeleteGuard": (f"{admission}/validatingadmissionpolicies/{ns}-pods-driver", "spec"),
        "podDeleteBinding": (f"{admission}/validatingadmissionpolicybindings/{ns}-pods-driver", "spec"),
        "secretGuard": (f"{admission}/validatingadmissionpolicies/{ns}-secrets-driver", "spec"),
        "secretBinding": (f"{admission}/validatingadmissionpolicybindings/{ns}-secrets-driver", "spec"),
        "serviceGuard": (f"{admission}/validatingadmissionpolicies/{ns}-services-driver", "spec"),
        "serviceBinding": (f"{admission}/validatingadmissionpolicybindings/{ns}-services-driver", "spec"),
        "gatewayRole": (f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles/{gateway}-gateway", "rules"),
        "workloadFence": (f"{net}/{ns}/networkpolicies/openshell-sandbox-workloads", "spec"),
        "supervisorFence": (f"{net}/{ns}/networkpolicies/openshell-sandbox-supervisors", "spec"),
        "binding": (f"{admission}/validatingadmissionpolicybindings/{policy}", "spec"),
        "network": (f"/apis/policy.networking.k8s.io/v1alpha1/adminnetworkpolicies/{policy}-egress", "spec"),
        "deny": (f"{net}/{ns}/networkpolicies/{gateway}-default-deny", "spec"),
        "gatewayNetwork": (f"{net}/{ns}/networkpolicies/{gateway}-gateway", "spec"),
        "gateway": (f"{apps}/{ns}/statefulsets/{gateway}-gateway", "spec"),
        "gatewayService": (f"{core}/{ns}/services/{gateway}-gateway", "spec"),
        "gatewayConfig": (f"{core}/{ns}/configmaps/{gateway}-gateway-config", "data"),
        "governance": (f"{apps}/{governance}/deployments/governance-interceptor", "spec"),
        "governanceService": (f"{core}/{governance}/services/governance-interceptor", "spec"),
        "governancePolicy": (f"{core}/{governance}/configmaps/governance-interceptor-policy", "data"),
        "governanceProfiles": (f"{core}/{governance}/configmaps/governance-interceptor-profiles", "data"),
        "proxy": (f"{apps}/{trusted}/deployments/{gateway}-credential-proxy", "spec"),
        "proxyNetwork": (f"{net}/{trusted}/networkpolicies/{gateway}-credential-proxy", "spec"),
        "proxyPolicy": (f"{core}/{trusted}/configmaps/{config.get('proxyPolicy', gateway + '-proxy-policy')}", "data"),
        "publicCA": (f"{core}/{ns}/configmaps/{gateway}-proxy-ca", "data"),
    }
    context = _confidential_context(config)
    if context is not None:
        # Confidential supervisors fetch credentials from CDH inside the VM.
        # They do not use the Kubernetes-side credential proxy or its CA.
        for key in ("proxy", "proxyNetwork", "proxyPolicy", "publicCA"):
            result.pop(key)
        provider_policy = config.get("confidentialProviderPolicy")
        if (not isinstance(provider_policy, str)
                or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", provider_policy)):
            raise BoundaryError("ConfidentialProviderPolicyUnavailable")
        result["confidentialProviderPolicy"] = (
            f"{core}/{trusted}/configmaps/{provider_policy}", "data")
        for key, ref in context["settings"]["references"].items():
            approval_key = "confidential" + key[0].upper() + key[1:]
            field = "spec" if key in {"trustee", "trusteeConfig"} else "data"
            result[approval_key] = (ref["path"], field)
    return result


def complete_list(get, path):
    response = get(path)
    if response.get("metadata", {}).get("continue") or not isinstance(response.get("items"), list):
        raise BoundaryError("IncompleteInventory")
    return response["items"]


def verify_confidential_plan(config, plan, confidential):
    if confidential is None:
        if plan.get("schemaVersion") == 2 or "attestation" in plan:
            raise BoundaryError("AttestationApprovalMissing")
        return
    if "schemaVersion" not in plan:
        if "attestation" in plan:
            raise BoundaryError("AttestationPlanMismatch")
        return
    if (plan.get("schemaVersion") != 2
            or plan.get("mode") != "kata"
            or plan.get("requestedPlacement") != {
                "supervisor": "confidential", "workload": "confidential"}
            or plan.get("runtimeClass", {}).get("name") != config.get("workloadRuntimeClass")):
        raise BoundaryError("AttestationPlanMismatch")
    slots = [f"{workspace['name']}/{sandbox['name']}"
             for workspace in plan.get("workspaces", [])
             for sandbox in workspace.get("sandboxes", [])]
    try:
        expected = attestation.placement_contract(
            {"attestation": confidential["settings"]}, confidential["owner"],
            confidential["registration"], confidential["installation"], slots,
            config["workloadRuntimeClass"])
    except (attestation.AttestationError, KeyError, TypeError):
        raise BoundaryError("AttestationPlanMismatch") from None
    if plan.get("attestation") != expected:
        raise BoundaryError("AttestationPlanMismatch")


def excludes_namespace(policy, namespace):
    """Prove disjointness only with the Kubernetes-managed, immutable name label.

    Pod labels, ordinary namespace labels, and unsupported selector forms do
    not establish an isolation boundary. A missing/unknown subject overlaps.
    """
    subject = policy.get("spec", {}).get("subject", {})
    if not isinstance(subject, dict):
        return False
    if set(subject) == {"pods"} and isinstance(subject["pods"], dict):
        selector = subject["pods"].get("namespaceSelector")
    elif set(subject) == {"namespaces"}:
        selector = subject["namespaces"]
    else:
        return False
    labels = selector.get("matchLabels") if isinstance(selector, dict) else None
    name = labels.get("kubernetes.io/metadata.name") if isinstance(labels, dict) else None
    return isinstance(name, str) and bool(name) and name != namespace


def verify(config, plan, get):
    if (config["namespace"], config["namespaceUID"], config["ownerID"], config["mode"]) != (
            plan["namespace"], plan["namespaceUID"], plan["ownerID"], plan["mode"]):
        raise BoundaryError("WrongInstallation")
    refs = objects(config)
    confidential = _confidential_context(config)
    if set(config["approved"]) != set(refs):
        raise BoundaryError("IncompleteApproval")
    observed = {}
    for key, (path, field) in refs.items():
        obj = get(path)
        meta = obj["metadata"]
        expected = config["approved"][key]
        if (meta.get("deletionTimestamp") or meta["uid"] != expected["uid"]
                or approval_fingerprint(key, obj[field]) != expected["sha256"]):
            raise BoundaryError("ChangedBoundary:" + key)
        observed[key] = obj
    for workspace in plan.get("workspaces", []):
        for provider in workspace["providers"]:
            credentials = provider.get("credentials")
            if credentials:
                policy_key = ("confidentialProviderPolicy" if confidential is not None
                              else "proxyPolicy")
                policy_field = "policy.json" if confidential is not None else "config.json"
                policy = json.loads(observed[policy_key]["data"][policy_field])
                kind = provider.get("type", "openai")
                if kind not in {"openai", "custom-inference"}:
                    live = observed["governanceProfiles"]["data"].get(kind + ".yaml", "")
                    if yaml.safe_load(live) != governed.document(kind):
                        raise BoundaryError("ProviderGovernanceMismatch")
                if not governed.check_policy(kind, credentials, policy, plan.get("customInferenceURL")):
                    raise BoundaryError("OpenAIProxyBindingMismatch" if kind == "openai"
                                        else "ProviderProxyBindingMismatch")
    checks = ["validation", "secretGuard", "serviceGuard", "podDeleteGuard"]
    if config["mode"] == "kata":
        import tomllib
        driver = tomllib.loads(observed["gatewayConfig"]["data"]["gateway.toml"])["openshell"]["drivers"]["kubernetes"]
        runtime = config.get("workloadRuntimeClass")
        if (not runtime or plan.get("runtimeClass", {}).get("name", runtime) != runtime
                or driver.get("default_runtime_class_name") != runtime):
            raise BoundaryError("WrongWorkloadPlacement")
        checks.append("sandboxPlacement")
    for key in checks:
        vap = observed[key]
        status = vap.get("status", {})
        if (status.get("observedGeneration") != vap["metadata"]["generation"]
                or "typeChecking" not in status or status["typeChecking"].get("expressionWarnings")):
            raise BoundaryError("AdmissionUnavailable:" + key)
    network = observed["network"]
    priority = network["spec"]["priority"]
    policies = complete_list(get, "/apis/policy.networking.k8s.io/v1alpha1/adminnetworkpolicies")
    if any(p["metadata"]["uid"] != network["metadata"]["uid"] and p["spec"]["priority"] <= priority
           and not excludes_namespace(p, config["namespace"])
           for p in policies):
        raise BoundaryError("EarlierNetworkPolicy")
    nodes = complete_list(get, "/api/v1/nodes")
    zones = {n["metadata"]["name"] for n in nodes}
    realized = {c["type"].removeprefix("Ready-In-Zone-")
                for c in network.get("status", {}).get("conditions", [])
                if c["type"].startswith("Ready-In-Zone-") and c["status"] == "True"
                and c.get("reason") == "SetupSucceeded"}
    if not zones or not zones <= realized:
        raise BoundaryError("NetworkNotRealized")
    rollouts = ["gateway", "governance"]
    if confidential is None:
        rollouts.append("proxy")
    for key in rollouts:
        obj = observed[key]
        status = obj.get("status", {})
        if (status.get("observedGeneration") != obj["metadata"]["generation"]
                or status.get("readyReplicas", 0) != obj["spec"]["replicas"]
                or status.get("updatedReplicas", 0) != obj["spec"]["replicas"]):
            raise BoundaryError("RolloutIncomplete:" + key)
    if confidential is not None:
        site = {"attestation": confidential["settings"]}
        try:
            attestation.verify_platform(site, get, "kata")
            attestation.verify_resource_membership(
                site, confidential["owner"], confidential["registration"], get)
        except attestation.AttestationError as exc:
            raise BoundaryError(str(exc)) from None
    verify_confidential_plan(config, plan, confidential)
