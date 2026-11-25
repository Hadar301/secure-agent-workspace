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
    if key in {"confidentialTrusteeConfig", "confidentialTrustee"}:
        try:
            return (attestation.trustee_config_digest(value) if key == "confidentialTrusteeConfig"
                    else attestation.trustee_deployment_digest(value))
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



def verify_confidential_driver(config, plan, context, driver, gateway, provider_policy=None):
    """Check the actual approved driver settings before confidential RPCs."""
    if context is None:
        if driver.get("confidential_mode"):
            raise BoundaryError("UnexpectedConfidentialDriver")
        return
    settings = context["settings"]
    containers = gateway.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    gateways = [c for c in containers if c.get("name") == "gateway"]
    if (driver.get("confidential_mode") is not True
            or len(gateways) != 1 or gateways[0].get("image") != settings["driver"]["gatewayImage"]
            or driver.get("supervisor_image") != settings["driver"]["supervisorImage"]
            or driver.get("default_runtime_class_name") != config.get("workloadRuntimeClass")
            or any(driver.get(key) for key in (
                "https_proxy", "no_proxy", "proxy_auth_secret_name", "proxy_auth_secret_key",
                "proxy_ca_bundle", "proxy_auth_allow_insecure", "provider_spiffe_workload_api_socket_path"))):
        raise BoundaryError("ConfidentialDriverMismatch")
    supervisors = driver.get("confidential_supervisors")
    workloads = driver.get("confidential_workloads")
    if (not isinstance(supervisors, dict) or not supervisors
            or not isinstance(workloads, dict) or set(supervisors) != set(workloads)):
        raise BoundaryError("ConfidentialDriverMismatch")
    # During boundary capture the compiled plan is not available yet. The
    # approved gateway-config hash binds these settings. Runtime passes must
    # additionally match the recomputed per-slot init-data contract exactly.
    if "schemaVersion" not in plan:
        return
    placements = plan.get("attestation", {}).get("placements")
    if not isinstance(placements, dict) or set(supervisors) != set(placements):
        raise BoundaryError("ConfidentialDriverMismatch")
    try:
        bootstrap = attestation.supervisor_bootstrap(provider_policy, context["owner"], context["registration"])
    except attestation.AttestationError:
        raise BoundaryError("ConfidentialDriverMismatch") from None
    for slot, placement in placements.items():
        try:
            supervisor = placement["supervisor"]
            workload = placement["workload"]
            expected_supervisor = {
                "runtime_class_name": supervisor["runtime_class_name"],
                "init_data": supervisor["init_data"],
                "bootstrap_json": bootstrap,
            }
            expected_workload = {key: workload[key] for key in ("runtime_class_name", "init_data")}
            if settings["schemaVersion"] == 2:
                pod = settings["launchPolicies"][slot]["supervisor"]["pod"]
                measured = [e.get("value") for e in pod["spec"]["containers"][0].get("env", [])
                            if e.get("name") == attestation.BOOTSTRAP_ENV]
                if measured != [bootstrap]:
                    raise BoundaryError("ConfidentialDriverMismatch")
        except (KeyError, TypeError, AttributeError):
            raise BoundaryError("ConfidentialDriverMismatch") from None
        if supervisors[slot] != expected_supervisor or workloads[slot] != expected_workload:
            raise BoundaryError("ConfidentialDriverMismatch")


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
        provider_policy = (json.loads(observed["confidentialProviderPolicy"]["data"]["policy.json"])
                           if confidential is not None else None)
        verify_confidential_driver(config, plan, confidential, driver, observed["gateway"], provider_policy)
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
            attestation.verify_deployment(site, get, "kata")
            attestation.verify_resource_membership(
                site, confidential["owner"], confidential["registration"], get)
            attestation.verify_resource_rollout(
                site, confidential["owner"], confidential["registration"], get)
        except attestation.AttestationError as exc:
            raise BoundaryError(str(exc)) from None
    verify_confidential_plan(config, plan, confidential)
