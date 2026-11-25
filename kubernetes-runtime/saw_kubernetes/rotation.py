"""Administrator-controlled rotation. No Vault or Kubernetes Secret reads."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import time
import uuid

from . import attestation


class RotationError(ValueError):
    """A fixed reason that is safe to display."""


def eso_version(metadata):
    """ESO 1.3 ctrlutil.GetResourceVersion: SHA3-224 of Go HashMeta.

    HashMeta contains only annotations and labels, not Secret data.
    https://github.com/external-secrets/external-secrets/blob/v1.3.0/pkg/controllers/util/metadata.go
    """
    def go_map(value):
        if value is None:
            value = {}
        if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
            raise RotationError("RotationMetadataRejected")
        return "map[" + " ".join(k + ":" + value[k] for k in sorted(value)) + "]"
    generation = metadata.get("generation")
    if type(generation) is not int or generation < 1:
        raise RotationError("RotationMetadataRejected")
    raw = "{annotations:" + go_map(metadata.get("annotations")) + " labels:" + go_map(metadata.get("labels")) + "}"
    return str(generation) + "-" + hashlib.sha3_224(raw.encode()).hexdigest()


def ready(obj):
    return any(c.get("type") == "Ready" and c.get("status") == "True"
               for c in obj.get("status", {}).get("conditions", []))


def identity(obj):
    meta = obj.get("metadata", {})
    if meta.get("deletionTimestamp") or not meta.get("uid") or not meta.get("resourceVersion"):
        raise RotationError("RotationObjectUnavailable")
    return meta


def check_deadline(deadline, clock):
    if clock() >= deadline:
        raise RotationError("RotationTimedOut")


def wait_until(check, deadline, *, clock=time.monotonic, sleep=time.sleep):
    while True:
        value = check()
        if value:
            return value
        remaining = deadline - clock()
        if remaining <= 0:
            raise RotationError("RotationTimedOut")
        sleep(min(2, remaining))


def check_external_secret(request, path, owner, registration, store):
    """Check the registration-scoped ESO input and acknowledgement format."""
    before = request("GET", path)
    meta = identity(before)
    labels, spec = meta.get("labels", {}), before.get("spec", {})
    name = "saw-" + owner + "-" + registration
    if (meta.get("name") != name or labels.get("saw.redhat.com/portal-owner") != owner
            or labels.get("saw.redhat.com/registration") != registration
            or spec.get("secretStoreRef") != {"kind": "ClusterSecretStore", "name": store}
            or spec.get("target", {}).get("name") != name
            or spec.get("target", {}).get("creationPolicy") != "Owner"
            or not ready(before)):
        raise RotationError("RotationCredentialScopeRejected")
    if before.get("status", {}).get("syncedResourceVersion") != eso_version(meta):
        raise RotationError("RotationExternalSecretsVersionUnsupported")
    expected = re.compile(r"[A-Za-z0-9_-]+/data/(?:[A-Za-z0-9_-]+/)*saw-" + re.escape(owner)
                          + "/" + registration + r"/[A-Za-z0-9_-]+")
    sources = spec.get("data")
    if (spec.get("dataFrom") or not isinstance(sources, list) or not sources
            or any(not expected.fullmatch(str(item.get("remoteRef", {}).get("key", "")))
                   for item in sources)):
        raise RotationError("RotationCredentialScopeRejected")
    return before


def refresh_resource(request, path, owner, registration, store, deadline, *, clock=time.monotonic, sleep=time.sleep):
    before = check_external_secret(request, path, owner, registration, store)
    meta, spec = before["metadata"], before["spec"]
    nonce = str(uuid.uuid4())
    annotations = {**meta.get("annotations", {}), "force-sync": nonce}
    patch = [{"op": "test", "path": "/metadata/uid", "value": meta["uid"]},
             {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]},
             {"op": "add", "path": "/metadata/annotations", "value": annotations}]
    check_deadline(deadline, clock)
    changed = request("PATCH", path, patch)
    expected = eso_version(identity(changed))
    def observed():
        current = request("GET", path)
        cm = identity(current)
        if (cm["uid"] != meta["uid"] or current.get("spec") != spec
                or cm.get("annotations", {}).get("force-sync") != nonce
                or eso_version(cm) != expected):
            raise RotationError("RotationInputsChanged")
        status = current.get("status", {})
        return (ready(current) and status.get("syncedResourceVersion") == expected
                and status.get("refreshTime")
                and status["refreshTime"] != before.get("status", {}).get("refreshTime"))
    wait_until(observed, deadline, clock=clock, sleep=sleep)


def reload_trustee(request, reference, verify, deadline, *, clock=time.monotonic, sleep=time.sleep):
    """Evict one stateless operand Pod. Preserve the approved Deployment."""
    path = reference["path"]
    match = re.fullmatch(r"/apis/apps/v1/namespaces/([a-z0-9-]+)/deployments/([a-z0-9-]+)", path)
    if not match:
        raise RotationError("RotationTrusteeReferenceRejected")
    ns = match[1]
    def deployment():
        verify()
        obj = request("GET", path)
        meta = identity(obj)
        if (meta["uid"] != reference["uid"]
                or attestation.trustee_deployment_digest(obj["spec"]) != reference["sha256"]):
            raise RotationError("RotationApprovalChanged")
        if obj["spec"].get("replicas", 1) != 1:
            raise RotationError("RotationTrusteeTopologyUnsupported")
        return obj
    initial = deployment()
    selector = initial["spec"]["selector"]
    if set(selector) != {"matchLabels"} or not selector["matchLabels"]:
        raise RotationError("RotationTrusteeTopologyUnsupported")
    def pods():
        listing = request("GET", f"/api/v1/namespaces/{ns}/pods")
        if listing.get("metadata", {}).get("continue") or not isinstance(listing.get("items"), list):
            raise RotationError("RotationInventoryIncomplete")
        matched = []
        for pod in listing["items"]:
            pm = pod.get("metadata", {})
            if not all(pm.get("labels", {}).get(k) == v for k, v in selector["matchLabels"].items()):
                continue
            refs = [r for r in pm.get("ownerReferences", []) if r.get("controller") is True]
            if len(refs) != 1 or refs[0].get("kind") != "ReplicaSet":
                raise RotationError("RotationTrusteeOwnerRejected")
            rs = request("GET", f"/apis/apps/v1/namespaces/{ns}/replicasets/{refs[0]['name']}")
            rm = identity(rs)
            if (rm["uid"] != refs[0].get("uid") or not any(
                    r.get("controller") is True and r.get("kind") == "Deployment"
                    and r.get("uid") == reference["uid"] for r in rm.get("ownerReferences", []))):
                raise RotationError("RotationTrusteeOwnerRejected")
            matched.append(pod)
        return matched

    current = pods()
    if len(current) != 1 or not ready(current[0]):
        raise RotationError("RotationTrusteeNotReady")
    old = identity(current[0])
    deployment()  # Recheck approval immediately before the eviction.
    eviction = {"apiVersion": "policy/v1", "kind": "Eviction",
                "metadata": {"name": old["name"], "namespace": ns},
                "deleteOptions": {"preconditions": {"uid": old["uid"], "resourceVersion": old["resourceVersion"]}}}
    check_deadline(deadline, clock)
    request("POST", f"/api/v1/namespaces/{ns}/pods/{old['name']}/eviction", eviction)
    def replacement():
        obj = deployment()
        new = pods()
        if any(p.get("metadata", {}).get("uid") == old["uid"] for p in new):
            return False
        live = [p for p in new if not p.get("metadata", {}).get("deletionTimestamp")]
        if len(live) != 1:
            return False
        status = obj.get("status", {})
        return (ready(live[0]) and status.get("observedGeneration") == obj["metadata"].get("generation")
                and status.get("readyReplicas") == status.get("updatedReplicas") == 1)
    wait_until(replacement, deadline, clock=clock, sleep=sleep)


class ManagedLifecycle:
    """Change the portal's source registry, never Argo-generated runtime data."""
    def __init__(self, request, owner, registration, installation, portal_namespace, runtime_namespace, status_name):
        self.request = request
        self.owner, self.registration = owner, registration
        self.installation = installation
        self.path = f"/api/v1/namespaces/{portal_namespace}/configmaps/saw-ws-{owner}"
        self.status_path = f"/api/v1/namespaces/{runtime_namespace}/configmaps/{status_name}"
        self.uid = None
        self.initial = None
        self.status_uid = None

    def read(self):
        obj = self.request("GET", self.path)
        meta = identity(obj)
        try:
            entry = json.loads(obj["data"]["user.json"])
        except (ValueError, KeyError, TypeError):
            raise RotationError("RotationRegistryRejected") from None
        if (meta.get("labels", {}).get("saw.redhat.com/deleting") == "true"
                or any(meta.get("annotations", {}).get(k) for k in
                       ["saw.redhat.com/deletion", "saw.redhat.com/credential-writer"])
                or entry.get("name") != self.owner
                or not str(entry.get("vaultPrefix", "")).endswith("/saw-" + self.owner + "/" + self.registration)
                or entry.get("values", {}).get("deployment", {}).get("mode") != "kata"
                or self.uid is not None and meta["uid"] != self.uid):
            raise RotationError("RotationRegistryRejected")
        if entry.get("lifecycleVersion") != 1:
            raise RotationError("RotationManagedLifecycleRequired")
        if type(entry.get("intentGeneration")) is not int or entry["intentGeneration"] < 1:
            raise RotationError("RotationRegistryRejected")
        self.uid = meta["uid"]
        return obj, entry

    def preflight(self):
        _, entry = self.read()
        if entry.get("desiredState") != "Running":
            raise RotationError("RotationWorkspaceNotRunning")
        self.initial = copy.deepcopy(entry)
        status = self.status()
        if (status.get("phase") != "GenericReady"
                or status.get("observedGeneration") != entry["intentGeneration"]):
            raise RotationError("RotationWorkspaceNotRunning")

    def status(self):
        obj = self.request("GET", self.status_path)
        meta = identity(obj)
        labels = meta.get("labels", {})
        if (labels.get("saw.redhat.com/runtime-owner") != self.installation
                or labels.get("saw.redhat.com/managed-by") != "kubernetes-runtime-controller"
                or self.status_uid is not None and meta["uid"] != self.status_uid):
            raise RotationError("RotationStatusRejected")
        self.status_uid = meta["uid"]
        try:
            return json.loads(obj["data"]["status.json"])
        except (ValueError, KeyError, TypeError):
            raise RotationError("RotationStatusRejected") from None

    def change(self, desired, deadline, *, clock=time.monotonic, sleep=time.sleep):
        obj, entry = self.read()
        expected = self.initial
        if expected is None or entry != expected:
            raise RotationError("RotationInputsChanged")
        changed = {**entry, "desiredState": desired, "intentGeneration": entry["intentGeneration"] + 1}
        patch = [{"op": "test", "path": "/metadata/uid", "value": self.uid},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": obj["metadata"]["resourceVersion"]},
                 {"op": "replace", "path": "/data/user.json", "value": json.dumps(changed, sort_keys=True)}]
        check_deadline(deadline, clock)
        self.request("PATCH", self.path, patch)
        self.initial = changed
        def observed():
            _, current = self.read()
            if current != changed:
                raise RotationError("RotationInputsChanged")
            status = self.status()
            if status.get("observedGeneration") != changed["intentGeneration"]:
                return False
            if status.get("phase") == "Blocked":
                raise RotationError("RotationRuntimeBlocked")
            return status.get("phase") == ("Stopped" if desired == "Stopped" else "GenericReady")
        wait_until(observed, deadline, clock=clock, sleep=sleep)


def supervisors(request, scope):
    namespace = request("GET", "/api/v1/namespaces/" + scope["runtimeNamespace"])
    meta = identity(namespace)
    if (meta["uid"] != scope["runtimeNamespaceUID"]
            or meta.get("labels", {}).get("saw.redhat.com/runtime-owner") != scope["installation"]):
        raise RotationError("RotationNamespaceReplaced")
    listed = request("GET", "/api/v1/namespaces/" + scope["runtimeNamespace"] + "/pods")
    if listed.get("metadata", {}).get("continue") or not isinstance(listed.get("items"), list):
        raise RotationError("RotationInventoryIncomplete")
    found, annotations = set(), set()
    for pod in listed["items"]:
        pm, spec = pod.get("metadata", {}), pod.get("spec", {})
        if pm.get("labels", {}).get("openshell.ai/boundary-role") != "supervisor":
            continue
        init_data = pm.get("annotations", {}).get("io.katacontainers.config.hypervisor.cc_init_data")
        images = [c.get("image") for c in spec.get("containers", []) if c.get("name") == "supervisor"]
        if (spec.get("runtimeClassName") != scope["runtimeClass"]
                or images != [scope["supervisorImage"]] or init_data not in scope["supervisorInitData"]):
            raise RotationError("RotationSupervisorPlacementChanged")
        if pm.get("deletionTimestamp") or not ready(pod):
            return None
        found.add(identity(pod)["uid"])
        if init_data in annotations:
            raise RotationError("RotationSupervisorPlacementChanged")
        annotations.add(init_data)
    return found if annotations == set(scope["supervisorInitData"]) and found else None


def rotate(request, scope, lifecycle, verify, *, timeout=900, clock=time.monotonic, sleep=time.sleep, report=lambda reason: None):
    """Rotate one managed registration; all failures stop the sequence."""
    if type(timeout) is not int or not 60 <= timeout <= 1800:
        raise RotationError("RotationTimeoutRejected")
    if not callable(verify):
        raise RotationError("RotationVerifierRequired")
    deadline = clock() + timeout
    verify()
    lifecycle.preflight()
    original = supervisors(request, scope)
    if not original:
        raise RotationError("RotationSupervisorUnavailable")
    # The CLI holds the shared maintenance Lease. The managed lifecycle
    # creates a fresh sandbox generation but preserves registration and PVCs.
    report("RefreshingTrusteeResource")
    refresh_resource(request, scope["externalSecretPath"], scope["owner"], scope["registration"],
                     scope["secretStore"], deadline, clock=clock, sleep=sleep)
    verify()
    report("ReloadingTrustee")
    reload_trustee(request, scope["trustee"], verify, deadline, clock=clock, sleep=sleep)
    verify()
    report("StoppingSelectedRegistration")
    lifecycle.change("Stopped", deadline, clock=clock, sleep=sleep)
    verify()
    report("StartingSelectedRegistration")
    lifecycle.change("Running", deadline, clock=clock, sleep=sleep)
    def replaced():
        verify()
        current = supervisors(request, scope)
        return current and current.isdisjoint(original)
    wait_until(replaced, deadline, clock=clock, sleep=sleep)
    report("RotationComplete")


def prepare(request, owner, registration, secret_store, portal_namespace="saw-portal"):
    """Resolve the enrolled boundary. Read public configuration only."""
    from . import boundary, compiler, preflight
    from .controller import valid_lifecycle_intent
    if (not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,17}[a-z0-9])?", owner)
            or not re.fullmatch(r"[a-f0-9]{16}", registration)
            or any(not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", s)
                   for s in (secret_store, portal_namespace))):
        raise RotationError("RotationIdentityRejected")
    trusted = "saw-ctl-" + registration
    config_path = f"/api/v1/namespaces/{trusted}/configmaps/{owner}-reconciler"
    config_cm = request("GET", config_path)
    config = json.loads(config_cm["data"]["controller.json"])
    context = boundary._confidential_context(config)
    if (context is None or context["owner"] != owner or context["registration"] != registration
            or config["namespace"] != "saw-" + owner):
        raise RotationError("RotationIdentityRejected")
    installation, runtime = context["installation"], config["namespace"]
    def read_cm(name):
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?", name):
            raise RotationError("RotationIdentityRejected")
        path = f"/api/v1/namespaces/{runtime}/configmaps/{name}"
        obj = request("GET", path)
        if identity(obj).get("labels", {}).get("saw.redhat.com/runtime-owner") != installation:
            raise RotationError("RotationIdentityRejected")
        return path, obj
    intent_path, intent_cm = read_cm(config["intent"])
    intent = json.loads(intent_cm["data"]["intent.json"])
    if not valid_lifecycle_intent(intent) or intent["desiredState"] != "Running":
        raise RotationError("RotationWorkspaceNotRunning")
    profile_path, profile = read_cm(config["profile"])
    reference = intent["profileRef"]
    if (reference["name"] != config["profile"] or reference["uid"] != identity(profile)["uid"]
            or reference["sha256"] != compiler.digest(profile["data"])):
        raise RotationError("RotationProfileChanged")
    plan = compiler.compile_profile_files(profile["data"], intent["bindings"])
    if reference.get("planSHA256") != plan["revision"]:
        raise RotationError("RotationProfileChanged")
    boundary.verify(config, plan, lambda path: request("GET", path))
    settings = context["settings"]
    trustee = settings["references"]["trustee"]
    trustee_ns = trustee["path"].split("/")[5]
    store_path = "/apis/external-secrets.io/v1/clustersecretstores/" + secret_store
    store = request("GET", store_path)
    provider = store["spec"].get("provider", {}).get("vault", {})
    if (store["spec"].get("conditions") != [{"namespaces": [trustee_ns]}]
            or provider.get("version") != "v2"
            or not str(provider.get("server", "")).startswith("https://")
            or not (provider.get("caBundle") or provider.get("caProvider"))
            or provider.get("auth", {}).get("kubernetes", {}).get("serviceAccountRef", {}).get("namespace") != trustee_ns
            or not ready(store)):
        raise RotationError("RotationSecretStoreRejected")
    tracked = {config_path: config_cm, profile_path: profile, store_path: store}
    def verify():
        runtime_class = request("GET", "/apis/node.k8s.io/v1/runtimeclasses/" + scope["runtimeClass"])
        try:
            identity(runtime_class)
            preflight.check_runtime_class(plan["runtimeClass"], runtime_class)
        except (preflight.PreflightError, RotationError):
            raise RotationError("RotationRuntimeClassChanged") from None
        _, current_entry = lifecycle.read()
        if current_entry != lifecycle.initial:
            raise RotationError("RotationInputsChanged")
        # Health is transient during reload. Keep approved identities and
        # contents fixed while the replacement Pod becomes ready.
        for path, original in tracked.items():
            current = request("GET", path)
            if (identity(current)["uid"] != identity(original)["uid"]
                    or any(current.get(k) != original.get(k) for k in ("spec", "data"))):
                raise RotationError("RotationInputsChanged")
        for key, (path, field) in boundary.objects(config).items():
            obj = request("GET", path)
            expected = config["approved"][key]
            if (identity(obj)["uid"] != expected["uid"]
                    or boundary.approval_fingerprint(key, obj[field]) != expected["sha256"]):
                raise RotationError("RotationApprovalChanged")
        current = request("GET", intent_path)
        value = json.loads(current["data"]["intent.json"])
        if (identity(current)["uid"] != identity(intent_cm)["uid"]
                or not valid_lifecycle_intent(value)
                or any(value[k] != intent[k] for k in ("bindings", "profileRef"))):
            raise RotationError("RotationInputsChanged")
    scope = dict(owner=owner, registration=registration, installation=installation,
                 runtimeNamespace=runtime, runtimeNamespaceUID=config["namespaceUID"],
                 runtimeClass=config["workloadRuntimeClass"],
                 supervisorImage=settings["driver"]["supervisorImage"],
                 supervisorInitData={p["supervisor"]["init_data"]
                                     for p in plan["attestation"]["placements"].values()},
                 externalSecretPath=f"/apis/external-secrets.io/v1/namespaces/{trustee_ns}/externalsecrets/saw-{owner}-{registration}",
                 secretStore=secret_store, trustee=trustee)
    lifecycle = ManagedLifecycle(request, owner, registration, installation,
                                 portal_namespace, runtime, config["status"])
    tracked[scope["externalSecretPath"]] = check_external_secret(
        request, scope["externalSecretPath"], owner, registration, secret_store)
    lifecycle.preflight()
    if not supervisors(request, scope):
        raise RotationError("RotationSupervisorUnavailable")
    # Check mutation privileges before the first resource change.
    for group, resource, verb, namespace, name, subresource in [
        ("external-secrets.io", "externalsecrets", "patch", trustee_ns, "saw-" + owner + "-" + registration, ""),
        ("", "pods", "create", trustee_ns, "", "eviction"),
        ("", "configmaps", "patch", portal_namespace, "saw-ws-" + owner, ""),
        ("coordination.k8s.io", "leases", "get", trustee_ns, "saw-credential-rotation", ""),
        ("coordination.k8s.io", "leases", "create", trustee_ns, "", ""),
        ("coordination.k8s.io", "leases", "patch", trustee_ns, "saw-credential-rotation", ""),
    ]:
        attrs = dict(group=group, resource=resource, verb=verb, namespace=namespace)
        if name: attrs["name"] = name
        if subresource: attrs["subresource"] = subresource
        review = request("POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                         {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
                          "spec": {"resourceAttributes": attrs}})
        if review.get("status", {}).get("allowed") is not True:
            raise RotationError("RotationPermissionDenied")
    verify()
    return scope, lifecycle, verify


class maintenance_lock:
    """Serialize shared Trustee maintenance. Never take over a stale holder."""
    def __init__(self, request, namespace):
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", namespace):
            raise RotationError("RotationIdentityRejected")
        self.request = request
        self.path = f"/apis/coordination.k8s.io/v1/namespaces/{namespace}/leases/saw-credential-rotation"
        self.namespace = namespace
        self.holder = str(uuid.uuid4())

    def __enter__(self):
        try:
            obj = self.request("GET", self.path)
        except RotationError as exc:
            if str(exc) != "RotationObjectUnavailable":
                raise
            obj = self.request("POST", self.path.rsplit("/", 1)[0], {
                "apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
                "metadata": {"name": "saw-credential-rotation", "namespace": self.namespace},
                "spec": {"holderIdentity": self.holder}})
            self.uid = identity(obj)["uid"]
            return self
        meta = identity(obj)
        if obj.get("spec", {}).get("holderIdentity"):
            raise RotationError("RotationMaintenanceLocked")
        self.uid = meta["uid"]
        self.request("PATCH", self.path, [
            {"op": "test", "path": "/metadata/uid", "value": self.uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]},
            {"op": "add", "path": "/spec/holderIdentity", "value": self.holder}])
        return self

    def __exit__(self, exc_type, exc, traceback):
        obj = self.request("GET", self.path)
        meta = identity(obj)
        if meta["uid"] != self.uid or obj.get("spec", {}).get("holderIdentity") != self.holder:
            raise RotationError("RotationMaintenanceLockChanged")
        self.request("PATCH", self.path, [
            {"op": "test", "path": "/metadata/uid", "value": self.uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]},
            {"op": "replace", "path": "/spec/holderIdentity", "value": ""}])
        return False
