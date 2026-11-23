"""Public confidential-workspace contract and Trustee registration helpers."""
import base64
import gzip
import hashlib
import io
import json
import re
import ssl
import uuid
from datetime import datetime, timezone
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

CAPABILITY = "saw-confidential-v1"
ANNOTATION = "io.katacontainers.config.hypervisor.cc_init_data"
IDENTITY_MARKER = "__SAW_IDENTITY_JSON__"
SHA = re.compile(r"[a-f0-9]{64}\Z")
IMAGE = re.compile(r"[^\s@]+@sha256:[a-f0-9]{64}\Z")
LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\Z")
REFERENCE_VALUE_NAMES = frozenset({"pcr03", "pcr08", "pcr09", "pcr11", "pcr12"})
REFERENCE_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
POLICY_DATA = re.compile(r"(?m)^[ \t]*policy_data[ \t]*:=[ \t]*\{")
IDENTITY_MEMBER = re.compile(
    r"(?m)^[ \t]*\"saw_identity\"[ \t]*:[ \t]*" + re.escape(IDENTITY_MARKER) + r"[ \t]*,?[ \t]*$")
KATA_AGENT_POLICY_TEMPLATE = r'''package agent_policy

import future.keywords.in
import future.keywords.if

default AddARPNeighborsRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResumeContainerRequest := true
default SetGuestDateTimeRequest := true
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := true
default StatsContainerRequest := true
default StopTracingRequest := true
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := true
default CreateContainerRequest := true
default ReadStreamRequest := false
default CopyFileRequest := false
default SetPolicyRequest := false
default ExecProcessRequest := false

CopyFileRequest if {
    allow_copy_file
}

allow_copy_file if {
    input.file_type == "Regular"
    allow_copy_file_path(input.path, "")
}

allow_copy_file if {
    input.file_type == "Directory"
    allow_copy_file_path(input.path, "")
}

allow_copy_file if {
    input.file_type == "Symlink"
    allow_copy_file_path(input.path, ".*/.+")
    check_directory_traversal(input.symlink_target)
    not startswith(input.symlink_target, "/")
}

allow_copy_file_path(path, regex_suffix) if {
    check_directory_traversal(path)
    some regex1 in policy_data.request_defaults.CopyFileRequest
    regex2 := replace(regex1, "$(sfprefix)", policy_data.common.sfprefix)
    regex3 := replace(regex2, "$(cpath)", policy_data.common.cpath)
    regex4 := replace(regex3, "$(bundle-id)", "[a-z0-9]{64}")
    regex5 := concat("", [regex4, regex_suffix])
    regex.match(regex5, path)
}

check_directory_traversal(i_path) if {
    not regex.match("(^|/)\\.\\.($|/)", i_path)
}

policy_data := {
    "saw_identity": __SAW_IDENTITY_JSON__,
    "common": {
        "cpath": "/run/kata-containers/shared/containers(?:/passthrough)?",
        "sfprefix": "^$(cpath)/(watchable/)?$(bundle-id)-[a-z0-9]{16}-"
    },
    "request_defaults": {
        "CopyFileRequest": ["$(sfprefix)"]
    }
}
'''

class AttestationError(ValueError):
    """Only fixed reason codes may leave this module."""

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def trustee_config_digest(spec):
    """Hash stable Trustee configuration, excluding its per-registration list."""
    if not isinstance(spec, dict):
        raise AttestationError("TrusteeConfigurationRejected")
    resources = spec.get("kbsSecretResources", [])
    if (not isinstance(resources, list)
            or any(not isinstance(name, str) or len(name) > 253
                   or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?", name)
                   for name in resources)
            or len(resources) != len(set(resources))):
        raise AttestationError("TrusteeConfigurationRejected")
    stable = {key: value for key, value in spec.items() if key != "kbsSecretResources"}
    return digest(stable)

def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

def verify_reference_values(data, expected_digest, tee):
    """Check Trustee 1.2 RVPS data and its approved canonical digest."""
    raw = data.get("reference_value") if isinstance(data, dict) else None
    if not isinstance(raw, str):
        raise AttestationError("ReferenceValuesRejected")
    try:
        values = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (ValueError, TypeError):
        raise AttestationError("ReferenceValuesRejected") from None
    if not isinstance(values, dict) or not values or tee not in ("snp", "tdx"):
        raise AttestationError("ReferenceValuesRejected")
    required_names = {f"{tee}_{suffix}" for suffix in REFERENCE_VALUE_NAMES}
    if not required_names.issubset(values):
        raise AttestationError("ReferenceValuesRejected")
    for name, encoded in values.items():
        if not isinstance(name, str) or not re.fullmatch(rf"{tee}_[a-z0-9_]+", name):
            raise AttestationError("ReferenceValuesRejected")
        try:
            decoded = base64.b64decode(encoded, validate=True)
            if base64.b64encode(decoded).decode("ascii") != encoded:
                raise ValueError("non-canonical base64")
            item = json.loads(decoded, object_pairs_hook=_unique_json_object)
            expiry = datetime.fromisoformat(item["expiration"].replace("Z", "+00:00"))
            measurements = item["value"]
        except (ValueError, TypeError, KeyError, UnicodeDecodeError, AttributeError):
            raise AttestationError("ReferenceValuesRejected") from None
        if (not isinstance(item, dict) or set(item) != {"name", "expiration", "value"}
                or item.get("name") != name or expiry.tzinfo is None
                or expiry.utcoffset() is None or expiry <= datetime.now(timezone.utc)
                or not isinstance(measurements, list) or not measurements
                or any(not isinstance(value, str) or not REFERENCE_SHA256.fullmatch(value)
                       for value in measurements)):
            raise AttestationError("ReferenceValuesRejected")
    if digest(values) != expected_digest:
        raise AttestationError("ReferenceValuesRejected")
    return values

def enabled(site):
    value = site.get("attestation") if isinstance(site, dict) else None
    if value is None:
        return False
    if not isinstance(value, dict) or type(value.get("enabled")) is not bool:
        raise AttestationError("AttestationConfigurationRejected")
    return value["enabled"]

def validate(site, mode="kata"):
    try:
        return _validate(site, mode)
    except AttestationError:
        raise
    except (ValueError, TypeError, AttributeError, KeyError):
        raise AttestationError("AttestationConfigurationRejected") from None

def _validate(site, mode="kata"):
    if not enabled(site):
        return None
    cfg = site["attestation"]
    required = {"enabled", "schemaVersion", "tee", "kbsURL", "kbsCA", "policyDigest",
                "referenceSet", "guestPolicy", "imagePolicy", "driver", "references"}
    if set(cfg) != required or mode != "kata" or (type(cfg["schemaVersion"]) is not int or cfg["schemaVersion"] != 1) or cfg["tee"] not in ("snp", "tdx"):
        raise AttestationError("AttestationConfigurationRejected")
    try:
        u = urlsplit(cfg["kbsURL"])
        valid = (u.scheme == "https" and u.hostname and u.username is None
                 and u.password is None and not u.query and not u.fragment
                 and u.path in {"", "/"} and u.port in {None, 443})
    except (ValueError, TypeError):
        valid = False
    if not valid or not isinstance(cfg["kbsCA"], str):
        raise AttestationError("TrusteeTrustRejected")
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=cfg["kbsCA"])
    except (ValueError, ssl.SSLError):
        raise AttestationError("TrusteeTrustRejected") from None
    if (not isinstance(cfg["guestPolicy"], str) or len(cfg["guestPolicy"]) > 512*1024
            or not SHA.fullmatch(str(cfg["policyDigest"]))
            or hashlib.sha256(cfg["guestPolicy"].encode()).hexdigest() != cfg["policyDigest"]
            or not SHA.fullmatch(str(cfg["referenceSet"]))):
        raise AttestationError("AttestationPolicyRejected")
    policy = cfg["guestPolicy"]
    if (len(POLICY_DATA.findall(policy)) != 1 or len(IDENTITY_MEMBER.findall(policy)) != 1
            or policy.count(IDENTITY_MARKER) != 1):
        raise AttestationError("AttestationIdentityClaimUnavailable")
    if policy != KATA_AGENT_POLICY_TEMPLATE:
        raise AttestationError("AttestationPolicyRejected")
    image_policy = cfg["imagePolicy"]
    if not isinstance(image_policy, dict) or image_policy.get("default") != [{"type": "reject"}]:
        raise AttestationError("ImageSignaturePolicyRejected")
    transports = image_policy.get("transports")
    if not isinstance(transports, dict) or not transports:
        raise AttestationError("ImageSignaturePolicyRejected")
    for transport, scopes in transports.items():
        if transport != "docker" or not isinstance(scopes, dict) or not scopes:
            raise AttestationError("ImageSignaturePolicyRejected")
        for scope, rules in scopes.items():
            if not isinstance(scope, str) or not scope or "*" in scope or not isinstance(rules, list) or not rules:
                raise AttestationError("ImageSignaturePolicyRejected")
            if any(not isinstance(r, dict) or r.get("type") not in {"sigstoreSigned", "signedBy"} for r in rules):
                raise AttestationError("ImageSignaturePolicyRejected")
    driver = cfg["driver"]
    if (not isinstance(driver, dict) or set(driver) != {"capability", "sourceRevision", "gatewayImage", "supervisorImage"}
            or driver["capability"] != CAPABILITY
            or not re.fullmatch(r"[a-f0-9]{40}", str(driver["sourceRevision"]))
            or any(not IMAGE.fullmatch(str(driver[k])) for k in ("gatewayImage", "supervisorImage"))):
        raise AttestationError("AttestationDriverUnavailable")
    refs = cfg["references"]
    if not isinstance(refs, dict) or set(refs) != {
            "peerPods", "trustee", "trusteeConfig", "attestationPolicy",
            "resourcePolicy", "referenceValues", "qualification"}:
        raise AttestationError("AttestationApprovalMissing")
    paths = {
        "peerPods": r"/api/v1/namespaces/openshift-sandboxed-containers-operator/configmaps/peer-pods-cm",
        "trustee": r"/apis/apps/v1/namespaces/[a-z0-9-]+/deployments/[a-z0-9-]+",
        "trusteeConfig": r"/apis/confidentialcontainers.org/v1alpha1/namespaces/[a-z0-9-]+/kbsconfigs/[a-z0-9-]+",
        "attestationPolicy": r"/api/v1/namespaces/[a-z0-9-]+/configmaps/[a-z0-9-]+",
        "resourcePolicy": r"/api/v1/namespaces/[a-z0-9-]+/configmaps/[a-z0-9-]+",
        "referenceValues": r"/api/v1/namespaces/[a-z0-9-]+/configmaps/[a-z0-9-]+",
        "qualification": r"/api/v1/namespaces/[a-z0-9-]+/configmaps/[a-z0-9-]+",
    }
    for key, ref in refs.items():
        if (not isinstance(ref, dict) or set(ref) != {"path", "uid", "sha256"}
                or not isinstance(ref["path"], str) or not re.fullmatch(paths[key], ref["path"])
                or not SHA.fullmatch(str(ref["sha256"]))):
            raise AttestationError("AttestationApprovalMissing")
        try:
            if str(uuid.UUID(ref["uid"])) != ref["uid"]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise AttestationError("AttestationApprovalMissing") from None
    return cfg

class _NoRedirect(HTTPRedirectHandler):
    """Do not follow redirects when checking the approved KBS endpoint."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_kbs_probe(request, context, timeout):
    opener = build_opener(HTTPSHandler(context=context), _NoRedirect())
    return opener.open(request, timeout=timeout)


def verify_kbs_reachability(site, open_url=None):
    """Check KBS HTTPS reachability without credentials or attestation data."""
    cfg = validate(site)
    if cfg is None:
        return
    request = Request(
        cfg["kbsURL"].rstrip("/") + "/kbs/v0/auth",
        data=b"{}",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    context = ssl.create_default_context(cadata=cfg["kbsCA"])
    opener = open_url or _open_kbs_probe
    try:
        response = opener(request, context, 5)
        try:
            status = getattr(response, "status", None)
        finally:
            response.close()
    except HTTPError as exc:
        status = exc.code
        exc.close()
    except (HTTPException, URLError, TimeoutError, OSError, ssl.SSLError):
        raise AttestationError("TrusteeReachabilityUnavailable") from None
    if status not in {400, 401}:
        raise AttestationError("TrusteeEndpointRejected")
    return True


def verify_platform(site, read, mode="kata"):
    cfg = validate(site, mode)
    if cfg is None:
        return
    observed = {}
    for key, ref in cfg["references"].items():
        try:
            obj = read(ref["path"])
            field = "spec" if key in {"trustee", "trusteeConfig"} else "data"
            meta = obj["metadata"]
            observed_digest = (trustee_config_digest(obj[field]) if key == "trusteeConfig"
                               else digest(obj[field]))
            if (meta.get("deletionTimestamp") or meta["uid"] != ref["uid"]
                    or observed_digest != ref["sha256"]):
                raise AttestationError("AttestationApprovalChanged")
            observed[key] = obj
        except AttestationError:
            raise
        except Exception:
            raise AttestationError("AttestationDependencyUnavailable") from None
    peer = observed["peerPods"]["data"]
    if (peer.get("CLOUD_PROVIDER") != "azure" or peer.get("DISABLECVM") != "false"
            or not peer.get("AZURE_IMAGE_ID")
            or not re.fullmatch(r"Standard_(?:DC|EC)[A-Za-z0-9_]+", peer.get("AZURE_INSTANCE_SIZE", ""))):
        raise AttestationError("ConfidentialRuntimeUnavailable")
    trustee = observed["trustee"]
    status = trustee.get("status", {})
    if (status.get("observedGeneration") != trustee["metadata"].get("generation")
            or status.get("availableReplicas", 0) < 1
            or status.get("updatedReplicas", 0) != trustee["spec"].get("replicas", 1)):
        raise AttestationError("TrusteeUnavailable")
    # This publication is created only after platform/driver qualification.
    # Its UID and complete contents are administrator-approved above.
    qualification = observed["qualification"]["data"]
    expected = {"capability": CAPABILITY, "tee": cfg["tee"],
                "gatewayImage": cfg["driver"]["gatewayImage"],
                "supervisorImage": cfg["driver"]["supervisorImage"],
                "referenceSet": cfg["referenceSet"], "policyDigest": cfg["policyDigest"],
                "imagePolicyDigest": digest(cfg["imagePolicy"]),
                "attestationPolicyDigest": digest(observed["attestationPolicy"]["data"]),
                "resourcePolicyDigest": digest(observed["resourcePolicy"]["data"]),
                "cdhEndpoint": "http://127.0.0.1:8006", "negativeTests": "passed"}
    if any(qualification.get(k) != v for k, v in expected.items()):
        raise AttestationError("AttestationQualificationMissing")
    verify_reference_values(observed["referenceValues"]["data"], cfg["referenceSet"], cfg["tee"])
    return digest(cfg)

def verify_resource_membership(site, owner, registration, read):
    """Require this registration's Secret name in Trustee's mutable resource list."""
    cfg = validate(site)
    if cfg is None:
        return
    ref = cfg["references"]["trusteeConfig"]
    try:
        obj = read(ref["path"])
        spec = obj["spec"]
        if (obj["metadata"].get("deletionTimestamp")
                or obj["metadata"]["uid"] != ref["uid"]
                or trustee_config_digest(spec) != ref["sha256"]):
            raise AttestationError("AttestationApprovalChanged")
        secret_name = resource(owner, registration, "inference").split("/")[1]
        resources = spec.get("kbsSecretResources", [])
        if resources.count(secret_name) != 1:
            raise AttestationError("CredentialResourceUnavailable")
    except AttestationError:
        raise
    except Exception:
        raise AttestationError("AttestationDependencyUnavailable") from None


def verify_resource_secret_ready(site, owner, registration, read):
    """Require the registration's Trustee ExternalSecret to be ready.

    This reads only ExternalSecret metadata and status. It does not read the
    generated Kubernetes Secret or its data.
    """
    cfg = validate(site)
    if cfg is None:
        raise AttestationError("AttestationConfigurationRejected")
    name = resource(owner, registration, "inference").split("/")[1]
    namespace = cfg["references"]["trusteeConfig"]["path"].split("/")[5]
    path = f"/apis/external-secrets.io/v1/namespaces/{namespace}/externalsecrets/{name}"
    try:
        obj = read(path)
        meta = obj["metadata"]
        labels = meta.get("labels", {})
        if (meta.get("name") != name or meta.get("namespace") != namespace
                or meta.get("deletionTimestamp")
                or labels.get("saw.redhat.com/portal-owner") != owner
                or labels.get("saw.redhat.com/registration") != registration
                or obj.get("spec", {}).get("target", {}).get("name") != name):
            raise AttestationError("CredentialResourceUnavailable")
        ready = any(isinstance(condition, dict)
                    and condition.get("type") == "Ready"
                    and condition.get("status") == "True"
                    for condition in obj.get("status", {}).get("conditions", []))
        if not ready:
            raise AttestationError("CredentialResourceUnavailable")
    except AttestationError:
        raise
    except Exception:
        raise AttestationError("AttestationDependencyUnavailable") from None
    return True


def _read_trustee_config_ref(ref, read, approved_sha256=None):
    if (not isinstance(ref, dict) or not re.fullmatch(
            r"/apis/confidentialcontainers.org/v1alpha1/namespaces/[a-z0-9-]+/kbsconfigs/[a-z0-9-]+",
            str(ref.get("path", ""))) or not SHA.fullmatch(str(ref.get("sha256", "")))):
        raise AttestationError("TrusteeConfigurationRejected")
    try:
        if str(uuid.UUID(ref.get("uid", ""))) != ref["uid"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise AttestationError("TrusteeConfigurationRejected") from None
    try:
        obj = read(ref["path"])
        spec = obj["spec"]
        resources = spec.get("kbsSecretResources", [])
        if (obj["metadata"].get("deletionTimestamp")
                or obj["metadata"]["uid"] != ref["uid"]
                or not isinstance(resources, list)
                or any(not isinstance(item, str) for item in resources)
                or (approved_sha256 is not None
                    and trustee_config_digest(spec) != approved_sha256)):
            raise AttestationError("TrusteeConfigurationRejected")
        version = obj["metadata"].get("resourceVersion")
        if not isinstance(version, str) or not version:
            raise AttestationError("TrusteeConfigurationRejected")
        return ref["path"], version, spec
    except AttestationError:
        raise
    except Exception:
        raise AttestationError("AttestationDependencyUnavailable") from None


def _read_trustee_config(site, read):
    cfg = validate(site)
    if cfg is None:
        raise AttestationError("AttestationConfigurationRejected")
    ref = cfg["references"]["trusteeConfig"]
    try:
        return _read_trustee_config_ref(ref, read, ref["sha256"])
    except AttestationError:
        raise
    except Exception:
        raise AttestationError("AttestationDependencyUnavailable") from None


def _change_resource_membership(site, owner, registration, read, patch, add):
    """Update one KbsConfig resource name with an optimistic resourceVersion.

    The patch replaces only the membership list. It preserves every other
    Trustee resource and retries if another writer changes KbsConfig first.
    """
    name = resource(owner, registration, "inference").split("/")[1]
    for _ in range(3):
        if add:
            path, version, spec = _read_trustee_config(site, read)
        else:
            ref = validate(site)["references"]["trusteeConfig"]
            path, version, spec = _read_trustee_config_ref(ref, read)
        resources = spec.get("kbsSecretResources", [])
        count = resources.count(name)
        if count > 1:
            raise AttestationError("TrusteeConfigurationRejected")
        if add and count == 1:
            return False
        if not add and count == 0:
            return False
        updated = list(resources)
        if add:
            updated.append(name)
        else:
            updated.remove(name)
        body = {"metadata": {"resourceVersion": version},
                "spec": {"kbsSecretResources": updated}}
        try:
            patch(path, body)
        except HTTPError as exc:
            if exc.code == 409:
                continue
            raise AttestationError("AttestationDependencyUnavailable") from None
        except Exception:
            raise AttestationError("AttestationDependencyUnavailable") from None
        if add:
            _, _, current = _read_trustee_config(site, read)
        else:
            _, _, current = _read_trustee_config_ref(ref, read)
        current_resources = current.get("kbsSecretResources", [])
        if (current_resources.count(name) == (1 if add else 0)
                and trustee_config_digest(current) == site["attestation"]["references"]["trusteeConfig"]["sha256"]):
            return True
        raise AttestationError("TrusteeConfigurationRejected")
    raise AttestationError("TrusteeConfigurationConflict")


def ensure_resource_membership(site, owner, registration, read, patch):
    """Register this owner's shared Trustee Secret name in KbsConfig."""
    return _change_resource_membership(site, owner, registration, read, patch, True)


def revoke_resource_membership(site, owner, registration, read, patch):
    """Remove this owner's shared Trustee Secret name from KbsConfig."""
    return _change_resource_membership(site, owner, registration, read, patch, False)


def revoke_trustee_resource_membership(ref, owner, registration, read, patch):
    """Revoke a registration using its stored KbsConfig identity.

    Cleanup checks the approved API path and object UID, then patches only the
    resource-name list. It remains possible after an administrator changes
    the KbsConfig spec hash; the operation cannot add names or change policy.
    """
    name = resource(owner, registration, "inference").split("/")[1]
    for _ in range(3):
        path, version, spec = _read_trustee_config_ref(ref, read)
        resources = spec.get("kbsSecretResources", [])
        count = resources.count(name)
        if count > 1:
            raise AttestationError("TrusteeConfigurationRejected")
        if count == 0:
            return False
        updated = list(resources)
        updated.remove(name)
        body = {"metadata": {"resourceVersion": version},
                "spec": {"kbsSecretResources": updated}}
        try:
            patch(path, body)
        except HTTPError as exc:
            if exc.code == 409:
                continue
            raise AttestationError("AttestationDependencyUnavailable") from None
        except Exception:
            raise AttestationError("AttestationDependencyUnavailable") from None
        _, _, current = _read_trustee_config_ref(ref, read)
        current_resources = current.get("kbsSecretResources", [])
        if current_resources.count(name) == 0:
            return True
        raise AttestationError("TrusteeConfigurationRejected")
    raise AttestationError("TrusteeConfigurationConflict")


def resource(owner, registration, credential):
    if (not isinstance(owner, str) or len(owner)>19 or not LABEL.fullmatch(owner)
            or not re.fullmatch(r"[a-f0-9]{16}", str(registration))
            or not isinstance(credential, str) or len(credential)>63 or not LABEL.fullmatch(credential)):
        raise AttestationError("CredentialResourceRejected")
    return f"default/saw-{owner}-{registration}/{credential}"


def approved_credential_references(site, owner, profile, secret_names, kv_mount, prefix_base):
    """Resolve the owner's approved KV v2 paths for one confidential profile.

    The site configuration owns these references. A request can select a
    profile but cannot supply or change a Vault path.
    """
    if (not isinstance(site, dict) or not isinstance(profile, str)
            or not isinstance(secret_names, (list, tuple, set)) or not secret_names):
        raise AttestationError("CredentialReferenceRejected")
    try:
        resource(owner, "0123456789abcdef", "inference")
    except AttestationError:
        raise AttestationError("CredentialReferenceRejected") from None
    if (not isinstance(kv_mount, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", kv_mount)
            or not isinstance(prefix_base, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", prefix_base)):
        raise AttestationError("CredentialReferenceRejected")
    expected = set(secret_names)
    if (any(not isinstance(name, str) or not LABEL.fullmatch(name) for name in expected)
            or len(expected) != len(secret_names)):
        raise AttestationError("CredentialReferenceRejected")
    all_refs = site.get("credentialReferences")
    refs = all_refs.get(profile) if isinstance(all_refs, dict) else None
    if not isinstance(refs, dict) or set(refs) != expected:
        raise AttestationError("CredentialReferenceRejected")
    root = f"{kv_mount}/data/{prefix_base}/saw-{owner}/"
    result = {}
    for name in sorted(expected):
        path = refs[name]
        if (not isinstance(path, str) or not path.startswith(root)
                or not re.fullmatch(r"(?:[A-Za-z0-9_-]+/)*" + re.escape(name), path[len(root):])):
            raise AttestationError("CredentialReferenceRejected")
        result[name] = path
    if len(set(result.values())) != len(result):
        raise AttestationError("CredentialReferenceRejected")
    return result

def initdata(site, owner, registration, installation, slot, role):
    cfg = validate(site)
    if cfg is None or role not in {"supervisor", "workload"}:
        raise AttestationError("AttestationConfigurationRejected")
    resource(owner, registration, "inference")
    try:
        if str(uuid.UUID(installation)) != installation:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise AttestationError("AttestationIdentityRejected") from None
    if not re.fullmatch(r"[a-z0-9-]+/[a-z0-9-]+", str(slot)):
        raise AttestationError("AttestationIdentityRejected")
    identity = dict(owner=owner, registration=registration, installation=installation, slot=slot, role=role)
    # Trustee parses Kata's policy_data from verified init-data and includes it
    # in the attestation claims. A comment or extra init-data key is not a claim.
    policy = IDENTITY_MEMBER.sub(
        '"saw_identity": ' + canonical(identity), cfg["guestPolicy"], count=1)
    aa = ("[token_configs]\n"
          "[token_configs.coco_as]\nurl = "+json.dumps(cfg["kbsURL"])+"\n"
          "[token_configs.kbs]\nurl = "+json.dumps(cfg["kbsURL"])+"\n")
    cdh = ("socket = \"unix:///run/confidential-containers/cdh.sock\"\ncredentials = []\n[kbc]\nname = \"cc_kbc\"\nurl = "
           +json.dumps(cfg["kbsURL"])+"\nkbs_cert = "+json.dumps(cfg["kbsCA"])
           +"\n[image]\nimage_security_policy_uri = "
           +json.dumps("kbs:///"+resource(owner, registration, "image-policy"))+"\n")
    values = {"aa.toml": aa, "cdh.toml": cdh, "policy.rego": policy}
    # Format follows OSC initdata: only supported guest component keys.
    text = 'version = "0.1.0"\nalgorithm = "sha256"\n[data]\n'
    text += "".join(json.dumps(k)+" = "+json.dumps(v, ensure_ascii=True)+"\n" for k,v in sorted(values.items()))
    raw = text.encode()
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=0) as stream:
        stream.write(raw)
    return {"identity": identity, "annotation": base64.b64encode(compressed.getvalue()).decode(),
            "sha256": hashlib.sha256(raw).hexdigest(), "boundarySHA256": digest(cfg)}


def placement_contract(site, owner, registration, installation, slots, runtime_class):
    """Bind per-slot supervisor and workload init-data into a compiled plan."""
    cfg = validate(site)
    if (cfg is None or not isinstance(runtime_class, str) or len(runtime_class) > 63
            or not LABEL.fullmatch(runtime_class) or not isinstance(slots, list)
            or not slots or any(not isinstance(slot, str) for slot in slots)
            or len(slots) != len(set(slots))):
        raise AttestationError("AttestationConfigurationRejected")
    resource(owner, registration, "inference")
    placements = {}
    for slot in sorted(slots):
        roles = {}
        for role in ("supervisor", "workload"):
            generated = initdata(site, owner, registration, installation, slot, role)
            roles[role] = {
                "runtime_class_name": runtime_class,
                "init_data": generated["annotation"],
                "init_data_sha256": generated["sha256"],
                "identity": generated["identity"],
            }
        placements[slot] = roles
    return {
        "settings_sha256": digest(cfg),
        "policy_digest": cfg["policyDigest"],
        "reference_set": cfg["referenceSet"],
        "identity": {"owner": owner, "registration": registration,
                     "installation": installation},
        "placements": placements,
    }


def trustee_resources(site, owner, registration, policy, secret_store):
    """Render a Trustee-only ESO bridge containing approved Vault references."""
    cfg = validate(site)
    resource(owner, registration, "inference")
    if (cfg is None or not isinstance(secret_store, str) or not LABEL.fullmatch(secret_store)
            or not isinstance(policy, dict) or not isinstance(policy.get("bindings"), list)
            or not policy["bindings"]):
        raise AttestationError("CredentialResourceRejected")
    namespace = cfg["references"]["trusteeConfig"]["path"].split("/")[5]
    refs = site.get("credentialReferences")
    if not isinstance(refs, dict):
        raise AttestationError("CredentialReferenceRejected")
    fields = {}
    for binding in policy["bindings"]:
        if not isinstance(binding, dict) or binding.get("refresh"):
            raise AttestationError("CredentialRefreshUnsupported")
        credential, key = binding.get("secret"), binding.get("key")
        resource(owner, registration, credential)
        if credential == "image-policy" or not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", key):
            raise AttestationError("CredentialResourceRejected")
        source = refs.get(credential)
        if not isinstance(source, str):
            raise AttestationError("CredentialReferenceRejected")
        prefix = re.match(r"^([A-Za-z0-9_-]+/data/(?:[A-Za-z0-9_-]+/)*)saw-" + re.escape(owner) + r"/", source)
        if (not prefix
                or not re.fullmatch(r"(?:[A-Za-z0-9_-]+/)*" + re.escape(credential), source[prefix.end():])):
            raise AttestationError("CredentialReferenceRejected")
        fields.setdefault(credential, set()).add(key)
    if set(refs) != set(fields) or len(set(refs.values())) != len(refs):
        raise AttestationError("CredentialReferenceRejected")
    data, templates = [], {"image-policy": canonical(cfg["imagePolicy"])}
    for credential, keys in sorted(fields.items()):
        pairs = []
        for key in sorted(keys):
            alias = "field"+str(len(data))
            data.append({"secretKey": alias, "remoteRef": {"key": refs[credential], "property": key}})
            pairs.extend([json.dumps(key), "."+alias])
        templates[credential] = "{{ dict "+" ".join(pairs)+" | toJson }}"
    name = "saw-"+owner+"-"+registration
    return {"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret",
            "metadata": {"name": name, "namespace": namespace,
                         "labels": {"saw.redhat.com/portal-owner": owner,
                                    "saw.redhat.com/registration": registration}},
            "spec": {"refreshInterval": "1m", "secretStoreRef": {"kind": "ClusterSecretStore", "name": secret_store},
                     "target": {"name": name, "creationPolicy": "Owner", "template": {
                         "engineVersion": "v2", "data": templates}}, "data": data}}
