"""Public confidential-workspace contract and Trustee registration helpers."""
import base64
import copy
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
    version = cfg.get("schemaVersion")
    required = {"enabled", "schemaVersion", "tee", "kbsURL", "kbsCA", "policyDigest",
                "referenceSet", "imagePolicy", "driver", "references"}
    required.add("launchPolicies" if version == 2 else "guestPolicy")
    if (set(cfg) != required or mode != "kata" or type(version) is not int
            or version not in (1, 2) or cfg["tee"] not in ("snp", "tdx")):
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
    if not SHA.fullmatch(str(cfg["policyDigest"])) or not SHA.fullmatch(str(cfg["referenceSet"])):
        raise AttestationError("AttestationPolicyRejected")
    if version == 1:
        policy = cfg["guestPolicy"]
        if (not isinstance(policy, str) or len(policy.encode()) > 512*1024
                or hashlib.sha256(policy.encode()).hexdigest() != cfg["policyDigest"]):
            raise AttestationError("AttestationPolicyRejected")
        if (len(POLICY_DATA.findall(policy)) != 1 or len(IDENTITY_MEMBER.findall(policy)) != 1
                or policy.count(IDENTITY_MARKER) != 1):
            raise AttestationError("AttestationIdentityClaimUnavailable")
        if policy != KATA_AGENT_POLICY_TEMPLATE:
            raise AttestationError("AttestationPolicyRejected")
    else:
        validate_launch_policies(cfg["launchPolicies"], cfg["policyDigest"])
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
    if cfg["schemaVersion"] == 2:
        try:
            entry = cfg["launchPolicies"][slot][role]
            pod = entry["pod"]
            if pod["metadata"]["namespace"] != "saw-" + owner:
                raise ValueError()
            if role == "supervisor":
                container = pod["spec"]["containers"][0]
                if (len(pod["spec"]["containers"]) != 1 or container["name"] != "supervisor"
                        or container["image"] != cfg["driver"]["supervisorImage"]):
                    raise ValueError()
                raw = next(e["value"] for e in container["env"] if e["name"] == BOOTSTRAP_ENV)
                public = json.loads(raw)
                if supervisor_bootstrap(public["policy"], owner, registration) != raw:
                    raise ValueError()
            policy = entry["template"].replace(IDENTITY_MARKER, canonical(identity))
        except (KeyError, TypeError, ValueError, StopIteration, IndexError):
            raise AttestationError("AttestationLaunchBindingRejected") from None
    else:
        # The identity is measured, but this Trustee build exposes only PCR08.
        # Resource policy must bind that verified measurement to this identity.
        policy = IDENTITY_MEMBER.sub(
            '\"saw_identity\": ' + canonical(identity), cfg["guestPolicy"], count=1)
    aa = ("[token_configs]\n"
          "[token_configs.coco_as]\nurl = "+json.dumps(cfg["kbsURL"])+"\n"
          "[token_configs.kbs]\nurl = "+json.dumps(cfg["kbsURL"])
          +"\ncert = "+json.dumps(cfg["kbsCA"])+"\n")
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
    if cfg["schemaVersion"] == 2:
        if set(cfg["launchPolicies"]) != set(slots):
            raise AttestationError("AttestationLaunchBindingRejected")
        if any(entry["pod"]["spec"].get("runtimeClassName") != runtime_class
               for roles in cfg["launchPolicies"].values() for entry in roles.values()):
            raise AttestationError("AttestationLaunchBindingRejected")
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


def launch_policy_input(pod):
    """Adapt a nonroot Pod to the pinned generator without ignoring fields.

    The returned document is generator input only. Deploy the original Pod.
    Keep unknown fields so genpolicy rejects unsupported security settings.
    """
    try:
        if not isinstance(pod, dict) or pod.get("apiVersion") != "v1" or pod.get("kind") != "Pod":
            raise ValueError()
        result = copy.deepcopy(pod)
        metadata = result.get("metadata", {})
        # API ownership is not a guest OCI field. Preserve it in the enrolled
        # original and remove only the exact driver shape from generator input.
        if "ownerReferences" in metadata:
            owners = metadata["ownerReferences"]
            if (not isinstance(owners, list) or len(owners) != 1
                    or not isinstance(owners[0], dict)
                    or set(owners[0]) != {"apiVersion", "kind", "name", "uid", "controller", "blockOwnerDeletion"}
                    or owners[0]["kind"] != "Sandbox"
                    or owners[0]["controller"] is not True or owners[0]["blockOwnerDeletion"] is not True
                    or any(not isinstance(owners[0][key], str) or not owners[0][key]
                           for key in ("apiVersion", "name", "uid"))):
                raise ValueError()
            del metadata["ownerReferences"]
        spec = result["spec"]
        # The driver removes this API scheduling gate before guest startup.
        if "schedulingGates" in spec:
            if spec["schedulingGates"] != [{"name": "openshell.ai/bootstrap"}]:
                raise ValueError()
            del spec["schedulingGates"]
        if (spec.get("automountServiceAccountToken") is not False
                or any(spec.get(k) for k in ("hostPID", "hostIPC", "hostNetwork", "ephemeralContainers"))):
            raise ValueError()
        del spec["automountServiceAccountToken"]
        pod_security = spec.get("securityContext", {})
        if not isinstance(pod_security, dict) or not isinstance(spec.get("containers"), list) or not spec["containers"]:
            raise ValueError()
        if "fsGroupChangePolicy" in pod_security:
            if pod_security["fsGroupChangePolicy"] != "OnRootMismatch":
                raise ValueError()
            # Keep numeric fsGroup so generated AdditionalGids stay constrained.
            del pod_security["fsGroupChangePolicy"]
        inherited_seccomp = pod_security.pop("seccompProfile", None)
        inherited_nonroot = pod_security.pop("runAsNonRoot", None)
        for group in ("containers", "initContainers"):
            containers = spec.get(group, [])
            if not isinstance(containers, list):
                raise ValueError()
            for container in containers:
                security = container.setdefault("securityContext", {})
                uid = security.get("runAsUser", pod_security.get("runAsUser"))
                nonroot = security.pop("runAsNonRoot", inherited_nonroot)
                if (type(uid) is not int or uid <= 0 or nonroot is not True
                        or security.get("privileged", False) is not False):
                    raise ValueError()
                seccomp = security.get("seccompProfile", inherited_seccomp)
                if seccomp != {"type": "RuntimeDefault"}:
                    raise ValueError()
                security["seccompProfile"] = copy.deepcopy(seccomp)
                if any("secretKeyRef" in env.get("valueFrom", {}) for env in container.get("env", [])):
                    raise ValueError()
                if container.get("envFrom"):
                    raise ValueError()
        for volume in spec.get("volumes", []):
            if "projected" not in volume:
                continue
            projection = volume["projected"]
            if (set(volume) != {"name", "projected"} or volume["name"] != "sa-token"
                    or not isinstance(projection, dict) or set(projection) != {"defaultMode", "sources"}
                    or projection["defaultMode"] != 0o440 or type(projection["defaultMode"]) is not int
                    or not isinstance(projection["sources"], list) or len(projection["sources"]) != 1
                    or set(projection["sources"][0]) != {"serviceAccountToken"}):
                raise ValueError()
            token = projection["sources"][0]["serviceAccountToken"]
            if (not isinstance(token, dict) or set(token) != {"audience", "expirationSeconds", "path"}
                    or token["audience"] != "openshell-gateway" or token["path"] != "token"
                    or type(token["expirationSeconds"]) is not int or not 1 <= token["expirationSeconds"] <= 3600):
                raise ValueError()
            mounts = [(container["name"], mount) for container in spec["containers"]
                      + spec.get("initContainers", []) for mount in container.get("volumeMounts", [])
                      if mount.get("name") == "sa-token"]
            if mounts != [("supervisor", {"name": "sa-token", "mountPath": "/var/run/secrets/openshell", "readOnly": True})]:
                raise ValueError()
            # The locked generator uses only the projected-volume type to
            # constrain a read-only shared mount. Its parser lacks sources.
            # Keep the full token projection in the original enrolled Pod.
            del projection["sources"]
        if not pod_security:
            spec.pop("securityContext", None)
        return result
    except (ValueError, TypeError, KeyError, AttributeError):
        raise AttestationError("LaunchPolicyInputRejected") from None


# OSC 1.13 release rules; digest covers the exact code with trailing whitespace
# removed. Generated policy data remains administrator-reviewed public input.
GENPOLICY_RULES_SHA256 = "2655cbb7641829dd88e0647cac76407a6072cdd130c77fda436fa9af08f4b43e"
GENPOLICY_ENV_RULES_SHA256 = '2fd6b64642343ce37b71dc6f88377b70e8b2b1b35357fc7c4526b0e046e10240'
BOOTSTRAP_ENV = "SAW_CONFIDENTIAL_BOOTSTRAP_JSON"


# Runtime IDs do not grant Trustee access. Resource release uses the enrolled
# registration measurement. These patterns permit only the driver's UUIDv4.
RUNTIME_UUID_V4 = r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"
RUNTIME_ID_ENV = "OPENSHELL_SANDBOX_ID"
RUNTIME_ID_RULE = "^" + RUNTIME_ID_ENV + "=" + RUNTIME_UUID_V4 + "$"


def _supervisor_runtime_identity(pod, data, *, restore=False):
    containers = pod["spec"]["containers"]
    supervisors = [c for c in containers if c["name"] == "supervisor"]
    if not supervisors:
        return
    entries = [e for e in supervisors[0].get("env", []) if e["name"] == RUNTIME_ID_ENV]
    if not entries:
        return
    if len(supervisors) != 1 or len(entries) != 1:
        raise ValueError()
    runtime_id = entries[0].get("value")
    if (not isinstance(runtime_id, str) or not re.fullmatch(RUNTIME_UUID_V4, runtime_id)
            or pod["metadata"]["name"] != "os-supervisor-" + runtime_id):
        raise ValueError()
    original_annotations = {
        "io.kubernetes.cri.sandbox-name": "^os-supervisor-" + runtime_id + "$",
        "openshell.ai/sandbox-id": runtime_id,
    }
    measured_annotations = {
        "io.kubernetes.cri.sandbox-name": "^os-supervisor-" + RUNTIME_UUID_V4 + "$",
        "openshell.ai/sandbox-id": "^" + RUNTIME_UUID_V4 + "$",
    }
    rules = data["request_defaults"]["CreateContainerRequest"]["allow_env_regex"]
    if restore:
        if not rules or rules[-1] != RUNTIME_ID_RULE or rules.count(RUNTIME_ID_RULE) != 1:
            raise ValueError()
        rules.pop()
    else:
        rules.append(RUNTIME_ID_RULE)
    found = 0
    for container in data["containers"]:
        annotations = container["OCI"]["Annotations"]
        for key, original in original_annotations.items():
            if annotations.get(key) != (measured_annotations[key] if restore else original):
                raise ValueError()
            annotations[key] = original if restore else measured_annotations[key]
        if annotations.get("io.kubernetes.cri.container-name") != "supervisor":
            continue
        found += 1
        environment = container["OCI"]["Process"]["Env"]
        original = RUNTIME_ID_ENV + "=" + runtime_id
        if restore:
            index = data.pop("saw_runtime_id_env_index")
            if type(index) is not int or not 0 <= index <= len(environment):
                raise ValueError()
            if any(e.startswith(RUNTIME_ID_ENV + "=") for e in environment):
                raise ValueError()
            environment.insert(index, original)
        else:
            matches = [i for i, e in enumerate(environment) if e.startswith(RUNTIME_ID_ENV + "=")]
            if len(matches) != 1 or environment[matches[0]] != original or "saw_runtime_id_env_index" in data:
                raise ValueError()
            data["saw_runtime_id_env_index"] = matches[0]
            environment.pop(matches[0])
    if found != 1:
        raise ValueError()


def compile_launch_policy(pod, generated):
    """Create an identity-bearing template from reviewed rules and Pod output.

    This does not qualify a driver, approve resource release, or enable enrollment.
    The generator must still run without unsupported-field suppression.
    """
    normalized = launch_policy_input(pod)
    try:
        if not isinstance(generated, str) or len(generated.encode()) > 512 * 1024:
            raise ValueError()
        matches = list(POLICY_DATA.finditer(generated))
        if len(matches) != 1 or IDENTITY_MARKER in generated:
            raise ValueError()
        match = matches[0]
        prefix = generated[:match.start()].rstrip()
        if hashlib.sha256(prefix.encode()).hexdigest() != GENPOLICY_RULES_SHA256:
            raise ValueError()
        # POLICY_DATA includes the opening brace. Decode one JSON object only;
        # trailing Rego rules or hand-written expressions are rejected.
        data = json.loads(generated[match.end()-1:])
        defaults = data["request_defaults"]
        if (digest(defaults["CreateContainerRequest"]["allow_env_regex"]) != GENPOLICY_ENV_RULES_SHA256
                or defaults["ExecProcessRequest"] != {"allowed_commands": [], "regex": []}
                or any(defaults[key] is not False for key in
                       ("ReadStreamRequest", "WriteStreamRequest", "GetDiagnosticDataRequest"))):
            raise ValueError()
        containers = data["containers"]
        actual, pauses = {}, []
        for container in containers:
            oci = container["OCI"]
            annotations = oci["Annotations"]
            if annotations["io.kubernetes.cri.container-type"] == "sandbox":
                pauses.append(oci)
            else:
                name = annotations["io.kubernetes.cri.container-name"]
                if name in actual:
                    raise ValueError()
                actual[name] = oci
        if len(pauses) != 1 or pauses[0]["Process"]["Args"] != ["/pause"]:
            raise ValueError()
        spec = normalized["spec"]
        expected = spec["containers"] + spec.get("initContainers", [])
        if len(expected) != len(actual) or len({c["name"] for c in expected}) != len(expected):
            raise ValueError()
        for container in expected:
            oci = actual[container["name"]]
            process = oci["Process"]
            security = container["securityContext"]
            if container["name"] == "supervisor":
                entries = [entry for entry in container.get("env", []) if entry.get("name") == BOOTSTRAP_ENV]
                if (len(entries) != 1 or not isinstance(entries[0].get("value"), str)
                        or any(entry.get("name") == "SAW_CONFIDENTIAL_CONFIG" for entry in container.get("env", []))):
                    raise ValueError()
                raw = entries[0]["value"]
                public = json.loads(raw)
                if (not isinstance(public, dict) or set(public) != {"schemaVersion", "policy", "resources", "publicCAFile"}
                        or type(public["schemaVersion"]) is not int or public["schemaVersion"] != 1 or canonical(public) != raw or len(raw.encode()) > 64*1024
                        or public["publicCAFile"] != "/run/openshell/saw-proxy-ca.pem"):
                    raise ValueError()
                measured = [entry for entry in process["Env"] if entry.startswith(BOOTSTRAP_ENV + "=")]
                if measured != [BOOTSTRAP_ENV + "=" + raw]:
                    raise ValueError()
            uid = security.get("runAsUser", spec.get("securityContext", {}).get("runAsUser"))
            image = container["image"]
            command = container.get("command")
            if (not IMAGE.fullmatch(image) or not isinstance(command, list) or not command
                    or any("$(node-name)" in arg for arg in command + container.get("args", []))
                    or process["Args"] != command + container.get("args", [])
                    or process["User"]["UID"] != uid
                    or process["NoNewPrivileges"] is not True
                    or oci["Root"]["Readonly"] != security.get("readOnlyRootFilesystem", False)
                    or oci["Annotations"]["io.kubernetes.cri.image-name"] != image
                    or oci["Annotations"]["io.kubernetes.cri.sandbox-namespace"] != pod["metadata"]["namespace"]):
                raise ValueError()
        if "saw_identity" in data or "saw_runtime_id_env_index" in data:
            raise ValueError()
        _supervisor_runtime_identity(pod, data)
        data["saw_identity"] = IDENTITY_MARKER
        encoded = canonical(data)
        if encoded.count(json.dumps(IDENTITY_MARKER)) != 1:
            raise ValueError()
        encoded = encoded.replace(json.dumps(IDENTITY_MARKER), IDENTITY_MARKER)
        return prefix + "\n\npolicy_data := " + encoded + "\n"
    except (ValueError, TypeError, KeyError, AttributeError):
        raise AttestationError("LaunchPolicyRejected") from None


def supervisor_bootstrap(policy, owner, registration):
    """Canonical public supervisor configuration; never provider material."""
    try:
        if (not isinstance(policy, dict) or set(policy) != {"markerPrefix", "allowHosts", "profiles", "bindings"}
                or not isinstance(policy["bindings"], list) or not policy["bindings"]):
            raise ValueError()
        resources = {}
        for binding in policy["bindings"]:
            if (not isinstance(binding, dict) or set(binding) != {"secret", "key", "providers"}
                    or not isinstance(binding["key"], str) or not binding["key"]):
                raise ValueError()
            name = binding["secret"]
            resources[name] = resource(owner, registration, name)
        result = canonical({"schemaVersion": 1, "policy": policy, "resources": resources,
                            "publicCAFile": "/run/openshell/saw-proxy-ca.pem"})
        if len(result.encode()) > 64 * 1024:
            raise ValueError()
        return result
    except (ValueError, TypeError, KeyError, AttributeError):
        raise AttestationError("AttestationBootstrapRejected") from None


def validate_launch_policies(policies, expected_digest):
    """Validate a complete, administrator-reviewed launch bundle without I/O.

    A bundle alone does not qualify the platform or enable enrollment.
    Its digest includes both original Pod manifests and generated templates.
    """
    try:
        if (not isinstance(policies, dict) or not policies or len(policies) > 16
                or len(canonical(policies).encode()) > 768 * 1024
                or digest(policies) != expected_digest):
            raise ValueError()
        for slot, roles in policies.items():
            if (not re.fullmatch(r"[a-z0-9-]+/[a-z0-9-]+", slot)
                    or not isinstance(roles, dict) or set(roles) != {"supervisor", "workload"}):
                raise ValueError()
            for role, entry in roles.items():
                if not isinstance(entry, dict) or set(entry) != {"pod", "template"}:
                    raise ValueError()
                pod_spec = entry["pod"]["spec"]
                if role == "supervisor":
                    containers = pod_spec["containers"]
                    if (len(containers) != 1 or containers[0]["name"] != "supervisor"
                            or pod_spec.get("initContainers")):
                        raise ValueError()
                    command = containers[0].get("command", []) + containers[0].get("args", [])
                    if command[:3] != ["/usr/local/bin/saw-credential-proxy", "supervise", "/openshell-supervisor"]:
                        raise ValueError()
                    for flag, value in (("--upstream-proxy", "http://127.0.0.1:3128"),
                                        ("--upstream-proxy-ca-bundle", "/run/openshell/saw-proxy-ca.pem")):
                        if command.count(flag) != 1 or command[command.index(flag)+1] != value:
                            raise ValueError()
                    allowed = {"--upstream-proxy", "--upstream-proxy-ca-bundle", "--upstream-proxy-connect-by-hostname"}
                    if any(arg.startswith("--upstream-") and arg not in allowed for arg in command):
                        raise ValueError()
                template = entry["template"]
                if not isinstance(template, str) or template.count(IDENTITY_MARKER) != 1:
                    raise ValueError()
                match, = list(POLICY_DATA.finditer(template))
                data = json.loads(template[match.end()-1:].replace(IDENTITY_MARKER, "null"))
                if "saw_identity" not in data or data.pop("saw_identity") is not None:
                    raise ValueError()
                _supervisor_runtime_identity(entry["pod"], data, restore=True)
                generated = template[:match.start()] + "policy_data := " + canonical(data) + "\n"
                if compile_launch_policy(entry["pod"], generated) != template:
                    raise ValueError()
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, AttestationError):
        raise AttestationError("AttestationLaunchPolicyRejected") from None
    return expected_digest
