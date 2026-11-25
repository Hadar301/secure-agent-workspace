"""Provider helpers for configuring the agent.

OpenShell owns provider security: profiles decide which endpoints a credential
may reach, and the supervisor substitutes the real value only for those. This
module tells the agent which environment variable holds its inference key,
checks the site's custom inference URL, and names the endpoints each
credentialed provider's profile must list (approved_endpoints), which the
reconciler compares with the live profile; for a shipped profile it also
compares every endpoint's path, protocol, access and rules
(approved_endpoint_specs).
"""
import json
import re
import ipaddress
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .core import shared

PROFILES = Path(shared.__file__).resolve().parents[1] / "provider-profiles"
INFERENCE = {"openai", "anthropic", "nvidia"}


@lru_cache(maxsize=4)
def _shipped(kind):
    return yaml.safe_load((PROFILES / (kind + ".yaml")).read_text())


def custom_host(url):
    """Custom inference must be an HTTPS v1 endpoint on port 443 with a DNS name."""
    if not isinstance(url, str) or shared.check_base_url(url) != url:
        raise ValueError("invalid custom inference base URL")
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("custom inference requires a DNS hostname")
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if (parsed.scheme != "https" or parsed.port not in (None, 443)
            or len(hostname) > 253 or not re.fullmatch(rf"{label}(?:\.{label})+", hostname)
            or not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*/v1", parsed.path)):
        raise ValueError("custom inference requires an approved HTTPS v1 endpoint on port 443")
    return parsed.hostname


def inference_key_env(kind):
    """The env var the agent reads its inference key from (an OpenShell placeholder)."""
    if kind == "custom-inference":
        return "CUSTOM_INFERENCE_API_KEY"
    if kind not in INFERENCE:
        raise ValueError("not an inference provider")
    slot, = _shipped(kind)["credentials"]
    return slot["env_vars"][0]


# The profile YAML's access preset as the gateway returns it (NetworkAccessPreset).
ACCESS = {"": "", "read-only": "NETWORK_ACCESS_PRESET_READ_ONLY",
          "read-write": "NETWORK_ACCESS_PRESET_READ_WRITE", "full": "NETWORK_ACCESS_PRESET_FULL"}


def _pruned(value):
    """Drop default (empty) values, as protobuf JSON omits them."""
    if isinstance(value, dict):
        kept = {key: _pruned(item) for key, item in value.items()}
        return {key: item for key, item in kept.items() if item not in (None, "", [], {}, 0, False)}
    if isinstance(value, list):
        return [_pruned(item) for item in value]
    return value


def endpoint_spec(endpoint, *, shipped):
    """Everything that decides where and how a credential may be used on one
    endpoint: host, ports, path, protocol, access preset and L7 rules. A
    shipped profile is YAML; a live one is the gateway's NetworkEndpoint JSON."""
    access = endpoint.get("access") or ""
    if shipped:
        if access not in ACCESS:
            raise ValueError("unknown access preset in a shipped profile")
        access = ACCESS[access]
    elif access == "NETWORK_ACCESS_PRESET_UNSPECIFIED":
        access = ""
    ports = endpoint.get("ports") or [endpoint.get("port") or 443]
    rules = lambda key: tuple(sorted(json.dumps(_pruned(rule), sort_keys=True)
                                     for rule in endpoint.get(key) or []))
    return (str(endpoint.get("host", "")).lower(), tuple(sorted(int(port) for port in ports)),
            endpoint.get("path") or "", str(endpoint.get("protocol") or "").lower(), access,
            rules("rules"), rules("deny_rules"))


def approved_endpoint_specs(kind):
    """The shipped governed profile's endpoints, one entry each (never merged
    by host and port), or None for custom inference, whose profile is the
    site's own and is checked by host only."""
    if kind == "custom-inference":
        return None
    path = PROFILES / (kind + ".yaml")
    if not re.fullmatch(r"[a-z0-9-]+", kind or "") or not path.is_file():
        raise ValueError("no governed profile ships for this provider type")
    return sorted(endpoint_spec(e, shipped=True) for e in _shipped(kind).get("endpoints", []))


def approved_endpoints(kind, custom_url=None):
    """The (host, port) pairs a credentialed provider's key may be sent to.

    Stock providers: the governed profile shipped with this runtime (the same
    files as the governance policy). Custom inference: only the site's
    approved URL host, so one workspace's key never reaches another's server.
    """
    if kind == "custom-inference":
        return {(custom_host(custom_url), 443)}
    path = PROFILES / (kind + ".yaml")
    if not re.fullmatch(r"[a-z0-9-]+", kind or "") or not path.is_file():
        raise ValueError("no governed profile ships for this provider type")
    return {(e["host"], int(e.get("port", 443))) for e in _shipped(kind).get("endpoints", [])}


def document(kind):
    if kind not in {"openai", "anthropic", "nvidia", "slack", "gmail", "brave"}:
        raise ValueError("unsupported governed provider")
    return _shipped(kind)


def requirements(kind, custom_url=None):
    if kind == "custom-inference" and custom_url:
        return {"name":"api_key", "env_vars":["CUSTOM_INFERENCE_API_KEY"]}, [custom_host(custom_url)]
    doc = document(kind)
    slot, = doc["credentials"]
    hosts = sorted({e["host"] for e in doc["endpoints"]})
    return slot, hosts


def checked_marker(provider, bindings, custom_url=None):
    """The plan carries only the public routing marker; keys remain in the proxy."""
    slot, _ = requirements(provider.type, custom_url)
    expected = {"secret": provider.credential_secret, "key": provider.credential_secret_key,
                "type": provider.type, "refresh": bool(provider.refresh_strategy)}
    if (expected not in bindings or provider.credentials_spec or provider.base_url or provider.base_url_secret_key
            or provider.refresh_strategy not in ("", "oauth2_refresh_token") or provider.inference_timeout
            or (provider.type != "nvidia" and (provider.model or provider.nemoclaw_provider))
            or provider.model_secret_key):
        raise ValueError("provider configuration differs from enrolled proxy binding")
    if expected["refresh"] and (slot.get("refresh") or {}).get("strategy") != provider.refresh_strategy:
        raise ValueError("provider refresh is not supported by its governance profile")
    if not re.fullmatch(r"[a-z0-9-]+", expected["secret"]) or not re.fullmatch(r"[a-zA-Z0-9_-]+", expected["key"]):
        raise ValueError("invalid proxy marker reference")
    return {slot["env_vars"][0]: shared.credential_marker("saw-cred", expected["secret"], expected["key"])}


def check_policy(kind, credentials, policy, custom_url=None):
    slot, hosts = requirements(kind, custom_url)
    if kind == "custom-inference":
        # Same contract as the VM: the trusted Secret's url supplies the marker
        # host. No static profile may add hosts, even under another binding.
        return (policy.get("markerPrefix") == "saw-cred"
                and not policy["profiles"].get(kind)
                and policy["allowHosts"] == hosts
                and len(policy["bindings"]) == 1
                and any(b.get("providers") == [kind] and b.get("key") == "api_key"
                        and not b.get("refresh") and credentials == {slot["env_vars"][0]:
                        shared.credential_marker("saw-cred", b["secret"], b["key"])} for b in policy["bindings"]))

    if (policy.get("markerPrefix") != "saw-cred" or sorted(policy["profiles"].get(kind, [])) != hosts or
            not set(hosts) <= set(policy["allowHosts"])):
        return False
    for binding in policy["bindings"]:
        if kind not in binding["providers"]:
            continue
        if set(binding["providers"]) - ({kind, "build"} if kind=="nvidia" else {kind}):
            continue
        marker = shared.credential_marker("saw-cred", binding["secret"], binding["key"])
        if credentials != {slot["env_vars"][0]: marker}:
            continue
        refresh = binding.get("refresh")
        if refresh:
            contract = slot.get("refresh", {})
            if (refresh.get("strategy") != contract.get("strategy") or
                    refresh.get("tokenURL") != contract.get("token_url") or
                    refresh.get("material") != {"clientID":"client_id", "clientSecret":"client_secret", "refreshToken":"refresh_token"}):
                return False
        return True
    return False
