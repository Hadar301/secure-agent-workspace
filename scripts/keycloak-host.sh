#!/usr/bin/env bash
# Print the host name of the Keycloak in a namespace (no scheme, no slash).
# Exits 1 if none is found.
#
# Usage: keycloak-host.sh [namespace]   (default: $KEYCLOAK_NS or saw-keycloak)
#
# Works for the Keycloak `make keycloak` deploys and for an existing RHBK
# instance, which may report its URL in status.externalURL, only set
# spec.hostname.hostname, or be exposed by a route without the app=keycloak
# label.
set -uo pipefail

NS="${1:-${KEYCLOAK_NS:-saw-keycloak}}"

clean() { sed -e 's|^https\{0,1\}://||' -e 's|/.*$||'; }

# The repo's own Keycloak (make keycloak) wins if the namespace has several.
host=$(oc get keycloak openshell-keycloak -n "${NS}" -o jsonpath='{.status.externalURL}' 2>/dev/null | clean)
[[ -n "${host}" ]] || host=$(oc get keycloak -n "${NS}" -o jsonpath='{.items[0].status.externalURL}' 2>/dev/null | clean)
[[ -n "${host}" ]] || host=$(oc get keycloak -n "${NS}" -o jsonpath='{.items[0].spec.hostname.hostname}' 2>/dev/null | clean)
[[ -n "${host}" ]] || host=$(oc get route -n "${NS}" -l app=keycloak -o jsonpath='{.items[0].spec.host}' 2>/dev/null)
[[ -n "${host}" ]] || host=$(oc get route -n "${NS}" -o jsonpath='{.items[0].spec.host}' 2>/dev/null)

if [[ -z "${host}" ]]; then
  echo "Error: no Keycloak found in namespace ${NS} (set KEYCLOAK_NS, or run 'make keycloak')" >&2
  exit 1
fi
echo "${host}"
