#!/usr/bin/env bash
# Print the Keycloak host in one namespace, without a scheme or path.
set -euo pipefail

namespace="${1:-${KEYCLOAK_NS:-saw-keycloak}}"
host=""

# Keep stderr out of the JSON we hand to jq. The Keycloak operator prints a
# "Please migrate to v2beta1" deprecation warning on stderr; merging it into
# stdout (2>&1) corrupts the JSON and makes jq fail with a parse error.
errfile="$(mktemp)"
trap 'rm -f "${errfile}"' EXIT

if keycloaks="$(oc get keycloaks -n "${namespace}" -o json 2>"${errfile}")"; then
  # Host can live in different fields across operator versions: prefer
  # status.externalURL, then spec.hostname (string), then spec.hostname.hostname.
  host="$(jq -r '
    [.items[] | select(.metadata.name == "openshell-keycloak")] +
    [.items[] | select(.metadata.name != "openshell-keycloak")] |
    map(
      (.status.externalURL // "") as $url |
      if $url != "" then $url
      elif (.spec.hostname | type) == "string" then .spec.hostname
      else .spec.hostname.hostname // "" end
    ) |
    map(select(. != "")) | first // empty' <<<"${keycloaks}")"
elif ! grep -qE "doesn't have a resource type|the server could not find the requested resource" "${errfile}"; then
  echo "Error: cannot query Keycloak in ${namespace}. Check cluster access." >&2
  exit 2
fi

if [[ -z "${host}" ]]; then
  if routes="$(oc get routes -n "${namespace}" -o json 2>"${errfile}")"; then
    host="$(jq -r '
      [.items[] | select(.metadata.labels.app == "keycloak" or
        (.metadata.name // "" | contains("keycloak")))] |
      map(.spec.host // empty) | map(select(. != "")) | first // empty' \
      <<<"${routes}")"
  elif ! grep -qE "NotFound|not found" "${errfile}"; then
    echo "Error: cannot query routes in ${namespace}. Check cluster access." >&2
    exit 2
  fi
fi

host="$(printf '%s' "${host}" | sed -e 's|^https\{0,1\}://||' -e 's|/.*$||')"
if [[ -z "${host}" ]]; then
  echo "Error: no Keycloak found in namespace ${namespace}. Set KEYCLOAK_NS or run make keycloak-deploy." >&2
  exit 1
fi
printf '%s\n' "${host}"
