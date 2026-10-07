#!/usr/bin/env bash
# Add this VM's dashboard and sandbox UI redirect URIs to the Keycloak client.
set -euo pipefail

register_redirects() {
  local hosts=() host secret user password base token_response token client_id
  local redirects origins client_json updated_json http_code

  if [[ "${DASHBOARD_ENABLED:-false}" == true ]]; then
    host="$(kubectl get route "${VM_NAME}-webui" -n "${NS}" -o jsonpath='{.spec.host}')"
    [[ -n "${host}" ]] || { echo "Error: dashboard route has no host." >&2; return 1; }
    hosts+=("${host}")
  fi
  for host in ${UI_ROUTE_HOSTS:-}; do
    hosts+=("${host}")
  done
  if (( ${#hosts[@]} == 0 )); then
    echo "No dashboard redirect URIs are required."
    return 0
  fi

  secret="${OIDC_KEYCLOAK_NAME}-initial-admin"
  user="$(kubectl get secret "${secret}" -n "${KEYCLOAK_NS}" \
    -o jsonpath='{.data.username}' | base64 -d)"
  password="$(kubectl get secret "${secret}" -n "${KEYCLOAK_NS}" \
    -o jsonpath='{.data.password}' | base64 -d)"
  [[ -n "${user}" && -n "${password}" ]] || {
    echo "Error: Keycloak admin credentials are incomplete." >&2
    return 1
  }
  base="${OIDC_ISSUER_URL%%/realms/*}"
  [[ "${base}" != "${OIDC_ISSUER_URL}" ]] || {
    echo "Error: OIDC issuer URL does not contain a realm path." >&2
    return 1
  }

  token_response="$(curl -fsSk -X POST \
    "${base}/realms/master/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=admin-cli \
    --data-urlencode "username=${user}" --data-urlencode "password=${password}")"
  token="$(jq -er '.access_token' <<<"${token_response}")" || {
    echo "Error: Keycloak did not return an admin token." >&2
    return 1
  }
  client_id="$(curl -fsSk -H "Authorization: Bearer ${token}" \
    "${base}/admin/realms/${OIDC_REALM}/clients?clientId=${DASHBOARD_CLIENT_ID}" |
    jq -er '.[0].id')" || {
    echo "Error: dashboard OIDC client was not found." >&2
    return 1
  }

  redirects="$(printf 'https://%s/oauth2/callback\n' "${hosts[@]}" | jq -R . | jq -s .)"
  origins="$(printf 'https://%s\n' "${hosts[@]}" | jq -R . | jq -s .)"
  client_json="$(curl -fsSk -H "Authorization: Bearer ${token}" \
    "${base}/admin/realms/${OIDC_REALM}/clients/${client_id}")"
  updated_json="$(jq --argjson redirects "${redirects}" --argjson origins "${origins}" \
    '.redirectUris = ((.redirectUris // []) + $redirects | unique) |
     .webOrigins = ((.webOrigins // []) + $origins | unique)' <<<"${client_json}")"
  http_code="$(curl -fsSk -o /dev/null -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' \
    -d "${updated_json}" \
    "${base}/admin/realms/${OIDC_REALM}/clients/${client_id}")"
  [[ "${http_code}" == 204 ]] || {
    echo "Error: Keycloak rejected the dashboard redirects (HTTP ${http_code})." >&2
    return 1
  }
  echo "Registered ${#hosts[@]} dashboard redirect URI(s)."
}

register_redirects
