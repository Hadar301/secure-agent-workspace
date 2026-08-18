#!/usr/bin/env bash
# Phase: register dashboard redirect URI on Keycloak and run dashboard setup on VM.
# Expects: VM_NAME, NS, SSH_USER, RUNTIME, OIDC_KEYCLOAK_NAME, OIDC_REALM,
#          KEYCLOAK_NS, DASHBOARD_IMAGE, DASHBOARD_PROXY_IMAGE, DASHBOARD_CLIENT_ID,
#          OIDC_ISSUER_URL, SCRIPTS_DIR, guest_ssh, guest_scp (functions)

guest_scp "${SCRIPTS_DIR}/setup-dashboard.sh" "/home/${SSH_USER}/setup-dashboard.sh"
WEBUI_ROUTE_HOST="$(kubectl get route "${VM_NAME}-webui" -n "${NS}" -o jsonpath='{.spec.host}' 2>/dev/null || true)"
if [[ -z "${WEBUI_ROUTE_HOST}" ]]; then
  echo "WARNING: ${VM_NAME}-webui route not found — skipping dashboard setup"
  return 0 2>/dev/null || true
fi

DASHBOARD_REDIRECT_URL="https://${WEBUI_ROUTE_HOST}/oauth2/callback"
DASHBOARD_COOKIE_SECRET="$(openssl rand -hex 16)"

# Register redirect URI on Keycloak client
KC_ADMIN_SECRET="${OIDC_KEYCLOAK_NAME}-initial-admin"
KC_ADMIN_USER="$(kubectl get secret "${KC_ADMIN_SECRET}" -n "${KEYCLOAK_NS}" -o jsonpath='{.data.username}' 2>/dev/null | base64 -d || true)"
KC_ADMIN_PASS="$(kubectl get secret "${KC_ADMIN_SECRET}" -n "${KEYCLOAK_NS}" -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || true)"
KC_BASE="$(echo "${OIDC_ISSUER:-${OIDC_ISSUER_URL}}" | sed 's#/realms/.*##')"
if [[ -n "${KC_ADMIN_USER}" && -n "${KC_BASE}" ]]; then
  echo "Registering redirect URI on Keycloak client '${DASHBOARD_CLIENT_ID}'..."
  KC_ADMIN_TOKEN="$(curl -sk -X POST "${KC_BASE}/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" -d "client_id=admin-cli" \
    -d "username=${KC_ADMIN_USER}" -d "password=${KC_ADMIN_PASS}" \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"
  if [[ -n "${KC_ADMIN_TOKEN}" ]]; then
    CLIENT_UUID="$(curl -sk -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" \
      "${KC_BASE}/admin/realms/${OIDC_REALM}/clients?clientId=${DASHBOARD_CLIENT_ID}" \
      | jq -r '.[0].id // empty')"
    if [[ -n "${CLIENT_UUID}" ]]; then
      CLIENT_JSON="$(curl -sk -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" \
        "${KC_BASE}/admin/realms/${OIDC_REALM}/clients/${CLIENT_UUID}")"
      WEBUI_ORIGIN="https://${WEBUI_ROUTE_HOST}"
      UPDATED_JSON="$(echo "${CLIENT_JSON}" | jq \
        --arg redirect "${DASHBOARD_REDIRECT_URL}" --arg origin "${WEBUI_ORIGIN}" \
        '.redirectUris = ((.redirectUris // []) + [$redirect] | unique) |
         .webOrigins = ((.webOrigins // []) + [$origin] | unique)')"
      HTTP_CODE="$(curl -sk -o /dev/null -w '%{http_code}' -X PUT \
        -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" -H "Content-Type: application/json" \
        -d "${UPDATED_JSON}" \
        "${KC_BASE}/admin/realms/${OIDC_REALM}/clients/${CLIENT_UUID}")"
      if [[ "${HTTP_CODE}" == "204" ]]; then
        echo "Redirect URI registered: ${DASHBOARD_REDIRECT_URL}"
      else
        echo "WARNING: failed to register redirect URI (HTTP ${HTTP_CODE}) — dashboard OIDC login will fail"
      fi
    else
      echo "WARNING: Keycloak client '${DASHBOARD_CLIENT_ID}' not found — dashboard OIDC login will fail"
    fi
  else
    echo "WARNING: could not obtain Keycloak admin token — dashboard OIDC login will fail"
  fi
else
  echo "WARNING: Keycloak admin credentials not found — dashboard OIDC login will fail"
fi

# Run dashboard setup on VM
guest_ssh "
  set -a; source /home/${SSH_USER}/bom.env 2>/dev/null; set +a
  export RUNTIME='${RUNTIME}'
  export DASHBOARD_ENABLED=true
  export DASHBOARD_IMAGE='${DASHBOARD_IMAGE}'
  export DASHBOARD_PROXY_IMAGE='${DASHBOARD_PROXY_IMAGE}'
  export DASHBOARD_CLIENT_ID='${DASHBOARD_CLIENT_ID}'
  export DASHBOARD_COOKIE_SECRET=${DASHBOARD_COOKIE_SECRET}
  export DASHBOARD_REDIRECT_URL=${DASHBOARD_REDIRECT_URL}
  export DASHBOARD_INSECURE_SKIP_TLS='${DASHBOARD_INSECURE_SKIP_TLS}'
  bash /home/${SSH_USER}/setup-dashboard.sh
" 2>&1 || echo "WARN: dashboard setup failed"
