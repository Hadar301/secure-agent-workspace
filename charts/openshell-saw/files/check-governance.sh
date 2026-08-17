#!/usr/bin/env bash
# Phase: verify governance interceptor is reachable and inject SSH key fallback.
# Expects: GOVERNANCE_ENABLED, GOVERNANCE_ENDPOINT, guest_ssh (function)

if [[ "${GOVERNANCE_ENABLED}" == "true" ]]; then
  echo "Checking governance interceptor at ${GOVERNANCE_ENDPOINT}..."
  INTERCEPTOR_READY=0
  for i in $(seq 1 12); do
    if curl -sf --max-time 5 "${GOVERNANCE_ENDPOINT}" >/dev/null 2>&1 || \
       guest_ssh "openshell-gateway --version" >/dev/null 2>&1 && \
       guest_ssh "journalctl --user -u openshell-gateway.service --no-pager 2>/dev/null | grep -q 'interceptors initialized'"; then
      INTERCEPTOR_READY=1
      break
    fi
    echo "  waiting for interceptor... (attempt $i)"
    sleep 5
  done
  if [[ "${INTERCEPTOR_READY}" -ne 1 ]]; then
    echo "ERROR: governance interceptor is unreachable at ${GOVERNANCE_ENDPOINT}" >&2
    echo "ERROR: governance.enabled=true requires a running interceptor. Deploy governance-interceptor chart first." >&2
    exit 1
  fi
  echo "Governance interceptor is reachable."
fi

# --- SSH key fallback (cloud-init may not have injected it yet) ---
if [[ -f /ssh-key/public_key ]]; then
  SSH_PUB="$(cat /ssh-key/public_key)"
  if [[ -n "${SSH_PUB}" ]]; then
    guest_ssh "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${SSH_PUB}' >> ~/.ssh/authorized_keys && sort -u -o ~/.ssh/authorized_keys ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" || true
    echo "SSH public key injected into VM"
  fi
fi
