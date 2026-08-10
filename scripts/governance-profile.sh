#!/usr/bin/env bash
# Manage governance interceptor provider profiles via GitOps.
#
# Usage:
#   governance-profile.sh list
#   governance-profile.sh add    <profile-name>
#   governance-profile.sh remove <profile-name>
#
# Examples:
#   governance-profile.sh list
#   governance-profile.sh remove github
#   governance-profile.sh add github

set -euo pipefail

NS="${NS:-openshell-agents}"
SAW_NAME="${SAW_NAME:-openshell-saw}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VALUES_FILE="${REPO_DIR}/charts/governance-interceptor/values.yaml"
PROFILES_DIR="${REPO_DIR}/charts/governance-interceptor/profiles"
SSH_KEY="${SSH_KEY:-$HOME/.generated-ssh-keys/sandbox-ssh}"

usage() {
  echo "Usage: $0 {list|add|remove} [profile-name]"
  echo ""
  echo "Commands:"
  echo "  list                 List active governance profiles"
  echo "  add <name>           Enable a provider profile (git push + ArgoCD sync)"
  echo "  remove <name>        Disable a provider profile (git push + ArgoCD sync)"
  echo ""
  echo "Available profiles:"
  for f in "${PROFILES_DIR}"/*.yaml; do
    echo "  - $(basename "${f}" .yaml)"
  done
  exit 1
}

wait_for_sync() {
  echo "  Waiting for ArgoCD to sync..."
  oc annotate application governance-interceptor -n vp-gitops \
    argocd.argoproj.io/refresh=hard --overwrite > /dev/null 2>&1
  sleep 20
  oc rollout status deployment/governance-interceptor -n "${NS}" --timeout=90s > /dev/null 2>&1

  echo "  Restarting gateway to pick up new profiles..."
  virtctl ssh -i "${SSH_KEY}" -n "${NS}" "cloud-user@vmi/${SAW_NAME}" \
    --local-ssh-opts="-o StrictHostKeyChecking=no" \
    --local-ssh-opts="-o UserKnownHostsFile=/dev/null" \
    --local-ssh-opts="-o LogLevel=ERROR" \
    --command "systemctl --user restart openshell-gateway.service; sleep 5" > /dev/null 2>&1
  echo "  Done."
}

is_profile_enabled() {
  grep -qE "^  - ${1}$" "${VALUES_FILE}"
}

cmd_list() {
  echo "Governance provider profiles:"
  echo ""
  openshell --gateway "${SAW_NAME}" --gateway-insecure provider list-profiles 2>&1 \
    | grep -v 'TLS certificate'
  echo ""
  echo "Profiles in values.yaml:"
  for f in "${PROFILES_DIR}"/*.yaml; do
    local name
    name=$(basename "${f}" .yaml)
    if is_profile_enabled "${name}"; then
      echo "  [enabled]  ${name}"
    else
      echo "  [disabled] ${name}"
    fi
  done
}

cmd_add() {
  local name="${1:?Profile name is required}"

  if [[ ! -f "${PROFILES_DIR}/${name}.yaml" ]]; then
    echo "Error: no profile file found at profiles/${name}.yaml" >&2
    echo "Available: $(ls "${PROFILES_DIR}"/*.yaml | xargs -I{} basename {} .yaml | tr '\n' ' ')" >&2
    exit 1
  fi

  if is_profile_enabled "${name}"; then
    echo "Profile '${name}' is already enabled."
    return 0
  fi

  echo "Enabling profile '${name}'..."
  # Add the profile to the list in values.yaml (after the last profile entry)
  sed -i '' "/^profiles:/,/^[^ ]/ { /^  - /{ H; }; }; /^profiles:/,/^[^ ]/ { /^$/{ x; s/$/  - ${name}/; p; d; }; }" "${VALUES_FILE}" 2>/dev/null \
    || sed -i "s/^profiles:$/&\n  - ${name}/" "${VALUES_FILE}"

  # If that didn't work (profile section is at end of file), append
  if ! is_profile_enabled "${name}"; then
    echo "  - ${name}" >> "${VALUES_FILE}"
  fi

  git -C "${REPO_DIR}" add "${VALUES_FILE}" > /dev/null 2>&1
  git -C "${REPO_DIR}" commit -m "policy: enable ${name} provider profile" --no-verify > /dev/null 2>&1
  git -C "${REPO_DIR}" push origin HEAD --no-verify > /dev/null 2>&1
  echo "  Pushed: added '${name}' to profiles list"

  wait_for_sync
  echo ""
  echo "Profile '${name}' enabled."
}

cmd_remove() {
  local name="${1:?Profile name is required}"

  if ! is_profile_enabled "${name}"; then
    echo "Profile '${name}' is already disabled."
    return 0
  fi

  echo "Disabling profile '${name}'..."
  # Remove the profile from the list in values.yaml
  sed -i '' "/^  - ${name}$/d" "${VALUES_FILE}" 2>/dev/null \
    || sed -i "/^  - ${name}$/d" "${VALUES_FILE}"

  git -C "${REPO_DIR}" add "${VALUES_FILE}" > /dev/null 2>&1
  git -C "${REPO_DIR}" commit -m "policy: revoke ${name} provider profile" --no-verify > /dev/null 2>&1
  git -C "${REPO_DIR}" push origin HEAD --no-verify > /dev/null 2>&1
  echo "  Pushed: removed '${name}' from profiles list"

  wait_for_sync
  echo ""
  echo "Profile '${name}' disabled."
}

[[ $# -ge 1 ]] || usage

case "$1" in
  list)   cmd_list ;;
  add)    cmd_add "${2:-}" ;;
  remove) cmd_remove "${2:-}" ;;
  *)      usage ;;
esac
