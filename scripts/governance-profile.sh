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
  echo "  list                      List active governance profiles"
  echo "  add <name>                Enable an existing profile (git push + ArgoCD sync)"
  echo "  remove <name>             Disable a provider profile (git push + ArgoCD sync)"
  echo "  create <name> <file>      Create a new profile from a YAML file and enable it"
  echo ""
  echo "Available profiles:"
  for f in "${PROFILES_DIR}"/*.yaml; do
    echo "  - $(basename "${f}" .yaml)"
  done
  echo ""
  echo "Examples:"
  echo "  $0 list"
  echo "  $0 remove github"
  echo "  $0 add github"
  echo "  $0 create jira /path/to/jira-profile.yaml"
  exit 1
}

wait_for_sync() {
  echo "  Waiting for ArgoCD to sync..."
  oc annotate application governance-interceptor -n vp-gitops \
    argocd.argoproj.io/refresh=hard --overwrite > /dev/null 2>&1
  sleep 20
  # Restart the interceptor so it loads the updated ConfigMap immediately
  oc rollout restart deployment/governance-interceptor -n "${NS}" > /dev/null 2>&1
  oc rollout status deployment/governance-interceptor -n "${NS}" --timeout=90s > /dev/null 2>&1
  echo "  Interceptor synced."
  # Gateway polls the interceptor manifest every 10s; wait for at least
  # one full poll cycle after the new pod is ready.
  sleep 15
  echo "  Gateway hot-reload picked up manifest changes."
}

is_profile_enabled() {
  grep -qE "^  - ${1}$" "${VALUES_FILE}"
}

cmd_list() {
  echo "Active profiles (enforced on gateway):"
  echo ""
  openshell --gateway "${SAW_NAME}" --gateway-insecure provider list-profiles 2>&1 \
    | grep -v 'TLS certificate'
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
  yq -i '.profiles += ["'"${name}"'"]' "${VALUES_FILE}"

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
  yq -i 'del(.profiles[] | select(. == "'"${name}"'"))' "${VALUES_FILE}"

  git -C "${REPO_DIR}" add "${VALUES_FILE}" > /dev/null 2>&1
  git -C "${REPO_DIR}" commit -m "policy: revoke ${name} provider profile" --no-verify > /dev/null 2>&1
  git -C "${REPO_DIR}" push origin HEAD --no-verify > /dev/null 2>&1
  echo "  Pushed: removed '${name}' from profiles list"

  wait_for_sync
  echo ""
  echo "Profile '${name}' disabled."
}

cmd_create() {
  local name="${1:?Profile name is required}"
  local file="${2:?Profile YAML file is required}"

  if [[ ! -f "${file}" ]]; then
    echo "Error: file '${file}' not found" >&2
    exit 1
  fi

  local dest="${PROFILES_DIR}/${name}.yaml"

  if [[ -f "${dest}" ]]; then
    echo "Profile file profiles/${name}.yaml already exists."
    echo "Use 'add ${name}' to enable it, or edit the file directly."
    return 1
  fi

  echo "Creating profile '${name}' from ${file}..."
  cp "${file}" "${dest}"
  echo "  Created: profiles/${name}.yaml"

  # Add to profiles list in values.yaml
  if ! is_profile_enabled "${name}"; then
    yq -i '.profiles += ["'"${name}"'"]' "${VALUES_FILE}"
  fi

  git -C "${REPO_DIR}" add "${dest}" "${VALUES_FILE}" > /dev/null 2>&1
  git -C "${REPO_DIR}" commit -m "policy: add ${name} provider profile" --no-verify > /dev/null 2>&1
  git -C "${REPO_DIR}" push origin HEAD --no-verify > /dev/null 2>&1
  echo "  Pushed: profiles/${name}.yaml + added to profiles list"

  wait_for_sync
  echo ""
  echo "Profile '${name}' created and enabled."
}

[[ $# -ge 1 ]] || usage

case "$1" in
  list)   cmd_list ;;
  add)    cmd_add "${2:-}" ;;
  remove) cmd_remove "${2:-}" ;;
  create) cmd_create "${2:-}" "${3:-}" ;;
  *)      usage ;;
esac
