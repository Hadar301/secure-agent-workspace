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
PROFILES_DIR="${REPO_DIR}/charts/governance-interceptor/profiles"
SSH_KEY="${SSH_KEY:-$HOME/.generated-ssh-keys/sandbox-ssh}"

# Profile name → file mapping
declare -A PROFILE_MAP=(
  [github]="github.yaml"
  [google-vertex-ai]="google-vertex-ai.yaml"
  [inference]="inference.yaml"
  [slack]="slack.yaml"
)

usage() {
  echo "Usage: $0 {list|add|remove} [profile-name]"
  echo ""
  echo "Commands:"
  echo "  list                 List active governance profiles"
  echo "  add <name>           Add a provider profile (git push + ArgoCD sync)"
  echo "  remove <name>        Remove a provider profile (git push + ArgoCD sync)"
  echo ""
  echo "Available profiles: ${!PROFILE_MAP[*]}"
  echo ""
  echo "Examples:"
  echo "  $0 list"
  echo "  $0 remove github       # revoke GitHub access"
  echo "  $0 add github          # restore GitHub access"
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

cmd_list() {
  echo "Governance provider profiles:"
  echo ""
  openshell --gateway "${SAW_NAME}" --gateway-insecure provider list-profiles 2>&1 \
    | grep -v 'TLS certificate'
  echo ""
  echo "Profile files in git:"
  for name in "${!PROFILE_MAP[@]}"; do
    file="${PROFILES_DIR}/${PROFILE_MAP[$name]}"
    if [[ -f "${file}" ]]; then
      echo "  [active]   ${name}  → profiles/${PROFILE_MAP[$name]}"
    elif [[ -f "${file}.disabled" ]]; then
      echo "  [disabled] ${name}  → profiles/${PROFILE_MAP[$name]}.disabled"
    else
      echo "  [missing]  ${name}  → profiles/${PROFILE_MAP[$name]}"
    fi
  done
}

cmd_add() {
  local name="${1:?Profile name is required}"
  local file="${PROFILE_MAP[$name]:-}"

  if [[ -z "${file}" ]]; then
    echo "Error: unknown profile '${name}'. Available: ${!PROFILE_MAP[*]}" >&2
    exit 1
  fi

  local path="${PROFILES_DIR}/${file}"

  if [[ -f "${path}" ]]; then
    echo "Profile '${name}' is already active."
    return 0
  fi

  if [[ -f "${path}.disabled" ]]; then
    echo "Restoring profile '${name}'..."
    git -C "${REPO_DIR}" mv "${path}.disabled" "${path}" > /dev/null 2>&1
  else
    echo "Error: no profile file found for '${name}' (expected ${path} or ${path}.disabled)" >&2
    exit 1
  fi

  git -C "${REPO_DIR}" commit -m "policy: enable ${name} provider profile" --no-verify > /dev/null 2>&1
  git -C "${REPO_DIR}" push origin HEAD --no-verify > /dev/null 2>&1
  echo "  Pushed: profiles/${file}"

  wait_for_sync
  echo ""
  echo "Profile '${name}' enabled."
}

cmd_remove() {
  local name="${1:?Profile name is required}"
  local file="${PROFILE_MAP[$name]:-}"

  if [[ -z "${file}" ]]; then
    echo "Error: unknown profile '${name}'. Available: ${!PROFILE_MAP[*]}" >&2
    exit 1
  fi

  local path="${PROFILES_DIR}/${file}"

  if [[ ! -f "${path}" ]]; then
    echo "Profile '${name}' is already disabled."
    return 0
  fi

  echo "Removing profile '${name}'..."
  git -C "${REPO_DIR}" mv "${path}" "${path}.disabled" > /dev/null 2>&1
  git -C "${REPO_DIR}" commit -m "policy: revoke ${name} provider profile" --no-verify > /dev/null 2>&1
  git -C "${REPO_DIR}" push origin HEAD --no-verify > /dev/null 2>&1
  echo "  Pushed: profiles/${file} → profiles/${file}.disabled"

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
