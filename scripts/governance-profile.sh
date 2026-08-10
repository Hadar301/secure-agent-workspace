#!/usr/bin/env bash
# Manage governance interceptor provider profiles.
#
# Usage:
#   governance-profile.sh list
#   governance-profile.sh add   <profile-name> <profile-file>
#   governance-profile.sh remove <profile-name>
#
# Examples:
#   governance-profile.sh list
#   governance-profile.sh add github profiles/github.yaml
#   governance-profile.sh remove github

set -euo pipefail

NS="${NS:-openshell-agents}"
CONFIGMAP="governance-interceptor-policy"
DEPLOYMENT="governance-interceptor"

usage() {
  echo "Usage: $0 {list|add|remove} [args]"
  echo ""
  echo "Commands:"
  echo "  list                        List current governance profiles"
  echo "  add <name> <file>           Add or update a provider profile"
  echo "  remove <name>               Remove a provider profile"
  echo ""
  echo "Examples:"
  echo "  $0 list"
  echo "  $0 add github profiles/github.yaml"
  echo "  $0 remove github"
  exit 1
}

restart_interceptor() {
  echo "Restarting interceptor..."
  oc rollout restart deployment/"${DEPLOYMENT}" -n "${NS}" > /dev/null
  oc rollout status deployment/"${DEPLOYMENT}" -n "${NS}" --timeout=30s > /dev/null
  echo "Interceptor restarted. Restart the gateway on the VM to pick up the change:"
  echo "  virtctl ssh ... cloud-user@vmi/openshell-saw --command 'systemctl --user restart openshell-gateway.service'"
}

cmd_list() {
  local saw_name="${SAW_NAME:-openshell-saw}"
  local ssh_key="${SSH_KEY:-$HOME/.generated-ssh-keys/sandbox-ssh}"

  echo "Governance provider profiles (from gateway via interceptor):"
  echo ""
  virtctl ssh -i "${ssh_key}" -n "${NS}" "cloud-user@vmi/${saw_name}" \
    --command "openshell provider list-profiles" 2>&1 \
    | grep -v 'You are using a client virtctl'
}

cmd_add() {
  local name="${1:?Profile name is required}"
  local file="${2:?Profile YAML file is required}"

  if [[ ! -f "${file}" ]]; then
    echo "Error: file '${file}' not found" >&2
    exit 1
  fi

  local content
  content=$(cat "${file}")

  echo "Adding profile '${name}' from ${file}..."
  oc patch configmap "${CONFIGMAP}" -n "${NS}" --type=json \
    -p "[{\"op\":\"add\",\"path\":\"/data/${name}-profile.yaml\",\"value\":$(echo "${content}" | jq -Rs .)}]"

  restart_interceptor
}

cmd_remove() {
  local name="${1:?Profile name is required}"

  echo "Removing profile '${name}'..."
  oc patch configmap "${CONFIGMAP}" -n "${NS}" --type=json \
    -p "[{\"op\":\"remove\",\"path\":\"/data/${name}-profile.yaml\"}]"

  restart_interceptor
}

[[ $# -ge 1 ]] || usage

case "$1" in
  list)   cmd_list ;;
  add)    cmd_add "${2:-}" "${3:-}" ;;
  remove) cmd_remove "${2:-}" ;;
  *)      usage ;;
esac
