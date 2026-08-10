#!/usr/bin/env bash
# Demo: Governance Interceptor for Secure Agent Workspace
#
# Shows how the governance interceptor enforces provider policies —
# only approved provider profiles can be created on the sandbox.
#
# Usage: ./scripts/demo-governance.sh [OPENSHELL_SAW_NAME]

set -euo pipefail

SAW_NAME="${1:-openshell-saw}"
NS="${NS:-openshell-agents}"
SSH_KEY="${SSH_KEY:-$HOME/.generated-ssh-keys/sandbox-ssh}"
PAUSE="${PAUSE:-true}"

GREEN='\033[1;32m'
RED='\033[1;31m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

press_enter() {
  if [[ "${PAUSE}" == "true" ]]; then
    echo ""
    read -rp "  Press Enter to continue..."
    echo ""
  fi
}

banner() {
  echo ""
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${CYAN}  $1${RESET}"
  echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
  echo ""
}

step() {
  echo -e "${BOLD}▸ $1${RESET}"
}

gw() {
  openshell --gateway "${SAW_NAME}" --gateway-insecure "$@" 2>&1 \
    | grep -v 'TLS certificate'
}

run_on_vm() {
  virtctl ssh -i "${SSH_KEY}" -n "${NS}" "cloud-user@vmi/${SAW_NAME}" \
    --local-ssh-opts="-o StrictHostKeyChecking=no" \
    --local-ssh-opts="-o UserKnownHostsFile=/dev/null" \
    --local-ssh-opts="-o LogLevel=ERROR" \
    --command "$1" 2>&1 \
    | grep -v 'You are using a client virtctl'
}

# Clean up any stale demo providers from previous runs
for p in demo-vertex demo-github demo-vertex-ok demo-github-restored demo-github-blocked; do
  gw provider delete "${p}" > /dev/null 2>&1 || true
done

banner "Governance Interceptor Demo — Secure Agent Workspace"

echo -e "This demo shows how a ${BOLD}governance interceptor${RESET} enforces"
echo -e "admin-controlled policies on AI agent sandboxes."
echo ""
echo -e "The interceptor runs as a ${BOLD}Kubernetes pod${RESET} and the gateway"
echo -e "inside the VM connects to it over the pod network."
echo ""

press_enter

# --- 1. Show interceptor pod ---
banner "1. Governance Interceptor Pod"

step "Interceptor deployed by ArgoCD as a Kubernetes pod:"
echo ""
oc get pods -n "${NS}" -l app.kubernetes.io/name=governance-interceptor \
  -o custom-columns='NAME:.metadata.name,STATUS:.status.phase,IMAGE:.spec.containers[0].image' \
  --no-headers
echo ""

step "Interceptor startup logs:"
echo ""
oc logs deployment/governance-interceptor -n "${NS}" 2>&1 | head -4
echo ""

press_enter

# --- 2. Show profiles ---
banner "2. Governed Provider Profiles"

step "These profiles are enforced by the interceptor — only these provider"
step "types can be created on the sandbox:"
echo ""
gw provider list-profiles
echo ""

press_enter

# --- 3. Pass tests ---
banner "3. Allowed Providers (should succeed)"

step "Creating a Google Vertex AI provider (governed profile):"
echo ""
gw provider create --name demo-vertex --type google-vertex-ai --credential GOOGLE_API_KEY=demo-key
echo ""

step "Creating a GitHub provider (governed profile):"
echo ""
gw provider create --name demo-github --type github --credential GITHUB_TOKEN=demo-token
echo ""

press_enter

# --- 4. Fail tests ---
banner "4. Blocked Providers (should fail)"

step "Attempting to create a 'custom' provider (not in governance profiles):"
echo ""
gw provider create --name demo-blocked --type custom --credential key=value || true
echo ""

step "Attempting to create an Anthropic provider (not in governance profiles):"
echo ""
gw provider create --name demo-blocked2 --type claude-code --credential ANTHROPIC_API_KEY=demo-key || true
echo ""

press_enter

# --- 5. Show gateway interceptor logs ---
banner "5. Gateway Interceptor Audit Log"

step "The gateway logs every interceptor decision (allow/deny):"
echo ""
run_on_vm "journalctl --user -u openshell-gateway.service --no-pager" \
  | { grep 'interceptor.*evaluated' || true; } \
  | sed 's/.*gateway interceptor evaluated /  /' \
  | tail -6
echo ""

press_enter

# --- 6. Revoke a profile ---
banner "6. Revoking Access — Remove GitHub Profile"

step "An admin decides GitHub access should no longer be allowed."
step "Removing the GitHub profile from the governance policy..."
echo ""

# Pause ArgoCD sync so it doesn't revert our changes
oc patch application governance-interceptor -n vp-gitops --type=merge \
  -p '{"spec":{"syncPolicy":null}}' > /dev/null 2>&1

# Back up and remove the github profile
GITHUB_PROFILE_BACKUP=$(oc get configmap governance-interceptor-policy -n "${NS}" -o jsonpath='{.data.github-profile\.yaml}')
oc get configmap governance-interceptor-policy -n "${NS}" -o json \
  | jq 'del(.data["github-profile.yaml"])' \
  | oc replace -f - > /dev/null 2>&1

# Remove the github volume mount from the deployment so the pod doesn't crash
oc get deployment governance-interceptor -n "${NS}" -o json \
  | jq '(.spec.template.spec.containers[0].volumeMounts) |= [.[] | select(.subPath != "github-profile.yaml")]' \
  | oc replace -f - > /dev/null 2>&1

oc rollout status deployment/governance-interceptor -n "${NS}" --timeout=60s > /dev/null 2>&1
run_on_vm "systemctl --user restart openshell-gateway.service; sleep 5" > /dev/null 2>&1

echo -e "${YELLOW}  GitHub profile removed. Interceptor and gateway restarted.${RESET}"
echo ""

step "Available profiles now (GitHub is gone):"
echo ""
gw provider list-profiles
echo ""

press_enter

step "Trying to create a GitHub provider (no longer in governance):"
echo ""
gw provider create --name demo-github-blocked --type github --credential GITHUB_TOKEN=demo-token || true
echo ""

step "Google Vertex AI still works (profile is still present):"
echo ""
gw provider create --name demo-vertex-ok --type google-vertex-ai --credential GOOGLE_API_KEY=demo-key || true
echo ""

press_enter

# --- 7. Restore profile ---
banner "7. Restoring GitHub Access"

step "Admin restores the GitHub profile..."
echo ""

# Re-enable ArgoCD sync — it will restore the configmap and deployment
oc patch application governance-interceptor -n vp-gitops --type=merge \
  -p '{"spec":{"syncPolicy":{"automated":{"prune":true,"selfHeal":true}}}}' > /dev/null 2>&1
oc annotate application governance-interceptor -n vp-gitops argocd.argoproj.io/refresh=hard --overwrite > /dev/null 2>&1
sleep 15
oc rollout status deployment/governance-interceptor -n "${NS}" --timeout=60s > /dev/null 2>&1

run_on_vm "systemctl --user restart openshell-gateway.service; sleep 5" > /dev/null 2>&1

echo -e "${GREEN}  GitHub profile restored via GitOps.${RESET}"
echo ""

step "GitHub provider creation works again:"
echo ""
gw provider create --name demo-github-restored --type github --credential GITHUB_TOKEN=demo-token || true
echo ""

press_enter

# --- 8. Cleanup ---
banner "8. Cleanup"

gw provider delete demo-vertex > /dev/null 2>&1 || true
gw provider delete demo-github > /dev/null 2>&1 || true
gw provider delete demo-vertex-ok > /dev/null 2>&1 || true
gw provider delete demo-github-restored > /dev/null 2>&1 || true
echo -e "${GREEN}  Demo providers cleaned up.${RESET}"
echo ""

banner "Demo Complete"

echo -e "Summary:"
echo -e "  ${GREEN}✓${RESET} Governance interceptor deployed as a Kubernetes pod (ArgoCD)"
echo -e "  ${GREEN}✓${RESET} VM gateway connects to interceptor over pod network (HTTP/2)"
echo -e "  ${GREEN}✓${RESET} Governed providers (google-vertex-ai, github) — ${GREEN}allowed${RESET}"
echo -e "  ${RED}✗${RESET} Ungoverned providers (custom, claude-code) — ${RED}blocked${RESET}"
echo -e "  ${YELLOW}!${RESET} Revoked profile (github removed) — ${RED}blocked until restored${RESET}"
echo -e "  ${GREEN}✓${RESET} Signed policy injected into sandbox creation (patch_count=2)"
echo -e "  ${GREEN}✓${RESET} Full audit trail in gateway logs"
echo ""
