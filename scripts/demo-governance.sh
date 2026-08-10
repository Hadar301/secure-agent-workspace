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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROFILES_DIR="${REPO_DIR}/charts/governance-interceptor/profiles"
VALUES_FILE="${REPO_DIR}/charts/governance-interceptor/values.yaml"

# Clean up any stale state from previous runs
for p in demo-vertex demo-github demo-vertex-ok demo-github-restored demo-github-blocked demo-jira demo-jira-blocked; do
  gw provider delete "${p}" > /dev/null 2>&1 || true
done

# Remove jira profile if left over from a previous run
if [[ -f "${PROFILES_DIR}/jira.yaml" ]]; then
  rm -f "${PROFILES_DIR}/jira.yaml"
  yq -i 'del(.profiles[] | select(. == "jira"))' "${VALUES_FILE}"
  git -C "${REPO_DIR}" add -A > /dev/null 2>&1
  git -C "${REPO_DIR}" commit -m "demo: clean up stale jira profile" --no-verify > /dev/null 2>&1
  git -C "${REPO_DIR}" push origin HEAD --no-verify > /dev/null 2>&1
fi

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
step "Admin removes the github profile from git and pushes..."
echo ""

NS="${NS}" SAW_NAME="${SAW_NAME}" SSH_KEY="${SSH_KEY}" "${SCRIPT_DIR}/governance-profile.sh" remove github

echo -e "${YELLOW}  GitHub profile revoked via GitOps.${RESET}"
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

step "Admin restores the github profile..."
echo ""

NS="${NS}" SAW_NAME="${SAW_NAME}" SSH_KEY="${SSH_KEY}" "${SCRIPT_DIR}/governance-profile.sh" add github

echo -e "${GREEN}  GitHub profile restored via GitOps.${RESET}"
echo ""

step "GitHub provider creation works again:"
echo ""
gw provider create --name demo-github-restored --type github --credential GITHUB_TOKEN=demo-token || true
echo ""

press_enter

# --- 8. Add a new provider profile ---
banner "8. Adding a New Provider — Jira"

step "A team needs Jira access from their sandbox."
step "First, let's see that Jira is not currently allowed:"
echo ""
gw provider create --name demo-jira --type jira --credential JIRA_TOKEN=demo-token || true
echo ""

press_enter

step "Admin creates a Jira profile YAML:"
echo ""

JIRA_PROFILE=$(mktemp /tmp/jira-profile-XXXXXX.yaml)
cat > "${JIRA_PROFILE}" << 'PROFILE'
display_name: Jira
description: Atlassian Jira project tracking
provider_type: custom
endpoints:
  - host: your-org.atlassian.net
    port: 443
    protocol: rest
    enforcement: enforce
    access: read-write
PROFILE

echo -e "  ${BOLD}${JIRA_PROFILE}${RESET}"
cat "${JIRA_PROFILE}" | sed 's/^/    /'
echo ""

press_enter

step "Admin adds the profile via governance-profile.sh create:"
echo ""
NS="${NS}" SAW_NAME="${SAW_NAME}" SSH_KEY="${SSH_KEY}" \
  "${SCRIPT_DIR}/governance-profile.sh" create jira "${JIRA_PROFILE}"
rm -f "${JIRA_PROFILE}"
echo ""

step "Profile registry now shows Jira:"
echo ""
NS="${NS}" SAW_NAME="${SAW_NAME}" "${SCRIPT_DIR}/governance-profile.sh" list
echo ""

press_enter

step "Creating a Jira provider (now allowed):"
echo ""
gw provider create --name demo-jira --type jira --credential JIRA_TOKEN=demo-token || true
echo ""

press_enter

# --- 9. Remove the Jira profile ---
banner "9. Removing Jira Profile"

step "Admin removes Jira access:"
echo ""
NS="${NS}" SAW_NAME="${SAW_NAME}" SSH_KEY="${SSH_KEY}" \
  "${SCRIPT_DIR}/governance-profile.sh" remove jira
echo ""

step "Jira provider creation blocked again:"
echo ""
gw provider create --name demo-jira-blocked --type jira --credential JIRA_TOKEN=demo-token || true
echo ""

press_enter

# --- 10. Cleanup ---
banner "10. Cleanup"

for p in demo-vertex demo-github demo-vertex-ok demo-github-restored demo-jira demo-jira-blocked; do
  gw provider delete "${p}" > /dev/null 2>&1 || true
done

# Remove jira profile file from git (step 9 only removes from values.yaml)
if [[ -f "${PROFILES_DIR}/jira.yaml" ]]; then
  rm -f "${PROFILES_DIR}/jira.yaml"
  git -C "${REPO_DIR}" add -A > /dev/null 2>&1
  git -C "${REPO_DIR}" commit -m "demo: remove jira profile file" --no-verify > /dev/null 2>&1
  git -C "${REPO_DIR}" push origin HEAD --no-verify > /dev/null 2>&1
fi
echo -e "${GREEN}  Demo providers and jira profile cleaned up.${RESET}"
echo ""

banner "Demo Complete"

echo -e "Summary:"
echo -e "  ${GREEN}✓${RESET} Governance interceptor deployed as a Kubernetes pod (ArgoCD)"
echo -e "  ${GREEN}✓${RESET} VM gateway connects to interceptor over pod network (HTTP/2)"
echo -e "  ${GREEN}✓${RESET} Governed providers (google-vertex-ai, github) — ${GREEN}allowed${RESET}"
echo -e "  ${RED}✗${RESET} Ungoverned providers (custom, claude-code) — ${RED}blocked${RESET}"
echo -e "  ${YELLOW}!${RESET} Revoked profile (github removed) — ${RED}blocked until restored${RESET}"
echo -e "  ${GREEN}✓${RESET} New profile added (jira) — ${GREEN}allowed after GitOps sync${RESET}"
echo -e "  ${GREEN}✓${RESET} Profile registry tracks available vs active"
echo -e "  ${GREEN}✓${RESET} Signed policy injected into sandbox creation (patch_count=2)"
echo -e "  ${GREEN}✓${RESET} Full audit trail in gateway logs"
echo ""
