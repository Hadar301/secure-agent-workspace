#!/usr/bin/env bash
# Live E2E for the SAW-BOM harness bundle (PR #53 follow-up).
#
# Verifies, against a real gateway VM, what the offline installer tests
# (make test-installer) can only model with fakes:
#   H1  bundle mounted read-only at /sandbox/harness
#   H2  volume content == applied source (audit: status.json appliedRevision)
#   H3  OpenClaw loads the bundle (MCP servers, plugins, skills)
#   H4  OpenClaw harness config points at the mount (no drift)
#   H5  no literal secrets in the mounted bundle (placeholders only)
#   H6  governance: live catalog serves the profile, host in its endpoints,
#       sandbox has a provider of that type
#   H7  cosign signature (image refs only; inline refs report SKIP)
#   H8  audit: volume admission labels present
#   H9  revocation drill (opt-in --revoke-drill): harnessEnabled=false ->
#       sandbox recreated without the mount, then harnessEnabled=true ->
#       mount back. Executed, not printed.
#
# Read-only by default: H1-H8 change nothing. H9 upgrades the saw-bom release
# twice, restarts the VM twice when vm.liveInputs is off, and recreates the
# sandbox (agent work outside /sandbox/persist is lost, like any pod restart).
# It restores harnessEnabled=true on exit, including on ^C.
#
# Platform gaps from the PR review are OUT OF SCOPE here and tracked
# separately (upstream OpenShell, not this repo's installer):
#   - default-deny egress outside the VM
#   - tool actions tied to task/permissions + approval for consequential ones
#   - provider/admin keys protected from VM-root
#   - policy-update propagation to running workspaces
#   - in-cluster MCP Service reachability (L7 403 is the sandbox net policy)
#
# Prerequisites:
#   - oc logged in; openshell CLI installed and gateway selected
#   - a SAW deployed with harnessEnabled=true + allowDriverConfig=true, e.g.
#       helm upgrade --install <saw> charts/openshell-saw ... \
#         --set allowDriverConfig=true
#       helm upgrade --install saw-bom charts/saw-bom ... \
#         --set harnessEnabled=true
#
# Usage:
#   ./scripts/e2e-harness.sh [--gateway NAME] [--workspace WS]
#                            [--sandbox SB] [--bundle B]
#                            [--revoke-drill [--bom-release NAME]]
#   make test-harness-e2e OPENSHELL_SAW_NAME=my-saw [--revoke-drill via E2E_ARGS]

set -euo pipefail

GATEWAY="${OPENSHELL_SAW_NAME:-}"
WORKSPACE="${WORKSPACE:-default}"
SANDBOX="${HARNESS_SANDBOX:-notebook}"
BUNDLE="${HARNESS_BUNDLE_EXPECT:-ds-default}"
REVOKE_DRILL="no"
BOM_RELEASE="${BOM_RELEASE:-saw-bom}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gateway)   GATEWAY="$2"; shift 2 ;;
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --sandbox)   SANDBOX="$2"; shift 2 ;;
    --bundle)    BUNDLE="$2"; shift 2 ;;
    --revoke-drill) REVOKE_DRILL="yes"; shift ;;
    --bom-release)  BOM_RELEASE="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,32p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1 (see --help)"; exit 2 ;;
  esac
done

if [[ -z "${GATEWAY}" ]]; then
  echo "Error: set OPENSHELL_SAW_NAME or pass --gateway NAME."
  exit 2
fi

GW=(openshell --gateway "${GATEWAY}")
SB=(openshell --gateway "${GATEWAY}" sandbox exec -n "${SANDBOX}" --workspace "${WORKSPACE}" --no-tty --)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
FAIL=0; SKIPPED=0

step()  { echo -e "\n${CYAN}=== $1 ===${NC}"; }
pass()  { echo -e "  ${GREEN}PASS${NC} $1"; }
fail()  { echo -e "  ${RED}FAIL${NC} $1"; FAIL=1; }
skip()  { echo -e "  ${YELLOW}SKIP${NC} $1"; SKIPPED=$((SKIPPED+1)); }
check() { # check <label> -- <cmd...>: PASS when cmd exits 0
  local label="$1"; shift
  [[ "${1:-}" == "--" ]] && shift
  if "$@" >/tmp/e2e-harness-out 2>&1; then pass "${label}"; else fail "${label}"; sed 's/^/    /' /tmp/e2e-harness-out; fi
}

sb_exec() { "${SB[@]}" "$@"; }

step "Pre-flight"
check "openshell CLI present" -- command -v openshell
check "gateway '${GATEWAY}' reachable" -- "${GW[@]}" sandbox list --workspace "${WORKSPACE}"
check "sandbox '${SANDBOX}' exists" -- \
  bash -c "openshell --gateway '${GATEWAY}' sandbox list --workspace '${WORKSPACE}' | grep -q '^${SANDBOX} '"

# Which source did the installer apply? status.json lives on the VM
# (root-owned); read it over vm-ssh when available, else report and continue.
step "Audit source (status.json appliedRevision)"
STATUS_JSON=""
if command -v virtctl >/dev/null 2>&1; then
  SAW_NS="${SAW_NS:-saw-${GATEWAY}}"
  SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.generated-ssh-keys/sandbox-ssh}"
  STATUS_JSON=$(virtctl -n "${SAW_NS}" ssh "cloud-user@vm/${GATEWAY}" \
    --identity-file="${SSH_KEY_PATH}" \
    --local-ssh-opts=-oStrictHostKeyChecking=no \
    --local-ssh-opts=-oUserKnownHostsFile=/dev/null \
    --command="sudo cat /var/lib/saw/status.json" 2>/dev/null || true)
fi
if [[ -n "${STATUS_JSON}" ]]; then
  echo "${STATUS_JSON}" | python3 -c "
import json,sys
d = json.load(sys.stdin)
rev = (d.get('apply') or {}).get('appliedRevision', {})
print('  appliedRevision:', json.dumps(rev))
" || fail "status.json parses as JSON"
  if echo "${STATUS_JSON}" | grep -q "${SANDBOX}"; then
    pass "status.json records sandbox '${SANDBOX}'"
  else
    fail "status.json has no entry for sandbox '${SANDBOX}'"
  fi
else
  skip "status.json not reachable (needs virtctl + vm-ssh); H2 compares mount content only"
fi

step "H1: read-only mount at /sandbox/harness"
check "mountpoint exists" -- sb_exec test -d /sandbox/harness
MOUNT_LINE=$(sb_exec mount 2>/dev/null | grep -F "/sandbox/harness" || true)
if [[ -z "${MOUNT_LINE}" ]]; then
  skip "mount table not readable here; RO proven by refused write below"
else
  echo "  ${MOUNT_LINE}"
  if echo "${MOUNT_LINE}" | grep -q "ro[, ]"; then pass "mounted read-only"; else fail "mount is not read-only"; fi
fi
# A write through the mount must be refused (proves RO end to end).
if sb_exec sh -c 'touch /sandbox/harness/.w 2>/dev/null' 2>/dev/null; then
  fail "write to /sandbox/harness succeeded (should be refused)"
  sb_exec sh -c 'rm -f /sandbox/harness/.w 2>/dev/null' 2>/dev/null || true
else
  pass "write to /sandbox/harness refused"
fi

step "H2: mounted content is the bundle"
check "plugin.json present" -- sb_exec test -f /sandbox/harness/plugin.json
check "mcp.json present" -- sb_exec test -f /sandbox/harness/mcp.json
check "skills dir present" -- sb_exec test -d /sandbox/harness/skills
check "revision marker present" -- sb_exec test -f /sandbox/harness/.saw-harness-revision
if [[ -n "${STATUS_JSON}" ]]; then
  MARKER_SRC=$(sb_exec cat /sandbox/harness/.saw-harness-revision 2>/dev/null || true)
  echo "  marker: ${MARKER_SRC}"
  # Compare bundle name + digest hex loosely: the marker names the source
  # (e.g. bundle:ds-default@sha256:…) while appliedRevision pins name@digest.
  MARKER_DIGEST=$(echo "${MARKER_SRC}" | python3 -c "import json,sys,re; m=re.search(r'[0-9a-f]{64}', sys.stdin.read()); print(m.group(0) if m else '')" 2>/dev/null)
  SANDBOX_REV=$(echo "${STATUS_JSON}" | python3 -c "import json,sys; print((json.load(sys.stdin).get('apply') or {}).get('appliedRevision', {}).get('${SANDBOX}',''))" 2>/dev/null)
  echo "  appliedRevision[${SANDBOX}]: ${SANDBOX_REV}"
  if [[ -n "${MARKER_DIGEST}" && -n "${SANDBOX_REV}" ]] && echo "${SANDBOX_REV}" | grep -q "${MARKER_DIGEST}"; then
    pass "marker digest matches appliedRevision"
  else
    fail "marker digest not found in appliedRevision (drift?)"
  fi
fi

step "H3: OpenClaw loads the bundle"
# `mcp list` never shows bundle servers; check `plugins list --json` instead.
PLUGINS_JSON=$(sb_exec sh -c 'OPENCLAW_HOME=/sandbox openclaw plugins list --json' 2>/dev/null || true)
if [[ -z "${PLUGINS_JSON}" ]]; then
  fail "openclaw plugins list --json returned nothing"
else
  # Same bar as the installer's verify: mount row loaded, caps covering the
  # mounted tree, every native plugin id enabled.
  NEED_CAPS=""
  sb_exec test -f /sandbox/harness/mcp.json >/dev/null 2>&1 && NEED_CAPS="mcpServers"
  sb_exec test -d /sandbox/harness/skills >/dev/null 2>&1 && NEED_CAPS="${NEED_CAPS} skills"
  NEED_PLUGINS=$(sb_exec ls /sandbox/harness/plugins 2>/dev/null || true)
  echo "${PLUGINS_JSON}" | NEED_CAPS="${NEED_CAPS}" NEED_PLUGINS="${NEED_PLUGINS}" python3 -c "
import json, os, sys
plugins = json.load(sys.stdin).get('plugins') or []
rows = [p for p in plugins if isinstance(p, dict)]
bundle = next((p for p in rows if p.get('format') == 'bundle'
               and p.get('rootDir') == '/sandbox/harness'), None)
assert bundle and bundle.get('enabled') and bundle.get('status') == 'loaded', 'bundle row not loaded'
caps = set(bundle.get('bundleCapabilities') or [])
if caps:
    missing = sorted(set(os.environ['NEED_CAPS'].split()) - caps)
    assert not missing, f'bundle lacks capabilities: {missing}'
by_id = {p.get('id') or p.get('name'): p for p in rows}
missing = [p for p in os.environ['NEED_PLUGINS'].split()
           if not by_id.get(p, {}).get('enabled', False)]
assert not missing, f'plugins not enabled: {missing}'
print('  bundle:', bundle.get('id'), '| caps:', ','.join(sorted(caps)) or '<unreported>')
print('  enabled plugins:', ' '.join(sorted(by_id)) or '<none>')
" && pass "bundle row loaded from /sandbox/harness (caps + plugins match)" \
    || fail "bundle row missing/disabled/capability-short in plugins list --json"
fi

# The bundle row says there ARE MCP servers, never which ones; `mcp status`
# names them, so a server OpenClaw dropped shows up only here.
MCP_DECLARED=$(sb_exec sh -c 'cat /sandbox/harness/mcp.json' 2>/dev/null \
  | python3 -c "import json,sys; print(' '.join(sorted((json.load(sys.stdin).get('mcpServers') or {}))))" 2>/dev/null || true)
if [[ -z "${MCP_DECLARED}" ]]; then
  skip "bundle declares no MCP servers"
else
  MCP_STATUS=$(sb_exec sh -c 'OPENCLAW_HOME=/sandbox openclaw mcp status' 2>/dev/null || true)
  if [[ -z "${MCP_STATUS}" ]]; then
    skip "sandbox does not answer 'openclaw mcp status'"
  else
    for s in ${MCP_DECLARED}; do
      if echo "${MCP_STATUS}" | grep -qw "$s"; then pass "MCP server '$s' listed"; else fail "MCP server '$s' missing from mcp status"; fi
    done
  fi
fi

step "H4: OpenClaw harness config points at the mount"
PATHS=$(sb_exec sh -c 'openclaw config get plugins.load.paths' 2>/dev/null || true)
if echo "${PATHS}" | grep -q "/sandbox/harness"; then
  pass "plugins.load.paths includes /sandbox/harness"
else
  fail "plugins.load.paths missing /sandbox/harness (got: ${PATHS:-<unset>})"
fi

step "H5: no literal secrets in the mounted bundle"
# Placeholders (${VAR} / Bearer ${VAR}) are the only allowed secret shape.
if sb_exec sh -c 'grep -rniE "api[_-]?key|bearer [A-Za-z0-9._-]{16,}|sk-[A-Za-z0-9]{16,}" /sandbox/harness/mcp.json' \
    2>/dev/null | grep -v '\${' >/dev/null; then
  fail "literal secret pattern found in mounted mcp.json"
else
  pass "mounted mcp.json holds no literal secrets"
fi

step "H6: governance against the live catalog"
CATALOG=$("${GW[@]}" provider list-profiles --workspace "${WORKSPACE}" -o json 2>/dev/null || true)
if [[ -z "${CATALOG}" ]]; then
  fail "provider list-profiles returned nothing"
else
  echo "${CATALOG}" | python3 -c "import json,sys; print('  profiles:', sorted(p['id'] for p in json.load(sys.stdin)))" \
    || fail "catalog is not JSON"
  # Every governanceProfile named by the bundle must be served...
  PROFILES_NEEDED=$(sb_exec sh -c 'cat /sandbox/harness/harness.yaml' 2>/dev/null \
    | python3 -c "import sys,yaml; d=yaml.safe_load(sys.stdin); got=set(); [got.add(x.get('governanceProfile')) for k in ('mcpServers','plugins') for x in (d.get('spec') or {}).get(k) or [] if x.get('governanceProfile')]; print(' '.join(sorted(got)))" 2>/dev/null || true)
  echo "  bundle needs profiles: ${PROFILES_NEEDED:-<none declared>}"
  for p in ${PROFILES_NEEDED:-}; do
    if echo "${CATALOG}" | grep -q "\"id\": *\"$p\""; then pass "catalog serves '${p}'"; else fail "catalog does not serve '${p}'"; fi
  done
  # ...and the sandbox must hold a provider of each type.
  ATTACHED=$("${GW[@]}" sandbox provider list "${SANDBOX}" --workspace "${WORKSPACE}" 2>/dev/null || true)
  for p in ${PROFILES_NEEDED:-}; do
    if echo "${ATTACHED}" | grep -qw "$p"; then pass "sandbox has provider '${p}'"; else fail "sandbox lacks provider '${p}'"; fi
  done
fi

step "H7: cosign (image refs only)"
HREF_KIND=""
if [[ -n "${STATUS_JSON}" ]]; then
  HREF_KIND=$(echo "${STATUS_JSON}" | python3 -c "
import json,sys
rev = (json.load(sys.stdin).get('apply') or {}).get('appliedRevision', {})
v = rev.get('${SANDBOX}','')
print('image' if '/' in v.split('@')[0] else 'inline')" 2>/dev/null || true)
fi
if [[ "${HREF_KIND}" == "image" ]]; then
  if ! command -v cosign >/dev/null 2>&1; then
    skip "cosign not installed; installer verified at apply time (see status)"
  elif [[ -z "${HARNESS_COSIGN_IDENTITY:-}" || -z "${HARNESS_COSIGN_ISSUER:-}" ]]; then
    skip "HARNESS_COSIGN_IDENTITY/HARNESS_COSIGN_ISSUER not set (same values as the SAW's harness.cosign.identity/.issuer); keyless cosign refuses without them"
  else
    check "cosign verifies the applied image" -- bash -c "echo '${STATUS_JSON}' | python3 -c \"import json,sys; print((json.load(sys.stdin).get('apply') or {}).get('appliedRevision',{}).get('${SANDBOX}',''))\" | xargs -I{} cosign verify --certificate-identity '${HARNESS_COSIGN_IDENTITY}' --certificate-oidc-issuer '${HARNESS_COSIGN_ISSUER}' {}"
  fi
else
  skip "inline ConfigMap bundle: no image signature to verify (installer enforces digest when pinned)"
fi

step "H8: audit labels on the harness volume"
if [[ -n "${STATUS_JSON}" ]] && command -v virtctl >/dev/null 2>&1; then
  SAW_NS="${SAW_NS:-saw-${GATEWAY}}"
  SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.generated-ssh-keys/sandbox-ssh}"
  LABELS=$(virtctl -n "${SAW_NS}" ssh "cloud-user@vm/${GATEWAY}" \
    --identity-file="${SSH_KEY_PATH}" \
    --local-ssh-opts=-oStrictHostKeyChecking=no \
    --local-ssh-opts=-oUserKnownHostsFile=/dev/null \
    --command="podman volume inspect saw-harness-${WORKSPACE}-${SANDBOX}-* --format '{{.Labels}}' 2>/dev/null" 2>/dev/null || true)
  if echo "${LABELS}" | grep -q "sandbox-attachable"; then
    pass "harness volume carries admission labels"
  else
    skip "volume labels not reachable from here (installer sets openshell.ai/sandbox-attachable*)"
  fi
else
  skip "volume labels need vm-ssh; covered offline by test_harness_mount.py"
fi

if [[ "${REVOKE_DRILL}" == "yes" ]]; then
  step "H9: revocation drill (DESTRUCTIVE: recreates '${SANDBOX}')"
  SAW_NS="${SAW_NS:-saw-${GATEWAY}}"
  BOM_RELEASE="${BOM_RELEASE:-saw-bom}"
  BOM_CHART="$(cd "$(dirname "$0")/.." && pwd)/charts/saw-bom"
  # An apply + recreate can take minutes; poll rather than guess a sleep.
  DRILL_TIMEOUT="${DRILL_TIMEOUT:-1500}"

  # The BOM reaches the VM over virtiofs only with vm.liveInputs; otherwise it
  # is an iso9660 disk KubeVirt re-renders on VM start, so the drill restarts
  # the VM after each helm upgrade.
  LIVE_INPUTS="no"
  if oc -n "${SAW_NS}" get vm "${GATEWAY}" \
      -o jsonpath='{.spec.template.spec.domain.devices.filesystems[*].name}' 2>/dev/null \
      | grep -q saw-profiles; then
    LIVE_INPUTS="yes"
  fi

  set_harness() { # set_harness true|false
    helm upgrade "${BOM_RELEASE}" "${BOM_CHART}" -n "${SAW_NS}" \
      --reuse-values --set "harnessEnabled=$1" >/dev/null
    if [[ "${LIVE_INPUTS}" != "yes" ]]; then
      virtctl restart -n "${SAW_NS}" "${GATEWAY}" >/dev/null
    fi
  }
  # want=gone: the sandbox must come back without /sandbox/harness.
  # want=present: it must come back with it. An unreachable gateway or a
  # missing sandbox is "not yet" in both directions, since the VM is
  # restarting and the installer is recreating the sandbox underneath.
  wait_mount() { # wait_mount gone|present
    local want="$1" deadline=$((SECONDS + DRILL_TIMEOUT)) have
    while [[ "${SECONDS}" -lt "${deadline}" ]]; do
      sleep 15
      "${GW[@]}" sandbox list --workspace "${WORKSPACE}" >/dev/null 2>&1 || continue
      sb_exec true >/dev/null 2>&1 || continue
      if sb_exec test -d /sandbox/harness >/dev/null 2>&1; then have=present; else have=gone; fi
      if [[ "${have}" == "${want}" ]]; then
        local paths
        paths=$(sb_exec sh -c 'openclaw config get plugins.load.paths' 2>/dev/null || true)
        if [[ "${want}" == "gone" ]] && echo "${paths}" | grep -q "/sandbox/harness"; then continue; fi
        if [[ "${want}" == "present" ]] && ! echo "${paths}" | grep -q "/sandbox/harness"; then continue; fi
        return 0
      fi
    done
    return 1
  }

  if ! command -v helm >/dev/null 2>&1 || ! command -v oc >/dev/null 2>&1; then
    skip "revocation drill needs helm and oc on PATH"
  elif [[ "${LIVE_INPUTS}" != "yes" ]] && ! command -v virtctl >/dev/null 2>&1; then
    skip "revocation drill needs virtctl (vm.liveInputs is off, so the BOM disk only changes on VM restart)"
  elif ! helm status "${BOM_RELEASE}" -n "${SAW_NS}" >/dev/null 2>&1; then
    skip "no helm release '${BOM_RELEASE}' in ${SAW_NS} (pass --bom-release NAME)"
  else
    echo "  revoking: helm upgrade ${BOM_RELEASE} --set harnessEnabled=false (ns ${SAW_NS}, liveInputs=${LIVE_INPUTS})"
    # Always put the harness back, including on ^C or a failed assert.
    # shellcheck disable=SC2064
    trap "echo 'restoring harnessEnabled=true'; set_harness true || true; trap - EXIT INT TERM" EXIT INT TERM
    set_harness false
    if wait_mount gone; then
      pass "harness revoked: sandbox recreated without /sandbox/harness, plugins.load.paths clean"
    else
      fail "harness still mounted or plugins.load.paths stale after revoke (timeout ${DRILL_TIMEOUT}s)"
    fi
    echo "  restoring: helm upgrade ${BOM_RELEASE} --set harnessEnabled=true"
    set_harness true
    if wait_mount present; then
      pass "harness restored: sandbox recreated with /sandbox/harness, plugins.load.paths set"
    else
      fail "harness not restored after re-enabling (timeout ${DRILL_TIMEOUT}s)"
    fi
    trap - EXIT INT TERM
  fi
fi

echo ""
echo "============================================="
if [[ "${FAIL}" -eq 0 ]]; then
  echo -e " HARNESS E2E ${GREEN}PASSED${NC} (skipped: ${SKIPPED})"
else
  echo -e " HARNESS E2E ${RED}FAILED${NC} (skipped: ${SKIPPED})"
fi
echo "============================================="
exit "${FAIL}"
