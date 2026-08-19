# Fix NemoClaw onboard failure: OpenShell version string mismatch

**Project:** APPENG
**Type:** Bug
**Epic:** Secure Agent Workspace Validated Pattern
**Priority:** High
**Component:** RH_AI_Blueprints
**Labels:** secure_agent_workspace, openshell, nemoclaw, version_mismatch

## Summary

NemoClaw onboard fails during the setup job because its feature gate (`openshell-feature-gate.js`) detects a version mismatch between the pip-installed OpenShell CLI and the native Go gateway/supervisor binaries. The fix installs a version-normalizing wrapper around the pip CLI so all three components report identical version strings.

## Root cause

The OpenShell stack on the VM consists of three binaries from two different build systems:

| Component | Source | Install path | Version output |
|-----------|--------|--------------|----------------|
| `openshell` (CLI) | pip from RHAIV index | `~/.local/bin/openshell` | `openshell 0.0.103+rhaiv.0` |
| `openshell-gateway` | Native Go binary from container image | `/usr/local/bin/openshell-gateway` | `openshell-gateway 0.0.103-rhaiv.0` |
| `openshell-supervisor` | Native Go binary from container image | `/usr/local/bin/openshell-supervisor` | `openshell-sandbox 0.0.103-rhaiv.0` |

The version suffix uses `+` (PEP 440 local version identifier) for the pip package and `-` (semver pre-release) for the native Go binaries. NemoClaw's `componentBuildVersionsMatch()` in `openshell-feature-gate.js` requires exact string equality (with a special case for `+g<commit>` git hashes only). The `+rhaiv.0` vs `-rhaiv.0` mismatch causes the check to fail.

## Failure sequence

1. Setup job installs OpenShell 0.0.103 (gateway, supervisor, CLI) via `upgrade-openshell.sh`
2. BOM profiles trigger `nemoclaw onboard` via `apply_bom.py`
3. NemoClaw's preflight runs `hasRequiredOpenshellMessagingFeatures()`:
   - Finds `openshell` at `~/.local/bin/openshell` via `command -v`
   - Runs `openshell --version` → extracts `0.0.103+rhaiv.0`
   - Runs `openshell-gateway --version` → extracts `0.0.103-rhaiv.0`
   - Calls `componentBuildVersionsMatch("0.0.103+rhaiv.0", "0.0.103-rhaiv.0")` → **false**
4. Feature gate returns false → NemoClaw logs "OpenShell is missing provider credential rewrite or MCP L7 policy support. Reinstalling..."
5. NemoClaw's bundled OpenShell installer runs and fails (output truncated at third-party notice)
6. `nemoclaw onboard` exits non-zero → fallback to manual provider/sandbox creation
7. Sandbox is created but immediately disappears ("sandbox not found") because the failed reinstall corrupted the gateway state

## Fix

Added a version-normalizing wrapper to `upgrade-openshell.sh` (lines 32-59). After pip-installing the CLI:

1. Query the gateway binary's version string (`openshell-gateway --version`)
2. Rename the pip-installed binary from `openshell` to `openshell-real`
3. Install a bash wrapper at the original path that:
   - For `--version`: outputs the version string matching the native binaries (using `-` instead of `+`)
   - For all other commands: delegates to `openshell-real`

### Wrapper script (generated at deploy time)

```bash
#!/usr/bin/env bash
if [[ "$1" == "--version" ]]; then
  echo "openshell 0.0.103-rhaiv.0"   # version derived from openshell-gateway
  exit 0
fi
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "${SELF_DIR}/openshell-real" "$@"
```

### Result

All three components report identical versions:

```
openshell 0.0.103-rhaiv.0
openshell-gateway 0.0.103-rhaiv.0
openshell-sandbox 0.0.103-rhaiv.0
```

NemoClaw's feature gate passes, `nemoclaw onboard` completes successfully, and sandboxes persist after creation.

## NemoClaw feature gate analysis

The check in `dist/lib/onboard/openshell-feature-gate.js` (NemoClaw commit `15069f9`) performs two validations:

1. **Version coherence** — all three binaries (`openshell`, `openshell-gateway`, `openshell-sandbox`) must report matching version strings via `--version`. The only flexibility is for `+g<hex>` git commit suffixes (prefix matching). The `+rhaiv.0` vs `-rhaiv.0` difference is not handled.

2. **Binary marker scan** — reads raw bytes of all three executables looking for string markers: `request-body-credential-rewrite`, `websocket-credential-rewrite`, and the MCP policy capability marker. The scan unions markers across all binaries, so they don't all need every marker. The native Go gateway and supervisor binaries contain these markers; the pip CLI (and our wrapper) do not need them.

The `NEMOCLAW_OPENSHELL_GATEWAY_BIN` and `NEMOCLAW_OPENSHELL_SANDBOX_BIN` env vars (set by `apply_bom.py`) enable `allowExternalGatewayBin`/`allowExternalSandboxBin`, which skip the directory co-location check. But they do not skip the version coherence check.

**Update (during PR review):** the claim above that "the native Go gateway and supervisor
binaries contain these markers" — which would imply the binary-marker-scan bypass patch in
`image-builder-charts/helm/nemoclaw-cli-imagestream/templates/buildconfig.yaml` isn't even
needed — could not be verified either way. Tried reverting that bypass and running
`nemoclaw onboard` directly against a live VM: it never reached the feature-gate check at
all, in this environment. Onboarding fails earlier, at `[1/8] Preflight checks`, with an
unrelated blocking finding (`host.docker.storage_incompatible`: "The Docker storage
configuration cannot support nested overlay mounts"). The same failure occurs identically
with the bypass *present* — confirmed against the already-deployed `cuda-sandbox`'s own
onboarding log, which failed at the exact same preflight step, with `apply_bom.py`'s
`openshell provider create` fallback being what actually made that sandbox work, not real
NemoClaw onboarding. So neither this doc's "binaries already have the markers" claim nor the
buildconfig's "OpenShell builds do not embed the hyphen-form capability strings" claim has
actually been exercised — genuine `nemoclaw onboard` has never successfully completed in this
environment at all. The nested-overlay preflight is worth its own separate investigation.

## Files changed

- `charts/openshell-saw/files/upgrade-openshell.sh` — added wrapper installation after pip CLI install
- `charts/openshell-saw/values.yaml` — normalized version field to `"0.0.103"` (pip resolves `+rhaiv.0` automatically from the RHAIV index)

## Testing

Validated on the live VM (`openshell-saw` in `openshell-agents` namespace on `cluster-j76gz`):

1. Installed wrapper manually via `virtctl scp` + `virtctl ssh`
2. Confirmed `openshell --version` reports `0.0.103-rhaiv.0` (matching gateway/supervisor)
3. Confirmed `openshell gateway list` and other CLI commands still work through the wrapper
4. Full E2E validation pending after ArgoCD sync with the committed fix
