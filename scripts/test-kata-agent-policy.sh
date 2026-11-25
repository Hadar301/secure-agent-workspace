#!/usr/bin/env bash
set -euo pipefail

if ! command -v opa; then
  printf '%s\n' 'OPA CLI is required to run the Kata Agent policy tests.' >&2
  exit 127
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/saw-kata-policy.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

sed 's/__SAW_IDENTITY_JSON__/{"test":"synthetic"}/g' \
  deploy/confidential/kata-agent-policy.rego \
  > "$tmp_dir/kata-agent-policy.rego"

opa check --strict "$tmp_dir/kata-agent-policy.rego"
opa test --fail-on-empty \
  "$tmp_dir/kata-agent-policy.rego" \
  deploy/confidential/kata-agent-policy_test.rego
