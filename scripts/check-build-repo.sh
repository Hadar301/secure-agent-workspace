#!/usr/bin/env bash
# CI owns the upstream namespace; manual builds may publish only elsewhere.
set -euo pipefail
repo="${1:-}"
normalized="$(printf '%s' "$repo" | tr '[:upper:]' '[:lower:]')"
case "$normalized" in
  ghcr.io/validatedpatterns-sandbox|ghcr.io/validatedpatterns-sandbox/*)
    echo "Error: the upstream GHCR namespace is reserved for CI. Set IMAGE_REPO to your own namespace, or omit it to keep the build in-cluster." >&2
    exit 1
    ;;
esac
