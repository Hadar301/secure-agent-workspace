#!/usr/bin/env bash
set -euo pipefail

: "${SUPERVISOR_IMAGE:?set SUPERVISOR_IMAGE to the pinned OpenShell supervisor image}"
: "${GO_BUILDER_IMAGE:?set GO_BUILDER_IMAGE to a pinned Go builder image}"
: "${CONFIDENTIAL_SUPERVISOR_TAG:?set CONFIDENTIAL_SUPERVISOR_TAG to the local output tag}"

PLATFORM="${PLATFORM:-linux/amd64}"
case "$PLATFORM" in
    linux/amd64|linux/arm64) ;;
    *) printf '%s\n' 'PLATFORM must be linux/amd64 or linux/arm64.' >&2; exit 1 ;;
esac

for image in "$SUPERVISOR_IMAGE" "$GO_BUILDER_IMAGE"; do
    if [[ ! "$image" =~ @sha256:[a-f0-9]{64}$ ]]; then
        printf '%s\n' 'Both base images must use sha256 digests.' >&2
        exit 1
    fi
done

command -v podman >/dev/null
podman build \
    --platform "$PLATFORM" \
    --file credential-proxy/Containerfile.confidential-supervisor \
    --build-arg "SUPERVISOR_IMAGE=$SUPERVISOR_IMAGE" \
    --build-arg "GO_BUILDER_IMAGE=$GO_BUILDER_IMAGE" \
    --tag "$CONFIDENTIAL_SUPERVISOR_TAG" \
    .
