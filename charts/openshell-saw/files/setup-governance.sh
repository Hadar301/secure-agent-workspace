#!/usr/bin/env bash
set -euo pipefail

GOVERNANCE_IMAGE="${GOVERNANCE_IMAGE:?}"
GOVERNANCE_PORT="${GOVERNANCE_PORT:-18081}"

echo "Pulling governance interceptor image..."
docker pull "${GOVERNANCE_IMAGE}" 2>&1 | tail -1

echo "Creating governance policy and profiles..."
mkdir -p /tmp/governance/profiles

cat > /tmp/governance/policy.yaml << 'POLICY'
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  inference_api:
    name: inference-api
    endpoints:
      - host: inference.local
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/bin/curl
POLICY

cat > /tmp/governance/profiles/github.yaml << 'PROFILE'
display_name: GitHub
description: GitHub API
provider_type: custom
endpoints:
  - host: api.github.com
    port: 443
    protocol: rest
PROFILE

echo "Starting governance interceptor container..."
docker rm -f governance-interceptor 2>/dev/null || true
docker run -d --name governance-interceptor \
  --restart unless-stopped \
  --network host \
  -v /tmp/governance/policy.yaml:/config/policy.yaml:ro \
  -v /tmp/governance/profiles:/config/profiles:ro \
  "${GOVERNANCE_IMAGE}" \
  --listen "127.0.0.1:${GOVERNANCE_PORT}" \
  --policy /config/policy.yaml \
  --profiles /config/profiles

# Wait for interceptor to be ready
for i in $(seq 1 10); do
  if docker logs governance-interceptor 2>&1 | grep -q 'listening on'; then
    echo "governance interceptor ready on port ${GOVERNANCE_PORT}"
    exit 0
  fi
  echo "  waiting for interceptor... (attempt $i)"
  sleep 3
done

echo "ERROR: governance interceptor failed to start" >&2
docker logs governance-interceptor 2>&1 | tail -5
exit 1
