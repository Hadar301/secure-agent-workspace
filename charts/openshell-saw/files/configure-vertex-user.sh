#!/usr/bin/env bash
set -euo pipefail

SA_JSON="${SA_JSON:?}"
PROVIDER_NAME="${PROVIDER_NAME:?}"
REGION="${VERTEX_AI_REGION:-global}"
MODEL="${VERTEX_MODEL:-claude-sonnet-4-6}"
GATEWAY_NAME="${OPENSHELL_GATEWAY:-openshell}"

test -r "${SA_JSON}"
PROJECT_ID="$(jq -r '.project_id // empty' "${SA_JSON}")"
CLIENT_EMAIL="$(jq -r '.client_email // empty' "${SA_JSON}")"
PRIVATE_KEY="$(jq -r '.private_key // empty' "${SA_JSON}")"

if [[ -z "${PRIVATE_KEY}" || "${PRIVATE_KEY}" == "null" || -z "${CLIENT_EMAIL}" || "${CLIENT_EMAIL}" == "null" ]]; then
  echo "vertex_skip incomplete SA JSON (missing private_key/client_email); continuing without Vertex"
  exit 0
fi

openshell gateway use "${GATEWAY_NAME}" 2>/dev/null || true
openshell settings set --global --key providers_v2_enabled --value true --yes

if openshell provider get "${PROVIDER_NAME}" >/dev/null 2>&1; then
  openshell provider update "${PROVIDER_NAME}" \
    --config "VERTEX_AI_PROJECT_ID=${PROJECT_ID}" \
    --config "VERTEX_AI_REGION=${REGION}"
else
  openshell provider create \
    --name "${PROVIDER_NAME}" \
    --type google-vertex-ai \
    --credential "GOOGLE_SERVICE_ACCOUNT_KEY=$(cat "${SA_JSON}")" \
    --config "VERTEX_AI_PROJECT_ID=${PROJECT_ID}" \
    --config "VERTEX_AI_REGION=${REGION}"
fi

openshell provider refresh configure "${PROVIDER_NAME}" \
  --credential-key GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN \
  --strategy google-service-account-jwt \
  --material "client_email=${CLIENT_EMAIL}" \
  --material "private_key=${PRIVATE_KEY}" \
  --secret-material-key private_key

ok=0
for _ in $(seq 1 36); do
  if openshell provider refresh status "${PROVIDER_NAME}" --credential-key GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN 2>/dev/null \
    | grep -qiE '[[:space:]]refreshed[[:space:]]'; then
    ok=1
    break
  fi
  sleep 5
done
[[ "${ok}" -eq 1 ]]

openshell inference set --provider "${PROVIDER_NAME}" --model "${MODEL}" --no-verify
echo "vertex_ok provider=${PROVIDER_NAME} region=${REGION} model=${MODEL}"
