#!/usr/bin/env bash
# Ensure the golden bootc image exists. Builds it if missing, waits for CDI import.
# Safe to re-run — picks up where it left off (running build, pending import, etc.)

set -euo pipefail

NS="${NS:-build-saw-images}"
HELM_DIR="${HELM_DIR:-image-builder-charts/helm}"

# Ensure the internal image registry has an external route
# (needed for VMs to pull sandbox images from the registry)
if ! oc get route default-route -n openshift-image-registry >/dev/null 2>&1; then
  echo "Enabling external image registry route..."
  oc patch configs.imageregistry.operator.openshift.io/cluster \
    --patch '{"spec":{"defaultRoute":true}}' --type=merge 2>/dev/null
  sleep 10
fi

# Check if CDI CRDs are available (requires OpenShift Virtualization / CNV)
CDI_AVAILABLE=true
if ! oc api-resources --api-group=cdi.kubevirt.io 2>/dev/null | grep -q datavolumes; then
  CDI_AVAILABLE=false
  echo "WARNING: CDI CRDs not available (OpenShift Virtualization not installed yet)."
  echo "  Will build the container image only. Golden image import will happen"
  echo "  after OpenShift Virtualization is installed (re-run this or let ArgoCD sync)."
fi

echo "=== Checking golden image in namespace '${NS}' ==="

HELM_GOLDEN_FLAG=""
if [[ "${CDI_AVAILABLE}" == "false" ]]; then
  HELM_GOLDEN_FLAG="--set goldenImage.enabled=false"
fi

# 1. Already ready?
if [[ "${CDI_AVAILABLE}" == "true" ]]; then
  DV_PHASE=$(oc get dv openshell-gateway-golden -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  if [[ "${DV_PHASE}" == "Succeeded" ]]; then
    echo "Golden image: ready"
    exit 0
  fi
fi

# 2. Build exists and running? Follow it.
BUILD_PHASE=$(oc get builds -n "${NS}" -l buildconfig=openshell-gateway \
  --sort-by='.metadata.creationTimestamp' -o jsonpath='{.items[-1].status.phase}' 2>/dev/null || true)

if [[ "${BUILD_PHASE}" == "Running" || "${BUILD_PHASE}" == "Pending" || "${BUILD_PHASE}" == "New" ]]; then
  BUILD_NAME=$(oc get builds -n "${NS}" -l buildconfig=openshell-gateway \
    --sort-by='.metadata.creationTimestamp' -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null || true)
  BUILD_AGE=$(oc get build "${BUILD_NAME}" -n "${NS}" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null || true)
  echo "Build '${BUILD_NAME}' already in progress (phase=${BUILD_PHASE}, started=${BUILD_AGE})."
  echo "  [Enter] to continue following it, or type 'restart' to cancel and rebuild: "
  if read -t 10 -r REPLY 2>/dev/null; then
    if [[ "${REPLY}" == "restart" ]]; then
      echo "  Cancelling build and starting fresh..."
      oc cancel-build "${BUILD_NAME}" -n "${NS}" 2>/dev/null || true
      oc delete build "${BUILD_NAME}" -n "${NS}" 2>/dev/null || true
      oc delete dv openshell-gateway-golden -n "${NS}" 2>/dev/null || true
      oc delete datasource openshell-gateway -n "${NS}" 2>/dev/null || true
      sleep 3
      echo "  Starting new build..."
      helm upgrade --install openshell-gateway-image "${HELM_DIR}/openshell-gateway-image" \
        --namespace "${NS}" --create-namespace ${HELM_GOLDEN_FLAG}
      oc start-build openshell-gateway -n "${NS}" 2>/dev/null || true
    fi
  fi
  echo "Following build logs..."
  oc logs -f "bc/openshell-gateway" -n "${NS}" 2>/dev/null || true

  # Wait briefly for build status to update after logs end
  for _ in $(seq 1 6); do
    BUILD_PHASE=$(oc get builds -n "${NS}" -l buildconfig=openshell-gateway \
      --sort-by='.metadata.creationTimestamp' -o jsonpath='{.items[-1].status.phase}' 2>/dev/null || true)
    if [[ "${BUILD_PHASE}" == "Complete" ]]; then break; fi
    sleep 5
  done
  if [[ "${BUILD_PHASE}" == "Complete" ]]; then
    echo "Build complete."
  else
    echo "ERROR: Build ${BUILD_PHASE:-unknown}"
    exit 1
  fi

elif [[ "${BUILD_PHASE}" == "Complete" ]]; then
  echo "Build already complete. Checking golden image import..."

else
  # 3. No build — start from scratch
  echo "Golden image: not found. Building bootc image..."

  # Create namespace if needed
  oc create namespace "${NS}" --dry-run=client -o yaml | oc apply -f - 2>/dev/null

  # Deploy BuildConfig + ImageStream (+ golden image DataVolume if CDI is available)
  echo "  Installing openshell-gateway-image chart..."
  helm upgrade --install openshell-gateway-image "${HELM_DIR}/openshell-gateway-image" \
    --namespace "${NS}" --create-namespace ${HELM_GOLDEN_FLAG}

  # Trigger build
  echo "  Starting build..."
  oc start-build openshell-gateway -n "${NS}" 2>/dev/null || true

  # Follow build logs
  echo "  Following build logs..."
  oc logs -f "bc/openshell-gateway" -n "${NS}" 2>/dev/null || true

  # Wait briefly for build status to update after logs end
  for _ in $(seq 1 6); do
    BUILD_PHASE=$(oc get builds -n "${NS}" -l buildconfig=openshell-gateway \
      --sort-by='.metadata.creationTimestamp' -o jsonpath='{.items[-1].status.phase}' 2>/dev/null || true)
    if [[ "${BUILD_PHASE}" == "Complete" ]]; then break; fi
    sleep 5
  done
  if [[ "${BUILD_PHASE}" != "Complete" ]]; then
    echo "  ERROR: Build ${BUILD_PHASE:-unknown}"
    exit 1
  fi
  echo "  Build complete."
fi

# 4. Wait for CDI golden image import (skip if CDI not available)
if [[ "${CDI_AVAILABLE}" == "false" ]]; then
  echo "Container image built. Golden image import deferred until OpenShift Virtualization is installed."
  echo "  Re-run 'make ensure-images' or 'make build-gateway-image' after CNV is ready."
  exit 0
fi

DV_PHASE=$(oc get dv openshell-gateway-golden -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
if [[ "${DV_PHASE}" == "Succeeded" ]]; then
  echo "Golden image: ready"
  exit 0
fi

echo "  Waiting for golden image CDI import..."
deadline=$((SECONDS + 600))
while true; do
  DV_PHASE=$(oc get dv openshell-gateway-golden -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  PROGRESS=$(oc get dv openshell-gateway-golden -n "${NS}" -o jsonpath='{.status.progress}' 2>/dev/null || true)
  echo "    DV phase=${DV_PHASE:-pending} progress=${PROGRESS:-N/A}"

  if [[ "${DV_PHASE}" == "Succeeded" ]]; then
    echo "Golden image: ready"
    exit 0
  fi
  if [[ "${DV_PHASE}" == "Failed" ]]; then
    echo "  ERROR: Golden image import failed"
    exit 1
  fi
  if (( SECONDS > deadline )); then
    echo "  WARNING: Golden image import not complete yet. It will finish in the background."
    exit 0
  fi
  sleep 15
done
