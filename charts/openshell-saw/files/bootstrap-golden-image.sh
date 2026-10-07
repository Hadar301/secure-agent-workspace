#!/usr/bin/env bash
# Phase: ensure the golden image DataSource exists and the VM DataVolume is provisioned.
# Expects: GOLDEN_DS, GOLDEN_NS, GOLDEN_DISK_SIZE, GOLDEN_IMAGE_URL, PULL_METHOD,
#          VM_NAME, NS
set -euo pipefail

if [[ -z "${GOLDEN_IMAGE_URL}" ]]; then
  GOLDEN_IMAGE_URL="docker://image-registry.openshift-image-registry.svc:5000/${GOLDEN_NS}/${GOLDEN_DS}:latest"
fi

if [[ -n "${GOLDEN_DS}" ]]; then
  sources="$(kubectl get datasources -n "${GOLDEN_NS}" -o json)"
  DS_EXISTS="$(jq -r --arg name "${GOLDEN_DS}" \
    '.items[] | select(.metadata.name == $name) | .metadata.name' <<<"${sources}")"
  dvs="$(kubectl get dv -n "${GOLDEN_NS}" -o json)"
  DV_PHASE="$(jq -r --arg name "${GOLDEN_DS}-golden" \
    '.items[] | select(.metadata.name == $name) | .status.phase // empty' <<<"${dvs}")"

  # Case 1: No DataVolume — create both DV + DS and wait
  if [[ -z "${DV_PHASE}" ]]; then
    echo "Golden image not found. Creating DataVolume + DataSource from registry..."
    kubectl apply -f - <<DVEOF
apiVersion: cdi.kubevirt.io/v1beta1
kind: DataVolume
metadata:
  name: ${GOLDEN_DS}-golden
  namespace: ${GOLDEN_NS}
  annotations:
    cdi.kubevirt.io/storage.bind.immediate.requested: "true"
spec:
  source:
    registry:
      url: "${GOLDEN_IMAGE_URL}"
      pullMethod: ${PULL_METHOD}
  storage:
    accessModes:
      - ReadWriteOnce
    resources:
      requests:
        storage: ${GOLDEN_DISK_SIZE}
DVEOF
    DV_PHASE="pending"
  fi

  # Case 2: DataVolume exists but not Succeeded — wait for import
  if [[ "${DV_PHASE}" != "Succeeded" ]]; then
    echo "Waiting for golden image import..."
    golden_deadline=$((SECONDS + 900))
    while true; do
      dvs="$(kubectl get dv -n "${GOLDEN_NS}" -o json)"
      DV_PHASE="$(jq -r --arg name "${GOLDEN_DS}-golden" \
        '.items[] | select(.metadata.name == $name) | .status.phase // empty' <<<"${dvs}")"
      gprog="$(jq -r --arg name "${GOLDEN_DS}-golden" \
        '.items[] | select(.metadata.name == $name) | .status.progress // empty' <<<"${dvs}")"
      echo "  golden image: phase=${DV_PHASE:-pending} progress=${gprog:-N/A}"
      if [[ "${DV_PHASE}" == "Succeeded" ]]; then break; fi
      if (( SECONDS > golden_deadline )); then
        echo "Timed out waiting for golden image import" >&2
        exit 1
      fi
      sleep 15
    done
  fi

  # Case 3: DataVolume Succeeded but DataSource missing — create DS only
  if [[ -z "${DS_EXISTS}" ]]; then
    echo "Creating DataSource '${GOLDEN_DS}'..."
    kubectl apply -f - <<DSEOF
apiVersion: cdi.kubevirt.io/v1beta1
kind: DataSource
metadata:
  name: ${GOLDEN_DS}
  namespace: ${GOLDEN_NS}
spec:
  source:
    pvc:
      name: ${GOLDEN_DS}-golden
      namespace: ${GOLDEN_NS}
DSEOF
  fi

  echo "Golden image ready (DataVolume: Succeeded, DataSource: ${GOLDEN_DS})."

  # If the VM was created before the DataSource existed, its DataVolume
  # was never created by KubeVirt. Create it directly so the VM can boot.
  DV_NAME="${VM_NAME}-root"
  vm_dvs="$(kubectl get dv -n "${NS}" -o json)"
  if ! jq -e --arg name "${DV_NAME}" \
      '.items | any(.metadata.name == $name)' <<<"${vm_dvs}" >/dev/null; then
    echo "VM DataVolume '${DV_NAME}' missing — creating clone from DataSource..."
    kubectl apply -f - <<CLONEDV
apiVersion: cdi.kubevirt.io/v1beta1
kind: DataVolume
metadata:
  name: ${DV_NAME}
  namespace: ${NS}
  annotations:
    cdi.kubevirt.io/storage.bind.immediate.requested: "true"
spec:
  sourceRef:
    kind: DataSource
    name: ${GOLDEN_DS}
    namespace: ${GOLDEN_NS}
  storage:
    accessModes:
      - ReadWriteOnce
    resources:
      requests:
        storage: ${GOLDEN_DISK_SIZE}
CLONEDV
  fi
fi

# Wait for VM DataVolume provisioning
DV_NAME="${VM_NAME}-root"
echo "Waiting for DataVolume ${DV_NAME} to be provisioned..."
deadline=$((SECONDS + 900))
while true; do
  vm_dvs="$(kubectl get dv -n "${NS}" -o json)"
  dv_phase="$(jq -r --arg name "${DV_NAME}" \
    '.items[] | select(.metadata.name == $name) | .status.phase // empty' <<<"${vm_dvs}")"
  echo "  datavolume phase=${dv_phase:-unknown}"
  if [[ "${dv_phase}" == "Succeeded" ]]; then
    break
  fi
  if (( SECONDS > deadline )); then
    echo "Timed out waiting for DataVolume provisioning" >&2
    exit 1
  fi
  sleep 10
done
