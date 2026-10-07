#!/usr/bin/env bash
# Read-only checks for a manual quickstart.
set -euo pipefail

for tool in oc helm jq openssl; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "Error: ${tool} is required." >&2
    exit 1
  fi
done
for tool in virtctl openshell; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "Warning: ${tool} is missing. Some SAW access commands need it." >&2
  fi
done

oc whoami >/dev/null
echo "OpenShift login: active"
echo "Helm: $(helm version --short)"

cnv="$(oc get csv -n openshift-cnv -o json)"
if ! jq -e '.items | any(.metadata.name | contains("kubevirt"))' <<<"${cnv}" >/dev/null; then
  echo "Error: OpenShift Virtualization is not installed in openshift-cnv." >&2
  exit 1
fi
echo "OpenShift Virtualization: installed"

hyperconverged="$(oc get hyperconverged -n openshift-cnv -o json)"
if ! jq -e '.items | length > 0' <<<"${hyperconverged}" >/dev/null; then
  echo "Error: no HyperConverged resource exists in openshift-cnv." >&2
  exit 1
fi
echo "HyperConverged resource: present"

storage="$(oc get storageclass -o json)"
if ! jq -e '.items | any(.metadata.annotations["storageclass.kubernetes.io/is-default-class"] == "true")' \
    <<<"${storage}" >/dev/null; then
  echo "Error: no default StorageClass is available for the VM disk." >&2
  exit 1
fi
echo "Default StorageClass: available"

nodes="$(oc get nodes -o json)"
if ! jq -e '.items | any((.spec.unschedulable != true) and
    any(.status.conditions[]?; .type == "Ready" and .status == "True"))' \
    <<<"${nodes}" >/dev/null; then
  echo "Error: no schedulable Ready node is available for the VM." >&2
  exit 1
fi
echo "Ready schedulable node: available"

rhbk="$(oc get csv -n "${KEYCLOAK_NS:-saw-keycloak}" -o json)"
if ! jq -e '.items | any(.metadata.name | contains("rhbk"))' <<<"${rhbk}" >/dev/null; then
  echo "Error: RHBK is not installed in ${KEYCLOAK_NS:-saw-keycloak}." >&2
  exit 1
fi
echo "RHBK: installed in ${KEYCLOAK_NS:-saw-keycloak}"

routes="$(oc get routes -n openshift-image-registry -o json)"
if jq -e '.items | any(.metadata.name == "default-route")' <<<"${routes}" >/dev/null; then
  echo "Image registry route: available"
else
  echo "Image registry route: absent. images-mirror will enable it."
fi

if [[ -f "${SSH_KEY_PATH:-${HOME}/.generated-ssh-keys/sandbox-ssh}.pub" ]]; then
  echo "SSH public key: available"
else
  echo "SSH public key: absent. Run make ssh-key-generate."
fi
