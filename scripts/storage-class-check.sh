#!/usr/bin/env bash
# Ensure the cluster has a default StorageClass for the SAW VM disks.
#
# The openshell-saw VM root disks are CDI DataVolumes with no storageClassName,
# so they provision from the cluster's default StorageClass. With none set, the
# DataVolumes stay Pending and the VMs never boot. This runs before the GitOps
# apply (a prerequisite of pattern-install) and, on a terminal, offers to fix it:
#   - a default is already set        -> continue
#   - classes exist but none default  -> offer to mark one default (confirm)
#   - no StorageClass at all           -> offer to enable the HostPath Provisioner
#                                        (HPP) through OpenShift Virtualization
#                                        and set it as the default
# Non-interactive (no TTY, e.g. CI/GitOps): prints guidance and fails instead of
# prompting, so the install stops cleanly rather than hanging. Set
# SAW_STORAGE_ASSUME_YES=1 to accept the prompts unattended (and
# SAW_STORAGE_DEFAULT_CLASS=<name> to choose which existing class to adopt).
#
# Uses only oc and jq, so it runs inside the validated-patterns utility
# container (./pattern.sh make install) as well as on a workstation.
set -euo pipefail

DEFAULT_ANNOTATION="storageclass.kubernetes.io/is-default-class"
HPP_CLASS="${SAW_HPP_STORAGECLASS:-saw-hostpath}"
HPP_POOL="${SAW_HPP_POOL:-saw-hpp}"
HPP_PATH="${SAW_HPP_PATH:-/var/hpvolumes}"
DOCS="docs/storage-setup.md"
CHECK_ONLY=0
[ "${1:-}" = "--check-only" ] && CHECK_ONLY=1

err() { echo "$@" >&2; }
banner() {
  err ""
  err "################################################################"
  err "#  $1"
  err "################################################################"
}
interactive() { [ -t 0 ] && [ -t 1 ]; }
ask_yes() {
  # $1 prompt. Yes -> 0. SAW_STORAGE_ASSUME_YES forces yes; no TTY -> no.
  [ "${SAW_STORAGE_ASSUME_YES:-0}" = 1 ] && return 0
  interactive || return 1
  local ans
  read -r -p "$1 [y/N] " ans || return 1
  [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]]
}
guidance() {
  err "SAW needs a default StorageClass before install: the VM disks set no"
  err "storageClassName and use the cluster default. Set one up, then re-run:"
  err "  - mark an existing class default:"
  err "      oc patch storageclass <name> \\"
  err "        -p '{\"metadata\":{\"annotations\":{\"${DEFAULT_ANNOTATION}\":\"true\"}}}'"
  err "  - or install a provisioner (LVMS for local disks, or HPP via OpenShift"
  err "    Virtualization). See ${DOCS}."
}

sc_json="$(oc get storageclass -o json)"

if jq -e --arg a "$DEFAULT_ANNOTATION" \
    '.items | any(.metadata.annotations[$a] == "true")' <<<"$sc_json" >/dev/null; then
  name="$(jq -r --arg a "$DEFAULT_ANNOTATION" \
    '.items[] | select(.metadata.annotations[$a] == "true") | .metadata.name // empty' \
    <<<"$sc_json" | head -n1)"
  msg="Default StorageClass: available"
  [ -n "$name" ] && msg="$msg (${name})"
  echo "$msg"
  exit 0
fi

if [ "$CHECK_ONLY" = 1 ]; then
  err "Error: no default StorageClass is available for the VM disk."
  exit 1
fi

mapfile -t names < <(jq -r '.items[].metadata.name // empty' <<<"$sc_json")

if [ "${#names[@]}" -gt 0 ]; then
  banner "No default StorageClass is set on this cluster."
  err "The SAW VM disks need a default StorageClass. Existing classes:"
  for n in "${names[@]}"; do err "  - ${n}"; done
  cand="${SAW_STORAGE_DEFAULT_CLASS:-${names[0]}}"
  if [ -z "${SAW_STORAGE_DEFAULT_CLASS:-}" ] && [ "${#names[@]}" -gt 1 ] && interactive; then
    read -r -p "Which StorageClass should be the default? [${cand}] " pick || pick=""
    [ -n "$pick" ] && cand="$pick"
  fi
  if ask_yes "Mark StorageClass '${cand}' as the cluster default?"; then
    oc patch storageclass "$cand" \
      -p "{\"metadata\":{\"annotations\":{\"${DEFAULT_ANNOTATION}\":\"true\"}}}"
    echo "Marked StorageClass '${cand}' as the cluster default."
    exit 0
  fi
  err ""
  guidance
  exit 1
fi

banner "NO STORAGECLASS EXISTS - the SAW VM disks cannot be provisioned."
if ! ask_yes "Configure a default StorageClass now by enabling the HostPath Provisioner (HPP)?"; then
  err ""
  guidance
  exit 1
fi

if ! oc get crd hostpathprovisioners.hostpathprovisioner.kubevirt.io >/dev/null 2>&1; then
  banner "HostPath Provisioner is not available yet."
  err "Enabling HPP needs OpenShift Virtualization, which this pattern installs"
  err "during 'make install'. On a fresh cluster it is not present yet, so HPP"
  err "cannot be enabled before the pattern is installed. Options:"
  err "  - install LVMS now (robust for local disks), or"
  err "  - let 'make install' bring up OpenShift Virtualization, then re-run"
  err "    'make storage-class-check' to enable HPP and set it default."
  err "See ${DOCS}."
  exit 1
fi

banner "WARNING: enabling host-path storage on every node."
err "This creates a HostPathProvisioner at node path '${HPP_PATH}' and a DEFAULT"
err "StorageClass '${HPP_CLASS}'. Host-path storage is node-local, not replicated,"
err "and not production-grade - fine for a demo or dev cluster."
if ! ask_yes "Proceed?"; then
  err ""
  guidance
  exit 1
fi

oc apply -f - <<HPP
apiVersion: hostpathprovisioner.kubevirt.io/v1beta1
kind: HostPathProvisioner
metadata:
  name: hostpath-provisioner
spec:
  imagePullPolicy: IfNotPresent
  storagePools:
    - name: ${HPP_POOL}
      path: ${HPP_PATH}
  workload:
    nodeSelector:
      kubernetes.io/os: linux
HPP

oc apply -f - <<SC
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ${HPP_CLASS}
  annotations:
    ${DEFAULT_ANNOTATION}: "true"
provisioner: kubevirt.io.hostpath-provisioner
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
parameters:
  storagePool: ${HPP_POOL}
SC

echo "Enabled HPP and created default StorageClass '${HPP_CLASS}'."
echo "Give the provisioner a minute to become Ready:"
echo "  oc get pods -n openshift-cnv | grep hostpath"
exit 0
