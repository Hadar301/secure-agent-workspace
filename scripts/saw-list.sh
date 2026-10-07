#!/usr/bin/env bash
set -euo pipefail

releases="$(helm list -A -o json)"
rows="$(jq -r '.[] | select(.chart | startswith("openshell-saw")) |
  [.name, .namespace, .status, (.updated | split(".")[0])] | @tsv' <<<"${releases}")"
printf '%-20s %-24s %-12s %-12s %s\n' NAME NAMESPACE STATUS VM UPDATED
while IFS=$'\t' read -r name namespace status updated; do
  [[ -n "${name}" ]] || continue
  vms="$(oc get vm -n "${namespace}" -o json)"
  vm="$(jq -r --arg name "${name}" \
    '.items[] | select(.metadata.name == $name) | .status.printableStatus // "unknown"' \
    <<<"${vms}")"
  printf '%-20s %-24s %-12s %-12s %s\n' \
    "${name}" "${namespace}" "${status}" "${vm:-missing}" "${updated}"
done <<<"${rows}"
