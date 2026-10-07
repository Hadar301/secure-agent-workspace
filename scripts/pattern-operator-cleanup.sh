#!/usr/bin/env bash
# Run only after the framework removes the Argo CD applications.
set -euo pipefail

namespaces="$(oc get namespaces -o json)"
if ! jq -e '.items | any(.metadata.name == "openshift-cnv")' \
  <<<"${namespaces}" >/dev/null; then
  echo "OpenShift Virtualization namespace is already absent."
  exit 0
fi

resources="$(oc api-resources -o name)"
for kind in hyperconvergeds.hco.kubevirt.io \
    subscriptions.operators.coreos.com \
    clusterserviceversions.operators.coreos.com \
    installplans.operators.coreos.com; do
  if ! grep -qx "${kind}" <<<"${resources}"; then continue; fi
  objects="$(oc get "${kind}" -n openshift-cnv -o json)"
  owned_names="$(jq -r '.items[] |
    select(.metadata.labels["argocd.argoproj.io/instance"] == "openshift-cnv" or
      ((.metadata.annotations["argocd.argoproj.io/tracking-id"] // "") |
       startswith("openshift-cnv:"))) | .metadata.name' <<<"${objects}")"
  total="$(jq -r '.items | length' <<<"${objects}")"
  owned_count="$(jq -r '.items | [ .[] |
    select(.metadata.labels["argocd.argoproj.io/instance"] == "openshift-cnv" or
      ((.metadata.annotations["argocd.argoproj.io/tracking-id"] // "") |
       startswith("openshift-cnv:"))) ] | length' <<<"${objects}")"
  if (( total > owned_count )); then
    echo "Keeping $((total - owned_count)) ${kind} objects without pattern ownership."
  fi
  while IFS= read -r name; do
    [[ -n "${name}" ]] || continue
    echo "Deleting pattern-owned ${kind}/${name} in openshift-cnv."
    oc delete "${kind}" "${name}" -n openshift-cnv \
      --wait=false --ignore-not-found=true
  done <<<"${owned_names}"
done
