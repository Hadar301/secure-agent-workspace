#!/usr/bin/env bash
# Prepare Job entrypoint: cluster-side work only. It never connects to the
# VM; the VM installs itself (see files/installer/apply_bom.py).
# Chart values are resolved by Helm tpl() at render time.
set -euo pipefail

VM_NAME="{{ include "openshell-sandbox.fullname" . }}"
NS="{{ .Release.Namespace }}"
GOLDEN_DS="{{ include "openshell-sandbox.dataSourceName" . }}"
GOLDEN_NS="{{ include "openshell-sandbox.goldenNamespace" . }}"
GOLDEN_DISK_SIZE="{{ .Values.vm.diskSize }}"
GOLDEN_IMAGE_URL="{{ .Values.source.goldenImageURL }}"
PULL_METHOD="{{ .Values.source.pullMethod | default "node" }}"
SCRIPTS_DIR="/scripts"

# --- Phase 1: tools ---
source "${SCRIPTS_DIR}/install-deps.sh"

# --- Phase 2: golden image DataSource (only for the DataSource disk source) ---
{{- if not (or .Values.source.registryURL .Values.source.httpURL) }}
source "${SCRIPTS_DIR}/bootstrap-golden-image.sh"
{{- else }}
echo "Disk source is a registry/HTTP import; no golden image bootstrap needed."
{{- end }}

# The web UI routes' Keycloak redirect URIs are not set here: the routes are
# labelled saw.redhat.com/oidc-redirect, and the redirect registrar in
# Keycloak's namespace (charts/openshell-keycloak) registers them.

echo "Prepare complete for vm/${VM_NAME}. The VM installs itself; follow its console log:"
echo "  oc logs -f -n ${NS} \$(oc get pod -n ${NS} -l vm.kubevirt.io/name=${VM_NAME} -o name) -c guest-console-log"
