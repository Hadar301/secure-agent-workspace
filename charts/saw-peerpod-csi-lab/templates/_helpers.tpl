{{- define "saw-peerpod-csi-lab.validate" -}}
{{- if not (regexMatch "^[a-f0-9]{16}$" .Values.registration) }}{{ fail "LabRegistrationRejected" }}{{ end -}}
{{- if ne .Release.Namespace (printf "saw-ppvc-%s" .Values.registration) }}{{ fail "LabNamespaceRejected" }}{{ end -}}
{{- if ne .Release.Name .Release.Namespace }}{{ fail "LabReleaseNameRejected" }}{{ end -}}
{{- if not (regexMatch "^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$" .Values.nodeName) }}{{ fail "LabNodeRejected" }}{{ end -}}
{{- if not (regexMatch "^[a-z0-9]+$" .Values.region) }}{{ fail "LabRegionRejected" }}{{ end -}}
{{- if not (regexMatch "^[a-zA-Z0-9._()-]{1,90}$" .Values.resourceGroup) }}{{ fail "LabResourceGroupRejected" }}{{ end -}}
{{- if not (regexMatch "^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$" .Values.cloudConfigSecret) }}{{ fail "LabCloudConfigReferenceRejected" }}{{ end -}}
{{- range $image := .Values.images }}{{ if not (regexMatch "^[a-z0-9][^ @]*@sha256:[a-f0-9]{64}$" $image) }}{{ fail "LabImagePinRequired" }}{{ end }}{{ end -}}
{{- if ne .Values.wrapperPatchSHA256 "60c188e8811cf2698ee878db735b56f6e6755d7241e5b993d1951a99ec259454" }}{{ fail "LabWrapperPatchRejected" }}{{ end -}}
{{- if not .Values.apiServerCIDRs }}{{ fail "LabApiTargetsRequired" }}{{ end -}}
{{- range $cidr := .Values.apiServerCIDRs }}{{ if not (regexMatch "^[0-9a-fA-F:.]+/[0-9]+$" $cidr) }}{{ fail "LabApiTargetsRejected" }}{{ end }}{{ end -}}
{{- if and .Values.wrapperBuildNamespace (not (regexMatch "^saw-[a-z0-9-]+$" .Values.wrapperBuildNamespace)) }}{{ fail "LabBuildNamespaceRejected" }}{{ end -}}
{{- if and .Values.activate (not .Values.acknowledgeGuestKubeletMarker) }}{{ fail "LabHelperMarkerReviewRequired" }}{{ end -}}
{{- if and .Values.activate (not .Values.enforceGuards) }}{{ fail "LabAdmissionGuardsRequired" }}{{ end -}}
{{- if and .Values.activate (not .Values.acknowledgePrivilegedNodeAccess) }}{{ fail "LabHostAccessReviewRequired" }}{{ end -}}
{{- end -}}
{{- define "saw-peerpod-csi-lab.driver" -}}{{ .Release.Namespace }}.disk.csi.saw.redhat.com{{- end -}}
{{- define "saw-peerpod-csi-lab.guestNamespace" -}}saw-ppvc-probe-{{ .Values.registration }}{{- end -}}
