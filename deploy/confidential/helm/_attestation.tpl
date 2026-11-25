{{/* Shared structural gate. Python verifies policies and live approvals. */}}
{{- define "saw.confidential.gate" -}}
{{- $site := . | default dict -}}
{{- $a := $site.attestation | default dict -}}
{{- if not (kindIs "map" $a) -}}{{ fail "AttestationConfigurationRejected" }}{{- end -}}
{{- if and (hasKey $a "enabled") (not (kindIs "bool" $a.enabled)) -}}{{ fail "AttestationConfigurationRejected" }}{{- end -}}
{{- if $a.enabled -}}
{{- if or (ne (toString $a.schemaVersion) "2") (not (kindIs "map" $a.launchPolicies)) (empty $a.launchPolicies) (hasKey $a "guestPolicy") -}}
{{- fail "AttestationLaunchPolicyRequired" -}}
{{- end -}}
{{- $required := list "enabled" "schemaVersion" "tee" "kbsURL" "kbsCA" "policyDigest" "referenceSet" "imagePolicy" "driver" "references" "launchPolicies" -}}
{{- if ne (len $a) (len $required) -}}{{ fail "AttestationConfigurationRejected" }}{{- end -}}
{{- range $key := $required -}}{{- if not (hasKey $a $key) -}}{{ fail "AttestationConfigurationRejected" }}{{- end -}}{{- end -}}
{{- if or (not (has $a.tee (list "snp" "tdx"))) (not (regexMatch "^[a-f0-9]{64}$" $a.policyDigest)) (not (regexMatch "^[a-f0-9]{64}$" $a.referenceSet)) -}}{{ fail "AttestationPolicyRejected" }}{{- end -}}
{{- if not (kindIs "map" $a.driver) -}}{{ fail "AttestationDriverUnavailable" }}{{- end -}}
{{- if or (ne $a.driver.capability "saw-confidential-v1") (not (regexMatch "^[a-f0-9]{40}$" $a.driver.sourceRevision)) (not (regexMatch "^.+@sha256:[a-f0-9]{64}$" $a.driver.gatewayImage)) (not (regexMatch "^.+@sha256:[a-f0-9]{64}$" $a.driver.supervisorImage)) -}}{{ fail "AttestationDriverUnavailable" }}{{- end -}}
{{- if not (kindIs "map" $a.references) -}}{{ fail "AttestationApprovalMissing" }}{{- end -}}
{{- $keys := list "peerPods" "trustee" "trusteeConfig" "attestationPolicy" "resourcePolicy" "referenceValues" "qualification" -}}
{{- if ne (len $a.references) (len $keys) -}}{{ fail "AttestationApprovalMissing" }}{{- end -}}
{{- range $key := $keys -}}
{{- $ref := index $a.references $key -}}
{{- if not (kindIs "map" $ref) -}}{{ fail "AttestationApprovalMissing" }}{{- end -}}
{{- $pattern := "^/api/v1/namespaces/[a-z0-9-]+/configmaps/[a-z0-9-]+$" -}}
{{- if eq $key "peerPods" -}}{{- $pattern = "^/api/v1/namespaces/openshift-sandboxed-containers-operator/configmaps/peer-pods-cm$" -}}
{{- else if eq $key "trustee" -}}{{- $pattern = "^/apis/apps/v1/namespaces/[a-z0-9-]+/deployments/[a-z0-9-]+$" -}}
{{- else if eq $key "trusteeConfig" -}}{{- $pattern = "^/apis/confidentialcontainers.org/v1alpha1/namespaces/[a-z0-9-]+/kbsconfigs/[a-z0-9-]+$" -}}{{- end -}}
{{- if or (ne (len $ref) 3) (not (regexMatch $pattern (toString $ref.path))) (not (regexMatch "^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$" (toString $ref.uid))) (not (regexMatch "^[a-f0-9]{64}$" (toString $ref.sha256))) -}}{{ fail "AttestationApprovalMissing" }}{{- end -}}
{{- end -}}
{{- range $slot, $roles := $a.launchPolicies -}}
{{- if or (not (regexMatch "^[a-z0-9-]+/[a-z0-9-]+$" $slot)) (not (kindIs "map" $roles)) -}}{{ fail "AttestationLaunchPolicyRejected" }}{{- end -}}
{{- if or (ne (len $roles) 2) (not (hasKey $roles "supervisor")) (not (hasKey $roles "workload")) -}}{{ fail "AttestationLaunchPolicyRejected" }}{{- end -}}
{{- range $entry := $roles -}}
{{- if not (kindIs "map" $entry) -}}{{ fail "AttestationLaunchPolicyRejected" }}{{- end -}}
{{- if or (ne (len $entry) 2) (not (kindIs "map" $entry.pod)) (not (kindIs "string" $entry.template)) (empty $entry.template) -}}{{ fail "AttestationLaunchPolicyRejected" }}{{- end -}}
{{- end -}}{{- end -}}
{{- end -}}
{{- end -}}

{{/* Named read-only approval access. No Secret, list, or write permissions. */}}
{{- define "saw.confidential.readRoles" -}}
{{- $refs := dict -}}
{{- range $site := .sites -}}
{{- include "saw.confidential.gate" $site -}}
{{- if ($site.attestation | default dict).enabled -}}
{{- range $ref := $site.attestation.references -}}{{- $_ := set $refs $ref.path true -}}{{- end -}}
{{- end -}}{{- end -}}
{{- range $path := .paths | default list -}}
{{- if or (not (kindIs "string" $path)) (not (regexMatch "^(/api/v1/namespaces/[a-z0-9-]+/configmaps/[a-z0-9-]+|/apis/apps/v1/namespaces/[a-z0-9-]+/deployments/[a-z0-9-]+|/apis/confidentialcontainers.org/v1alpha1/namespaces/[a-z0-9-]+/kbsconfigs/[a-z0-9-]+)$" $path)) -}}{{ fail "AttestationApprovalPathRejected" }}{{- end -}}
{{- $_ := set $refs $path true -}}
{{- end -}}
{{- range $path, $_ := $refs }}
{{- $parts := splitList "/" $path -}}
{{- $namespaceIndex := 4 -}}{{- $group := "" -}}
{{- if eq (index $parts 1) "apis" -}}{{- $namespaceIndex = 5 -}}{{- $group = index $parts 2 -}}{{- end -}}
{{- $role := printf "saw-attestation-%s" (printf "%s/%s/%s" $.namespace $.serviceAccount $path | sha256sum | trunc 24) -}}
{{ "\n" }}---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ $role }}
  namespace: {{ index $parts $namespaceIndex }}
rules:
- apiGroups: [{{ $group | quote }}]
  resources: [{{ index $parts (add $namespaceIndex 1 | int) | quote }}]
  resourceNames: [{{ base $path | quote }}]
  verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ $role }}
  namespace: {{ index $parts $namespaceIndex }}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: {{ $role }}}
subjects: [{kind: ServiceAccount, name: {{ $.serviceAccount }}, namespace: {{ $.namespace }}}]
{{- end -}}
{{- end -}}


{{/* Bootstrap belongs to the trusted control plane, not a provider proxy. */}}
{{- define "saw.workspace.bootstrapEgress" -}}
{{- include "saw.confidential.gate" . -}}
{{- $egress := list -}}
{{- if (.attestation | default dict).enabled -}}
{{- $egress = .bootstrapEgress -}}
{{- else -}}
{{- $egress = dig "stack" "proxy" "values" "network" "bootstrapEgress" list . -}}
{{- end -}}
{{- if or (not (kindIs "slice" $egress)) (empty $egress) -}}{{ fail "BootstrapEgressMissing" }}{{- end -}}
{{- $egress | toJson -}}
{{- end -}}
