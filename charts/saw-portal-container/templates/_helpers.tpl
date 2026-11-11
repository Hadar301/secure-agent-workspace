{{/* Targets are derived from the selected BOM, never a fixed profile. */}}
{{- define "portal.targets" -}}
{{- $s := .Values.site | default dict -}}
{{ required "BOM-derived sandbox targets are required" $s.targets | toJson }}
{{- end -}}
{{- define "portal.claims" -}}
{{- $claims := list -}}
{{- range $slot := include "portal.targets" . | fromJson -}}
{{- range $prefix := list "workspace-" "saw-gate-" "saw-audit-" -}}
{{- $claims = append $claims (printf "%s%s" $prefix $slot.base) -}}
{{- end -}}{{- end -}}
{{ $claims | toJson }}
{{- end -}}
{{- define "portal.workloadRuntime" -}}
{{- $site := .Values.site | default dict -}}
{{- $w := $site.workloadRuntime | default dict -}}
{{- if empty $w -}}
{{- dict "kind" "container" "runtimeClassName" "" | toJson -}}
{{- else -}}
{{- if not (kindIs "map" $w) -}}{{- fail "site.workloadRuntime must be an operator-owned object" -}}{{- end -}}
{{- if or (ne (len $w) 2) (ne (get $w "kind") "kata") (not (hasKey $w "runtimeClassName")) -}}
{{- fail "site.workloadRuntime must set kind kata and runtimeClassName" -}}
{{- end -}}
{{- $name := get $w "runtimeClassName" -}}
{{- if or (not (kindIs "string" $name)) (gt (len $name) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$" $name)) -}}
{{- fail "site.workloadRuntime.runtimeClassName must be a DNS subdomain" -}}
{{- end -}}
{{- dict "kind" "kata" "runtimeClassName" $name | toJson -}}
{{- end -}}
{{- end -}}
