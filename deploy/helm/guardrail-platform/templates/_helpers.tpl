{{/* ---- names & labels ------------------------------------------------------------------ */}}

{{- define "gp.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* gp.name: "<fullname>-<component>" ; call with (dict "root" $ "component" "gateway") */}}
{{- define "gp.name" -}}
{{- printf "%s-%s" (include "gp.fullname" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gp.selectorLabels" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "gp.labels" -}}
{{ include "gp.selectorLabels" . }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/part-of: guardrail-platform
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version }}
{{- end -}}

{{/* ---- images ------------------------------------------------------------------------------ */}}

{{/* (dict "root" $ "image" "guardrail-gateway") -> registry/image:tag */}}
{{- define "gp.image" -}}
{{- $tag := .root.Values.global.imageTag | default .root.Chart.AppVersion -}}
{{- printf "%s/%s:%s" .root.Values.global.imageRegistry .image $tag -}}
{{- end -}}

{{/* ---- secrets & connection strings -------------------------------------------------------- */}}

{{- define "gp.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else if .Values.secrets.create -}}
{{- printf "%s-secrets" (include "gp.fullname" .) -}}
{{- else -}}
{{- fail "set secrets.existingSecret (recommended, e.g. from SOPS) or secrets.create=true with secrets.values" -}}
{{- end -}}
{{- end -}}

{{/* env var from the release Secret: (dict "root" $ "name" "INTERNAL_TOKEN" "key" "INTERNAL_TOKEN" "optional" false) */}}
{{- define "gp.secretEnv" -}}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ include "gp.secretName" .root }}
      key: {{ .key | default .name }}
      {{- if .optional }}
      optional: true
      {{- end }}
{{- end -}}

{{- define "gp.postgresHost" -}}
{{- include "gp.name" (dict "root" . "component" "postgres") -}}
{{- end -}}

{{/*
POSTGRES_DSN for a component. In-chart Postgres: built from POSTGRES_PASSWORD (defined just
before it, so $(POSTGRES_PASSWORD) expands). External: the component's DSN key in the Secret.
(dict "root" $ "key" "GATEWAY_POSTGRES_DSN" "name" "POSTGRES_DSN")
*/}}
{{- define "gp.dsnEnv" -}}
{{- $v := .root.Values.postgresql -}}
{{- if $v.enabled }}
{{ include "gp.secretEnv" (dict "root" .root "name" "POSTGRES_PASSWORD") }}
- name: {{ .name | default "POSTGRES_DSN" }}
  value: {{ printf "postgresql+asyncpg://%s:$(POSTGRES_PASSWORD)@%s:%v/%s" $v.username (include "gp.postgresHost" .root) $v.port $v.database | quote }}
{{- else }}
{{ include "gp.secretEnv" (dict "root" .root "name" (.name | default "POSTGRES_DSN") "key" .key) }}
{{- end }}
{{- end -}}

{{/* (dict "root" $ "db" 0) */}}
{{- define "gp.redisEnv" -}}
{{- if .root.Values.redis.enabled }}
- name: REDIS_URL
  value: {{ printf "redis://%s:6379/%v" (include "gp.name" (dict "root" .root "component" "redis")) .db | quote }}
{{- else }}
{{ include "gp.secretEnv" (dict "root" .root "name" "REDIS_URL" "optional" true) }}
{{- end }}
{{- end -}}

{{/* ---- URLs between components --------------------------------------------------------------- */}}

{{- define "gp.controlPlaneUrl" -}}
{{- if .Values.gateway.controlPlaneUrl -}}
{{- .Values.gateway.controlPlaneUrl -}}
{{- else if eq .Values.mtls.mode "app" -}}
{{- printf "https://%s:%v" (include "gp.name" (dict "root" . "component" "control-plane")) .Values.controlPlane.internalPort -}}
{{- else -}}
{{- printf "http://%s:%v" (include "gp.name" (dict "root" . "component" "control-plane")) .Values.controlPlane.port -}}
{{- end -}}
{{- end -}}

{{- define "gp.gatewayInternalUrl" -}}
{{- if eq .Values.mtls.mode "app" -}}
{{- printf "https://%s:%v" (include "gp.name" (dict "root" . "component" "gateway")) .Values.gateway.internalPort -}}
{{- else -}}
{{- printf "http://%s:%v" (include "gp.name" (dict "root" . "component" "gateway")) .Values.gateway.port -}}
{{- end -}}
{{- end -}}

{{/* ---- mTLS (mode=app) ----------------------------------------------------------------------- */}}

{{/* (dict "root" $ "component" "gateway" "key" "gateway") -> secret with ca.crt, tls.crt, tls.key */}}
{{- define "gp.mtlsSecret" -}}
{{- $explicit := index .root.Values.mtls.app.secretNames .key -}}
{{- if $explicit -}}{{ $explicit }}{{- else -}}{{ printf "%s-mtls" (include "gp.name" (dict "root" .root "component" .component)) }}{{- end -}}
{{- end -}}

{{- define "gp.mtlsEnv" -}}
{{- if eq .root.Values.mtls.mode "app" }}
- name: INTERNAL_PORT
  value: {{ .internalPort | quote }}
- name: TLS_CERT_FILE
  value: /certs/tls.crt
- name: TLS_KEY_FILE
  value: /certs/tls.key
- name: TLS_CLIENT_CA_FILE
  value: /certs/ca.crt
- name: TLS_CA_FILE
  value: /certs/ca.crt
- name: TLS_CLIENT_CERT_FILE
  value: /certs/tls.crt
- name: TLS_CLIENT_KEY_FILE
  value: /certs/tls.key
{{- end }}
{{- end -}}

{{- define "gp.podAnnotations" -}}
{{- if eq .root.Values.mtls.mode "linkerd" }}
linkerd.io/inject: enabled
{{- end }}
{{- if and .root.Values.monitoring.podAnnotations .metricsPort }}
prometheus.io/scrape: "true"
prometheus.io/port: {{ .metricsPort | quote }}
prometheus.io/path: /metrics
{{- end }}
{{- end -}}

{{- define "gp.scheduling" -}}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* ---- network policy peers ------------------------------------------------------------------ */}}

{{- define "gp.np.from" -}}
- podSelector:
    matchLabels:
      app.kubernetes.io/instance: {{ .root.Release.Name }}
      app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "gp.np.ns" -}}
- namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: {{ . }}
{{- end -}}
