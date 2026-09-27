{{/*
Expand the name of the chart.
*/}}
{{- define "infraguard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "infraguard.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "infraguard.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "infraguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "infraguard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "infraguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "infraguard.proxySelectorLabels" -}}
{{ include "infraguard.selectorLabels" . }}
app.kubernetes.io/component: proxy
{{- end -}}

{{- define "infraguard.dashboardSelectorLabels" -}}
{{ include "infraguard.selectorLabels" . }}
app.kubernetes.io/component: dashboard
{{- end -}}

{{- define "infraguard.redisSelectorLabels" -}}
{{ include "infraguard.selectorLabels" . }}
app.kubernetes.io/component: redis
{{- end -}}
