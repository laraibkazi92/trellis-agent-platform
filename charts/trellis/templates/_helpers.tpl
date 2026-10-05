{{/*
Expand the name of the chart.
*/}}
{{- define "trellis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name (max 63 chars).
*/}}
{{- define "trellis.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels (component-agnostic; add app.kubernetes.io/component per resource).
Takes the root context directly.
*/}}
{{- define "trellis.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
app.kubernetes.io/name: {{ include "trellis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels, pinned to one component.
Usage: {{ include "trellis.selectorLabels" (dict "ctx" . "component" "host") }}
*/}}
{{- define "trellis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trellis.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Workspace volume block (optional existing PVC), mounted at /app/workspace.
Usage: {{ include "trellis.workspaceVolume" (dict "ctx" .) }}
*/}}
{{- define "trellis.workspaceVolume" -}}
{{- if .ctx.Values.workspace.persistentVolumeClaim }}
- name: workspace
  persistentVolumeClaim:
    claimName: {{ .ctx.Values.workspace.persistentVolumeClaim }}
{{- end }}
{{- end }}

{{/*
Workspace volumeMount block for /app/workspace.
Usage: {{ include "trellis.workspaceVolumeMount" (dict "ctx" .) }}
*/}}
{{- define "trellis.workspaceVolumeMount" -}}
{{- if .ctx.Values.workspace.persistentVolumeClaim }}
- name: workspace
  mountPath: /app/workspace
{{- end }}
{{- end }}
