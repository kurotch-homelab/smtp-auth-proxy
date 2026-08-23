{{- define "smtp-auth-proxy.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "smtp-auth-proxy.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "smtp-auth-proxy.labels" -}}
app.kubernetes.io/name: {{ include "smtp-auth-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "smtp-auth-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "smtp-auth-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "smtp-auth-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "smtp-auth-proxy.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Guard rails: the combinations that lose data or cannot start are refused at
render time, where the message can say why, rather than at runtime.
*/}}
{{- define "smtp-auth-proxy.validate" -}}
{{- if and (eq .Values.database.driver "sqlite") (gt (int .Values.replicaCount) 1) -}}
{{- fail "replicaCount > 1 requires database.driver=postgres: SQLite is a single local file, and two replicas writing it through two volumes is data loss, not availability." -}}
{{- end -}}
{{- if not .Values.encryption.existingSecret -}}
{{- fail "encryption.existingSecret is required. Generate a key with 'smtp-auth-proxy genkey' and create the Secret yourself, so it never passes through Helm's release storage: kubectl create secret generic smtp-auth-proxy-encryption --from-literal=key=<generated>" -}}
{{- end -}}
{{- if and (eq .Values.database.driver "postgres") (not .Values.database.existingSecret) (not .Values.database.dsn) -}}
{{- fail "database.driver=postgres needs either database.dsn or database.existingSecret." -}}
{{- end -}}
{{- end -}}
