# 📖 Referencia Completa de CLI

## 🎯 Comandos Principales

### `repo-scan scan`
Escanea un repositorio con múltiples opciones avanzadas.

```bash
# Opciones básicas
repo-scan scan --path /path/to/repo
repo-scan scan --url https://github.com/user/repo.git

# Opciones avanzadas
repo-scan scan \
  --path /path/to/repo \
  --scanner semgrep \
  --scanner gitleaks \
  --scanner trivy \
  --exclude "*.test.js" \
  --exclude "node_modules/*" \
  --exclude "vendor/*" \
  --include "*.py" \
  --include "*.js" \
  --include "*.ts" \
  --timeout 3600 \
  --parallel 8 \
  --max-workers 4 \
  --output-format json,html,junit \
  --output-dir ./reports \
  --config-file ./custom-config.yaml \
  --severity-threshold HIGH \
  --risk-threshold 70 \
  --fail-on-critical \
  --continue-on-error \
  --verbose \
  --debug \
  --quiet \
  --no-progress \
  --json-output \
  --color always \
  --no-color
```

### `repo-scan list-scanners`
Lista todos los scanners disponibles con información detallada.

```bash
# Lista básica
repo-scan list-scanners

# Con detalles
repo-scan list-scanners --verbose

# Solo disponibles
repo-scan list-scanners --available

# Con configuración
repo-scan list-scanners --config
```

### `repo-scan config`
Gestión avanzada de configuración.

```bash
# Ver configuración actual
repo-scan config show

# Ver configuración específica
repo-scan config get scanners.semgrep.enabled
repo-scan config get workspace_dir

# Establecer configuración
repo-scan config set scanners.semgrep.timeout 1800
repo-scan config set max_workers 8

# Resetear configuración
repo-scan config reset

# Validar configuración
repo-scan config validate

# Exportar configuración
repo-scan config export --output config-backup.yaml

# Importar configuración
repo-scan config import --file config-backup.yaml
```

### `repo-scan plugins`
Sistema de plugins avanzado.

```bash
# Listar plugins
repo-scan plugins list

# Instalar plugin
repo-scan plugins install custom-scanner

# Desinstalar plugin
repo-scan plugins uninstall custom-scanner

# Habilitar/deshabilitar plugin
repo-scan plugins enable custom-scanner
repo-scan plugins disable custom-scanner

# Información del plugin
repo-scan plugins info custom-scanner

# Actualizar plugins
repo-scan plugins update
```

### `repo-scan reports`
Gestión avanzada de reportes.

```bash
# Listar reportes
repo-scan reports list

# Ver reporte específico
repo-scan reports show scan_20241221_143022

# Comparar reportes
repo-scan reports compare scan_old scan_new

# Generar reporte consolidado
repo-scan reports consolidate --from 2024-01-01 --to 2024-12-31

# Exportar reportes
repo-scan reports export --format json --output consolidated.json

# Limpiar reportes antiguos
repo-scan reports cleanup --older-than 30d
```

### `repo-scan notifications`
Sistema de notificaciones avanzado.

```bash
# Configurar Slack
repo-scan notifications setup slack \
  --webhook-url https://hooks.slack.com/services/... \
  --channel security-alerts \
  --severity-threshold HIGH

# Configurar Email
repo-scan notifications setup email \
  --smtp-server smtp.company.com \
  --smtp-port 587 \
  --username alerts@company.com \
  --password-file /path/to/password \
  --to security-team@company.com

# Configurar Webhook
repo-scan notifications setup webhook \
  --url https://api.company.com/security-alerts \
  --headers "Authorization: Bearer token" \
  --method POST

# Probar notificaciones
repo-scan notifications test slack
repo-scan notifications test email
```

### `repo-scan server`
Servidor API avanzado.

```bash
# Iniciar servidor
repo-scan server start \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --ssl-cert /path/to/cert.pem \
  --ssl-key /path/to/key.pem \
  --auth-enabled \
  --auth-provider oidc \
  --oidc-client-id client-id \
  --oidc-client-secret client-secret \
  --oidc-issuer https://auth.company.com

# Estado del servidor
repo-scan server status

# Parar servidor
repo-scan server stop

# Reiniciar servidor
repo-scan server restart

# Logs del servidor
repo-scan server logs --follow
```

## 🎨 Opciones de Salida Avanzadas

### Formato de Salida
```bash
# Múltiples formatos
--output-format json,html,junit,sarif,pdf

# Formato específico
--json-output
--html-output
--junit-output
--sarif-output
--pdf-output

# Personalización de salida
--output-template custom-template.html
--output-styles custom-styles.css
--output-scripts custom-scripts.js
```

### Opciones de Filtrado
```bash
# Por severidad
--severity CRITICAL,HIGH
--severity-threshold MEDIUM

# Por riesgo
--risk-threshold 50
--risk-range 20-80

# Por scanner
--scanner semgrep,gitleaks
--exclude-scanner bandit

# Por archivo
--include "*.py,*.js,*.ts"
--exclude "*.test.*,node_modules/*"

# Por fecha
--since 2024-01-01
--until 2024-12-31

# Por tags
--tags security,vulnerability
--exclude-tags false-positive
```

## 🔧 Opciones de Rendimiento

### Paralelización
```bash
# Workers paralelos
--max-workers 8
--parallel-scanners 4

# Timeouts
--timeout 3600
--scanner-timeout 1800
--connection-timeout 30

# Recursos
--memory-limit 4G
--cpu-limit 80%
--disk-limit 10G
```

### Caché y Optimización
```bash
# Caché
--cache-enabled
--cache-dir /var/cache/repo-scan
--cache-ttl 3600

# Optimizaciones
--skip-cleanup
--keep-temp-files
--incremental-scan
--delta-scan
```

## 🎯 Opciones de Integración

### CI/CD
```bash
# GitHub Actions
repo-scan scan --ci github-actions

# GitLab CI
repo-scan scan --ci gitlab-ci

# Jenkins
repo-scan scan --ci jenkins

# Azure DevOps
repo-scan scan --ci azure-devops
```

### APIs y Webhooks
```bash
# Webhook de resultados
--webhook-url https://api.company.com/scan-results
--webhook-secret secret-key

# API de resultados
--api-endpoint https://api.company.com
--api-key api-key-here

# Integración con SIEM
--siem-integration splunk
--siem-endpoint https://splunk.company.com:8089
--siem-token splunk-token
```
