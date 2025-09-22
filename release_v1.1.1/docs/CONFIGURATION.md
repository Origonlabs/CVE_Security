# ⚙️ Configuración Avanzada

## 🎯 Archivo de Configuración Principal

### Ubicaciones de Configuración
```yaml
# Orden de prioridad (mayor a menor):
# 1. CLI arguments
# 2. Environment variables
# 3. Project config: .repo-scan.yaml
# 4. User config: ~/.config/repo-scan/config.yaml
# 5. Global config: /etc/repo-scan/config.yaml
# 6. Default values
```

### Estructura Completa de Configuración
```yaml
# config.yaml - Configuración completa de repo-scan

# Configuración general
general:
  workspace_dir: "/var/lib/repo-scan"
  temp_dir: "/tmp/repo-scan"
  log_level: "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_format: "json"  # json, text, structured
  log_file: "/var/log/repo-scan/repo-scan.log"
  max_log_size: "100MB"
  log_retention: "30d"
  debug: false
  verbose: false
  quiet: false

# Configuración de rendimiento
performance:
  max_workers: 4
  parallel_scanners: true
  max_parallel_scans: 2
  memory_limit: "4G"
  cpu_limit: 80
  disk_limit: "10G"
  connection_timeout: 30
  request_timeout: 300

# Configuración de caché
cache:
  enabled: true
  cache_dir: "/var/cache/repo-scan"
  ttl: 3600  # seconds
  max_size: "5G"
  cleanup_interval: "1h"
  compression: true

# Configuración de scanners
scanners:
  # Semgrep - SAST
  semgrep:
    enabled: true
    timeout: 1800
    config_file: "semgrep-config.yaml"
    rules:
      - "security"
      - "python"
      - "javascript"
      - "typescript"
      - "java"
      - "go"
    custom_rules: []
    severity_threshold: "LOW"
    confidence_threshold: 0.7
    max_findings: 1000
    exclude_patterns:
      - "*.test.*"
      - "node_modules/*"
      - "vendor/*"
      - "*.min.js"
    include_patterns:
      - "*.py"
      - "*.js"
      - "*.ts"
      - "*.java"
      - "*.go"

  # Gitleaks - Secret Detection
  gitleaks:
    enabled: true
    timeout: 600
    config_file: "gitleaks-config.toml"
    scan_history: true
    history_depth: 100
    severity_threshold: "LOW"
    custom_rules: []
    exclude_patterns:
      - "*.test.*"
      - "*.spec.*"
    include_patterns:
      - "*.py"
      - "*.js"
      - "*.ts"
      - "*.yaml"
      - "*.yml"
      - "*.json"
      - "*.env*"

  # Trivy - SCA & Container Security
  trivy:
    enabled: true
    timeout: 1200
    config_file: "trivy-config.yaml"
    scan_types:
      - "vuln"  # vulnerabilities
      - "secret"  # secrets
      - "config"  # misconfigurations
      - "license"  # license issues
    severity_threshold: "LOW"
    ignore_unfixed: false
    skip_files:
      - "*.test.*"
    skip_dirs:
      - "node_modules"
      - "vendor"
    custom_db_path: ""
    offline_scan: false

  # Bandit - Python SAST
  bandit:
    enabled: true
    timeout: 600
    config_file: "bandit-config.yaml"
    severity_level: "LOW"
    confidence_level: "LOW"
    exclude_dirs:
      - "tests"
      - "test_*"
    exclude_files:
      - "*/test_*.py"
      - "*/tests/*.py"
    skip_tests: true
    custom_plugins: []

  # Checkov - IaC Security
  checkov:
    enabled: true
    timeout: 900
    config_file: "checkov-config.yaml"
    framework:
      - "terraform"
      - "cloudformation"
      - "kubernetes"
      - "dockerfile"
      - "arm"
    severity_threshold: "LOW"
    skip_checks: []
    include_checks: []
    exclude_directories:
      - "test"
      - "tests"
    exclude_files:
      - "*.test.*"
      - "*.spec.*"

# Configuración de scoring
scoring:
  enabled: true
  algorithm: "advanced"  # simple, advanced, custom
  custom_weights:
    severity_base:
      CRITICAL: 100
      HIGH: 75
      MEDIUM: 40
      LOW: 10
    exposure_multipliers:
      in_git_history: 1.25
      in_main_branch: 1.3
      in_production: 1.5
      publicly_exposed: 2.0
    secret_type_multipliers:
      private_key: 2.0
      api_key: 1.8
      password: 1.5
      token: 1.3
    exploitability_multipliers:
      cve_known: 1.5
      exploit_available: 2.0
      remote_code_execution: 2.5
  risk_thresholds:
    CRITICAL: 90
    HIGH: 70
    MEDIUM: 40
    LOW: 10

# Configuración de reportes
reports:
  default_format: "all"  # json, html, junit, sarif, pdf, all
  output_dir: "./reports"
  template_dir: "/usr/share/repo-scan/templates"
  custom_templates: []
  include_remediation: true
  include_code_snippets: true
  include_trends: true
  group_by_severity: true
  group_by_scanner: true
  group_by_file: false
  include_metadata: true
  include_statistics: true
  max_findings_per_report: 1000
  compression: true
  retention_days: 90

# Configuración de notificaciones
notifications:
  enabled: true
  default_channels: ["console"]
  severity_threshold: "HIGH"
  risk_threshold: 70
  rate_limit: 10  # notifications per hour
  
  # Slack
  slack:
    enabled: false
    webhook_url: ""
    channel: "#security-alerts"
    username: "repo-scan"
    icon_emoji: ":shield:"
    severity_threshold: "HIGH"
    include_findings: true
    max_findings: 10

  # Email
  email:
    enabled: false
    smtp_server: ""
    smtp_port: 587
    smtp_username: ""
    smtp_password: ""
    smtp_use_tls: true
    from_address: "repo-scan@company.com"
    to_addresses: ["security-team@company.com"]
    subject_template: "Security Scan Results: {repository}"
    severity_threshold: "CRITICAL"
    include_attachments: true

  # Webhook
  webhook:
    enabled: false
    url: ""
    method: "POST"
    headers:
      "Content-Type": "application/json"
      "Authorization": "Bearer token"
    timeout: 30
    retry_attempts: 3
    retry_delay: 5

  # Teams
  teams:
    enabled: false
    webhook_url: ""
    severity_threshold: "HIGH"

# Configuración de integración
integrations:
  # CI/CD
  ci_cd:
    enabled: true
    platforms:
      - "github-actions"
      - "gitlab-ci"
      - "jenkins"
      - "azure-devops"
    fail_on_critical: true
    fail_on_high: false
    fail_on_risk_threshold: 80
    comment_on_pr: true
    create_issues: false

  # SIEM
  siem:
    enabled: false
    type: "splunk"  # splunk, elasticsearch, qradar, sentinel
    endpoint: ""
    token: ""
    index: "security"
    sourcetype: "repo-scan"
    format: "cef"  # json, cef, leef

  # Ticketing
  ticketing:
    enabled: false
    type: "jira"  # jira, servicenow, github-issues
    endpoint: ""
    username: ""
    password: ""
    project_key: "SEC"
    issue_type: "Bug"
    severity_mapping:
      CRITICAL: "Critical"
      HIGH: "High"
      MEDIUM: "Medium"
      LOW: "Low"

# Configuración de plugins
plugins:
  enabled: true
  plugin_dir: "/usr/share/repo-scan/plugins"
  custom_plugin_dir: "~/.config/repo-scan/plugins"
  auto_load: true
  plugin_timeout: 300
  plugin_memory_limit: "1G"
  trusted_plugins: []
  blocked_plugins: []

# Configuración de seguridad
security:
  # Autenticación
  auth:
    enabled: false
    provider: "oidc"  # oidc, ldap, local
    oidc:
      client_id: ""
      client_secret: ""
      issuer: ""
      scope: "openid profile email"
    ldap:
      server: ""
      base_dn: ""
      user_dn: ""
      password: ""
    local:
      users_file: "/etc/repo-scan/users.yaml"

  # Autorización
  authorization:
    enabled: false
    rbac:
      roles:
        admin:
          permissions: ["*"]
        user:
          permissions: ["scan:read", "scan:create"]
        viewer:
          permissions: ["scan:read"]

  # Cifrado
  encryption:
    enabled: false
    algorithm: "AES-256-GCM"
    key_file: "/etc/repo-scan/encryption.key"
    encrypt_findings: true
    encrypt_reports: false

  # Auditoría
  audit:
    enabled: true
    log_file: "/var/log/repo-scan/audit.log"
    log_retention: "1y"
    events:
      - "scan_started"
      - "scan_completed"
      - "scan_failed"
      - "config_changed"
      - "user_login"
      - "user_logout"

# Configuración de base de datos
database:
  type: "sqlite"  # sqlite, postgresql, mysql
  sqlite:
    path: "/var/lib/repo-scan/repo-scan.db"
    max_connections: 1
  postgresql:
    host: "localhost"
    port: 5432
    database: "repo_scan"
    username: "repo_scan"
    password: ""
    ssl_mode: "prefer"
    max_connections: 20
  mysql:
    host: "localhost"
    port: 3306
    database: "repo_scan"
    username: "repo_scan"
    password: ""
    ssl_mode: "prefer"
    max_connections: 20

# Configuración de servidor web
server:
  enabled: false
  host: "127.0.0.1"
  port: 8000
  workers: 4
  ssl:
    enabled: false
    cert_file: ""
    key_file: ""
  cors:
    enabled: true
    origins: ["*"]
    methods: ["GET", "POST", "PUT", "DELETE"]
    headers: ["*"]
  rate_limiting:
    enabled: true
    requests_per_minute: 100
    burst_size: 20
```

## 🔧 Variables de Entorno

### Variables Principales
```bash
# Configuración general
export REPO_SCAN_WORKSPACE_DIR="/var/lib/repo-scan"
export REPO_SCAN_LOG_LEVEL="INFO"
export REPO_SCAN_DEBUG="false"
export REPO_SCAN_VERBOSE="false"

# Rendimiento
export REPO_SCAN_MAX_WORKERS="4"
export REPO_SCAN_PARALLEL_SCANNERS="true"
export REPO_SCAN_MEMORY_LIMIT="4G"
export REPO_SCAN_CPU_LIMIT="80"

# Caché
export REPO_SCAN_CACHE_ENABLED="true"
export REPO_SCAN_CACHE_DIR="/var/cache/repo-scan"
export REPO_SCAN_CACHE_TTL="3600"

# Scanners
export REPO_SCAN_SEMGREP_ENABLED="true"
export REPO_SCAN_SEMGREP_TIMEOUT="1800"
export REPO_SCAN_GITLEAKS_ENABLED="true"
export REPO_SCAN_TRIVY_ENABLED="true"

# Notificaciones
export REPO_SCAN_SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export REPO_SCAN_SLACK_CHANNEL="#security-alerts"
export REPO_SCAN_EMAIL_SMTP_SERVER="smtp.company.com"
export REPO_SCAN_EMAIL_SMTP_USERNAME="alerts@company.com"
export REPO_SCAN_EMAIL_SMTP_PASSWORD="password"

# Base de datos
export REPO_SCAN_DB_TYPE="sqlite"
export REPO_SCAN_DB_PATH="/var/lib/repo-scan/repo-scan.db"
export REPO_SCAN_DB_HOST="localhost"
export REPO_SCAN_DB_PORT="5432"
export REPO_SCAN_DB_NAME="repo_scan"
export REPO_SCAN_DB_USERNAME="repo_scan"
export REPO_SCAN_DB_PASSWORD="password"

# Servidor
export REPO_SCAN_SERVER_ENABLED="true"
export REPO_SCAN_SERVER_HOST="0.0.0.0"
export REPO_SCAN_SERVER_PORT="8000"
export REPO_SCAN_SERVER_WORKERS="4"

# Seguridad
export REPO_SCAN_AUTH_ENABLED="true"
export REPO_SCAN_AUTH_PROVIDER="oidc"
export REPO_SCAN_OIDC_CLIENT_ID="client-id"
export REPO_SCAN_OIDC_CLIENT_SECRET="client-secret"
export REPO_SCAN_OIDC_ISSUER="https://auth.company.com"
```

## 🎯 Configuración por Proyecto

### Archivo .repo-scan.yaml
```yaml
# .repo-scan.yaml - Configuración específica del proyecto
project:
  name: "my-awesome-project"
  repository: "https://github.com/company/my-awesome-project"
  branch: "main"
  
scanners:
  semgrep:
    enabled: true
    rules:
      - "security"
      - "python"
      - "javascript"
    custom_rules:
      - "custom-security-rules.yaml"
  
  gitleaks:
    enabled: true
    scan_history: true
    custom_rules:
      - "custom-secrets-rules.toml"

filters:
  include:
    - "src/**/*.py"
    - "src/**/*.js"
    - "src/**/*.ts"
  exclude:
    - "tests/**/*"
    - "docs/**/*"
    - "*.test.*"
    - "node_modules/**/*"

scoring:
  custom_weights:
    severity_base:
      CRITICAL: 100
      HIGH: 80
      MEDIUM: 50
      LOW: 20

notifications:
  channels: ["slack", "email"]
  severity_threshold: "MEDIUM"
  risk_threshold: 60

integrations:
  ci_cd:
    fail_on_critical: true
    fail_on_high: true
    comment_on_pr: true
    create_issues: true
```

## 🔄 Configuración Dinámica

### Hot Reload
```bash
# Habilitar hot reload
repo-scan config set general.hot_reload true

# Recargar configuración sin reiniciar
repo-scan config reload

# Verificar configuración
repo-scan config validate
```

### Configuración Remota
```bash
# Cargar configuración desde URL
repo-scan config load --url https://config.company.com/repo-scan.yaml

# Sincronizar configuración
repo-scan config sync --remote https://config.company.com/repo-scan.yaml
```
