# 🔒 Repo-Scan: Advanced Repository Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Fedora](https://img.shields.io/badge/Fedora-38+-blue.svg)](https://fedoraproject.org/)
[![Security](https://img.shields.io/badge/security-scanner-red.svg)](https://github.com/Origonlabs/CVE_Security)

**Repo-Scan** es una herramienta avanzada de escaneo de seguridad para repositorios de código que proporciona análisis integral de seguridad con múltiples motores de escaneo, puntuación de riesgo avanzada, y capacidades de reporte e integración de nivel empresarial.

## 🚀 Características Principales

### 🔍 Múltiples Motores de Escaneo
- **SAST (Static Application Security Testing)**: Semgrep, Bandit, SonarQube
- **SCA (Software Composition Analysis)**: Trivy, Grype, Snyk
- **Secret Detection**: Gitleaks, TruffleHog, Detect-secrets
- **IaC Security**: Checkov, Terrascan, TFSec, Kube-score
- **Container Security**: Trivy, Clair, Anchore
- **Supply Chain**: Sigstore, Cosign, SLSA
- **License Analysis**: Licensee, FOSSology

### 📊 Sistema de Scoring Avanzado
- **Algoritmo multi-dimensional** con factores de contexto
- **Puntuación de riesgo 0-100** con priorización automática
- **Análisis de exposición** en historial de Git
- **Detección de explotabilidad** con CVE/CWE mapping
- **Multiplicadores contextuales** (rama principal, producción, etc.)

### 🎨 Interfaces de Usuario
- **GUI de Escritorio**: Interfaz nativa con Tkinter
- **Interfaz Web**: Dashboard moderno con FastAPI y WebSockets
- **CLI Avanzado**: Línea de comandos con autocompletado y colores
- **API REST**: Documentación automática con Swagger/OpenAPI

### 📈 Reportes Avanzados
- **JSON Estructurado**: Para integración con SIEM/SOAR
- **HTML Interactivo**: Con gráficos, filtros y búsqueda
- **JUnit XML**: Compatible con CI/CD
- **SARIF**: Para compatibilidad con herramientas de seguridad
- **PDF**: Reportes ejecutivos automatizados
- **Formatos Personalizados**: Sistema de templates extensible

### 🔌 Sistema de Plugins
- **Arquitectura Extensible**: Plugins para scanners personalizados
- **API de Plugin**: Desarrollo fácil de integraciones
- **Gestión Automática**: Instalación, actualización y configuración
- **Tipos de Plugin**: Scanner, Notifier, Reporter, Integrator, Analyzer

### 🔗 Integraciones Empresariales
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins, Azure DevOps
- **SIEM**: Splunk, Elasticsearch, QRadar, Sentinel
- **Ticketing**: Jira, ServiceNow, GitHub Issues
- **Notificaciones**: Slack, Teams, Email, Webhooks
- **APIs**: REST API completa con autenticación OIDC

## 📦 Instalación

### Instalación desde RPM (Recomendado)
```bash
# Descargar e instalar RPM
sudo ./install_repo_scan.sh

# Verificar instalación
repo-scan --version
repo-scan-gui --help
```

### Instalación desde Código Fuente
```bash
# Clonar repositorio
git clone https://github.com/Origonlabs/CVE_Security.git
cd repo-scan

# Instalar dependencias
pip install -r requirements.txt

# Instalar en modo desarrollo
pip install -e .

# O instalar normalmente
pip install .
```

### Instalación de Dependencias
```bash
# Scanners requeridos
sudo dnf install gitleaks semgrep trivy bandit checkov

# O instalar individualmente
# Gitleaks
curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz -C /usr/local/bin

# Semgrep
pip install semgrep

# Trivy
sudo dnf install trivy

# Bandit
pip install bandit

# Checkov
pip install checkov
```

## 🎯 Uso Básico

### Interfaz Gráfica (GUI)
```bash
# Lanzar GUI de escritorio
repo-scan-gui

# Lanzar interfaz web
repo-scan-gui --web

# Interfaz web en puerto personalizado
repo-scan-gui --web --port 8080
```

### Escaneo de Repositorio Local
```bash
# Escanear repositorio local
repo-scan scan --path /path/to/repository

# Escanear con scanners específicos
repo-scan scan --path /path/to/repository --scanner semgrep --scanner gitleaks

# Escanear con patrones de exclusión
repo-scan scan --path /path/to/repository --exclude "*.test.js" --exclude "node_modules/*"
```

### Escaneo de Repositorio Remoto
```bash
# Clonar y escanear repositorio remoto
repo-scan scan --url https://github.com/user/repo.git

# Escanear rama específica
repo-scan scan --url https://github.com/user/repo.git --branch develop

# Escanear commit específico
repo-scan scan --url https://github.com/user/repo.git --commit abc123
```

### Opciones Avanzadas
```bash
# Escaneo con configuración personalizada
repo-scan scan \
  --path /path/to/repository \
  --scanner semgrep \
  --scanner gitleaks \
  --scanner trivy \
  --timeout 3600 \
  --parallel 8 \
  --max-workers 4 \
  --output-format json,html,junit \
  --output-dir ./reports \
  --severity-threshold HIGH \
  --risk-threshold 70 \
  --fail-on-critical \
  --continue-on-error \
  --verbose \
  --config-file ./custom-config.yaml
```

## ⚙️ Configuración

### Archivo de Configuración
```yaml
# ~/.config/repo-scan/config.yaml
general:
  workspace_dir: "/var/lib/repo-scan"
  log_level: "INFO"
  max_workers: 4

scanners:
  semgrep:
    enabled: true
    timeout: 1800
    rules: ["security", "python", "javascript"]
  
  gitleaks:
    enabled: true
    timeout: 600
    scan_history: true
  
  trivy:
    enabled: true
    timeout: 1200
    scan_types: ["vuln", "secret", "config"]

scoring:
  algorithm: "advanced"
  risk_thresholds:
    CRITICAL: 90
    HIGH: 70
    MEDIUM: 40
    LOW: 10

notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/..."
    channel: "#security-alerts"
  
  email:
    enabled: true
    smtp_server: "smtp.company.com"
    to_addresses: ["security-team@company.com"]
```

### Variables de Entorno
```bash
# Configuración general
export REPO_SCAN_WORKSPACE_DIR="/var/lib/repo-scan"
export REPO_SCAN_LOG_LEVEL="INFO"
export REPO_SCAN_MAX_WORKERS="4"

# Notificaciones
export REPO_SCAN_SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export REPO_SCAN_SLACK_CHANNEL="#security-alerts"
export REPO_SCAN_EMAIL_SMTP_SERVER="smtp.company.com"
export REPO_SCAN_EMAIL_SMTP_USERNAME="alerts@company.com"
export REPO_SCAN_EMAIL_SMTP_PASSWORD="password"
```

## 🔧 Comandos Avanzados

### Gestión de Configuración
```bash
# Ver configuración actual
repo-scan config show

# Establecer configuración
repo-scan config set scanners.semgrep.timeout 1800

# Exportar/importar configuración
repo-scan config export --output config-backup.yaml
repo-scan config import --file config-backup.yaml
```

### Gestión de Plugins
```bash
# Listar plugins
repo-scan plugins list

# Instalar plugin
repo-scan plugins install custom-scanner

# Habilitar/deshabilitar plugin
repo-scan plugins enable custom-scanner
repo-scan plugins disable custom-scanner
```

### Gestión de Reportes
```bash
# Listar reportes
repo-scan reports list

# Ver reporte específico
repo-scan reports show scan_20241221_143022

# Comparar reportes
repo-scan reports compare scan_old scan_new

# Generar reporte consolidado
repo-scan reports consolidate --from 2024-01-01 --to 2024-12-31
```

### Servidor API
```bash
# Iniciar servidor API
repo-scan server start --host 0.0.0.0 --port 8000

# Con autenticación OIDC
repo-scan server start \
  --auth-enabled \
  --auth-provider oidc \
  --oidc-client-id client-id \
  --oidc-client-secret client-secret \
  --oidc-issuer https://auth.company.com
```

## 🔗 Integración CI/CD

### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Run Security Scan
      run: |
        repo-scan scan \
          --path . \
          --scanner semgrep \
          --scanner gitleaks \
          --fail-on-critical \
          --ci github-actions
```

### GitLab CI
```yaml
security-scan:
  stage: security
  script:
    - repo-scan scan --path . --scanner semgrep --scanner gitleaks --ci gitlab-ci
  artifacts:
    reports:
      junit: security-reports/scan_*.xml
```

## 📊 Ejemplos de Salida

### Reporte JSON
```json
{
  "scan_id": "scan_20241221_143022",
  "risk_score": 78.5,
  "risk_level": "HIGH",
  "total_findings": 23,
  "findings": [
    {
      "id": "finding_001",
      "scanner": "semgrep",
      "severity": "CRITICAL",
      "title": "SQL Injection Vulnerability",
      "file_path": "src/api/users.py",
      "line_number": 45,
      "risk_score": 95.0,
      "remediation": {
        "description": "Use parameterized queries",
        "automation_suggested": true
      }
    }
  ]
}
```

### Reporte HTML
- Dashboard interactivo con gráficos
- Filtros por severidad, scanner, archivo
- Búsqueda en tiempo real
- Exportación a PDF
- Enlaces a remediación

## 🛠️ Desarrollo

### Estructura del Proyecto
```
repo-scan/
├── src/repo_scan/           # Código fuente principal
│   ├── core/               # Modelos y configuración
│   ├── detectors/          # Implementaciones de scanners
│   ├── gui/               # Interfaces gráficas
│   ├── plugins/           # Sistema de plugins
│   ├── notifications/     # Sistema de notificaciones
│   └── report/            # Generadores de reportes
├── docs/                  # Documentación
├── examples/              # Ejemplos de uso
├── packaging/             # Archivos de empaquetado
└── tests/                 # Tests unitarios
```

### Contribuir
1. Fork el repositorio
2. Crear rama de feature (`git checkout -b feature/amazing-feature`)
3. Commit cambios (`git commit -m 'Add amazing feature'`)
4. Push a la rama (`git push origin feature/amazing-feature`)
5. Abrir Pull Request

### Desarrollo de Plugins
```python
from repo_scan.plugins.base import BasePlugin, PluginType

class CustomScanner(BasePlugin):
    def get_metadata(self):
        return PluginMetadata(
            name="custom-scanner",
            type=PluginType.SCANNER,
            # ... más metadatos
        )
    
    def scan_repository(self, repo_path):
        # Implementar lógica de escaneo
        return findings
```

## 📚 Documentación Completa

- **[Características Avanzadas](docs/ADVANCED_FEATURES.md)** - Funcionalidades avanzadas
- **[Referencia CLI](docs/CLI_REFERENCE.md)** - Comandos completos
- **[Referencia API](docs/API_REFERENCE.md)** - API REST completa
- **[Configuración](docs/CONFIGURATION.md)** - Configuración avanzada
- **[Desarrollo de Plugins](docs/PLUGIN_DEVELOPMENT.md)** - Crear plugins
- **[Guía de Integración](docs/INTEGRATION_GUIDE.md)** - Integraciones CI/CD y SIEM

## 🤝 Soporte

- **Documentación**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/Origonlabs/CVE_Security/issues)
- **Discusiones**: [GitHub Discussions](https://github.com/Origonlabs/CVE_Security/discussions)
- **Email**: security-team@company.com

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para detalles.

## 🙏 Agradecimientos

- [Semgrep](https://semgrep.dev/) - Análisis estático de código
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Detección de secretos
- [Trivy](https://trivy.dev/) - Análisis de vulnerabilidades
- [Bandit](https://bandit.readthedocs.io/) - Análisis de seguridad Python
- [Checkov](https://www.checkov.io/) - Análisis de infraestructura como código

---

**Repo-Scan** - Escaneo de seguridad avanzado para repositorios modernos 🚀
