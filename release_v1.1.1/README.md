# Repo-Scan: Advanced Repository Security Scanning Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Fedora](https://img.shields.io/badge/Fedora-supported-green.svg)](https://getfedora.org/)

Repo-Scan es una herramienta avanzada de análisis de seguridad para repositorios que proporciona análisis integral de seguridad para repositorios de software. Soporta múltiples motores de escaneo incluyendo SAST, SCA, detección de secretos, escaneo de IaC y más.

## 🚀 Características

### Motores de Escaneo
- **SAST (Static Application Security Testing)**: Análisis estático de código con Semgrep y Bandit
- **SCA (Software Composition Analysis)**: Análisis de dependencias con Trivy
- **Detección de Secretos**: Detección de secretos y credenciales con Gitleaks
- **IaC (Infrastructure as Code)**: Análisis de seguridad de infraestructura con Checkov
- **Contenedores**: Análisis de seguridad de contenedores con Trivy
- **Supply Chain**: Verificación de cadena de suministro

### Sistema de Scoring Avanzado
- Puntuación de riesgo personalizable (0-100)
- Factores multiplicadores basados en contexto
- Priorización automática de hallazgos
- Análisis de exposición en historial de Git
- Detección de explotabilidad

### Reportes y Salidas
- **JSON**: Formato estructurado para integración
- **HTML**: Reporte interactivo y visual
- **JUnit**: Compatible con CI/CD
- **API REST**: Para automatización

### Interfaces de Usuario
- **GUI de Escritorio**: Interfaz nativa con Tkinter
- **Interfaz Web**: Dashboard moderno con FastAPI
- **CLI**: Línea de comandos para automatización

### Integración y Automatización
- Integración con CI/CD (GitHub Actions, GitLab CI)
- Notificaciones (Slack, Email)
- API REST con autenticación
- Sistema de plugins extensible
- Soporte para repositorios locales y remotos

## 📦 Instalación

### Instalación en Fedora

#### Opción 1: Instalación Automática
```bash
# Clonar el repositorio
git clone https://github.com/Origonlabs/CVE_Security.git
cd repo-scan

# Ejecutar el instalador
sudo ./packaging/installer.sh
```

#### Opción 2: Instalación Manual
```bash
# Instalar dependencias del sistema
sudo dnf install python3 python3-pip git curl wget

# Instalar herramientas de seguridad
pip3 install semgrep bandit checkov
# Instalar Gitleaks y Trivy (ver documentación)

# Instalar repo-scan
pip3 install repo-scan
```

#### Opción 3: RPM Package
```bash
# Construir el paquete RPM
./build_rpm.sh

# Instalar el paquete
sudo dnf install dist/repo-scan-1.1.0-1*.noarch.rpm
```

#### Opción 4: Instalar el RPM oficial
Descarga los artefactos publicados en la sección de releases (`repo-scan-1.1.0-1.<dist>.noarch.rpm`) y ejecútalo:

```bash
sudo dnf install ./repo-scan-1.1.0-1.fc$(rpm -E %fedora).noarch.rpm
```

El paquete instala:

- Servicio systemd `repo-scan.service` (FastAPI backend)
- Configuración en `/etc/repo-scan/config.yaml`
- Directorios de runtime en `/var/lib/log/cache/repo-scan`
- Rotación de logs en `/etc/logrotate.d/repo-scan`
- Completados bash/zsh y página man `repo-scan(1)`

### Instalación desde Código Fuente
```bash
# Clonar el repositorio
git clone https://github.com/Origonlabs/CVE_Security.git
cd repo-scan

# Instalar en modo desarrollo
pip install -e .

# O instalar normalmente
pip install .
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
repo-scan --path /path/to/repository

# Escanear con scanners específicos
repo-scan --path /path/to/repository --scanner semgrep --scanner gitleaks

# Escanear con patrones de exclusión
repo-scan --path /path/to/repository --exclude "*.test.js" --exclude "node_modules/*"
```

### Escaneo de Repositorio Remoto
```bash
# Clonar y escanear repositorio remoto
repo-scan --url https://github.com/user/repo.git

# Escanear rama específica
repo-scan --url https://github.com/user/repo.git --branch develop
```

### Generación de Reportes
```bash
# Generar reporte JSON
repo-scan --path /path/to/repository --format json --output ./reports

# Generar reporte HTML
repo-scan --path /path/to/repository --format html --output ./reports

# Generar todos los formatos
repo-scan --path /path/to/repository --format all --output ./reports
```

### Modo Verbose y Debug
```bash
# Modo verbose para más información
repo-scan --path /path/to/repository --verbose

# Modo debug para información detallada
repo-scan --path /path/to/repository --debug
```

## ⚙️ Configuración

### Archivo de Configuración
El archivo de configuración se encuentra en `/etc/repo-scan/config.yaml` (instalación del sistema) o `~/.repo-scan/config.yaml` (instalación de usuario).

```yaml
# Configuración general
debug: false
verbose: false
workspace_dir: "/var/tmp/repo-scan"
max_workers: 4
scan_timeout: 3600

# Configuración de scanners
scanners:
  semgrep:
    enabled: true
    timeout: 300
    memory_limit: "1g"
    custom_rules: null
  
  gitleaks:
    enabled: true
    timeout: 300
    custom_config: null

# Configuración de notificaciones
notifications:
  slack_webhook: "https://hooks.slack.com/services/..."
  email_smtp_server: "smtp.gmail.com"
  email_username: "user@example.com"
  email_to: ["admin@example.com"]

# Configuración de scoring de riesgo
risk_scoring:
  severity_weights:
    LOW: 10
    MEDIUM: 40
    HIGH: 75
    CRITICAL: 100
  
  multipliers:
    private_key: 2.0
    api_token: 1.8
    published_exploit: 1.5
```

### Variables de Entorno
```bash
export REPO_SCAN_DEBUG=true
export REPO_SCAN_VERBOSE=true
export REPO_SCAN_WORKSPACE="/custom/workspace"
export DATABASE_URL="postgresql://user:pass@localhost/repo_scan"
export SLACK_WEBHOOK="https://hooks.slack.com/services/..."
```

## 🔧 API REST

### Iniciar el Servidor API
```bash
# Iniciar servidor API
repo-scan serve --host 0.0.0.0 --port 8000

# Con autenticación
repo-scan serve --host 0.0.0.0 --port 8000 --auth-enabled
```

### Endpoints Principales
```bash
# Escanear repositorio
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/path/to/repo", "scanners": ["semgrep", "gitleaks"]}'

# Obtener resultados de escaneo
curl http://localhost:8000/api/v1/scan/{scan_id}

# Listar scanners disponibles
curl http://localhost:8000/api/v1/scanners

# Obtener estadísticas
curl http://localhost:8000/api/v1/stats
```

## 🔌 Sistema de Plugins

### Crear Plugin Personalizado
```python
from repo_scan.detectors.base import BaseDetector
from repo_scan.detectors.registry import register_detector
from repo_scan.core.models import Finding, FindingType, Severity, ScanConfig

class CustomDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="custom-detector",
            scanner_type=FindingType.CUSTOM,
            description="Custom security detector"
        )
    
    def is_available(self) -> bool:
        return True  # Implementar verificación de disponibilidad
    
    def scan(self, scan_config: ScanConfig) -> List[Finding]:
        findings = []
        # Implementar lógica de escaneo
        return findings

# Registrar el plugin
register_detector(CustomDetector)
```

## 🚀 Integración CI/CD

### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install repo-scan
        run: |
          pip install repo-scan
          # Instalar scanners
          pip install semgrep bandit checkov
      
      - name: Run security scan
        run: |
          repo-scan --path . --format all --output ./reports
      
      - name: Upload reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: ./reports
```

### GitLab CI
```yaml
security_scan:
  stage: test
  image: python:3.11
  before_script:
    - pip install repo-scan semgrep bandit checkov
  script:
    - repo-scan --path . --format all --output ./reports
  artifacts:
    reports:
      junit: reports/scan_*.xml
    paths:
      - reports/
    expire_in: 1 week
```

## 📊 Sistema de Scoring

### Factores de Puntuación
- **Severidad Base**: LOW (10), MEDIUM (40), HIGH (75), CRITICAL (100)
- **Exposición en Historial**: ×1.25 si se encuentra en commits anteriores
- **Tipo de Secreto**: Claves privadas (×2.0), tokens API (×1.8)
- **Explotabilidad**: ×1.5 si hay exploits publicados
- **Rama de Producción**: ×1.3 si está en main/master/prod
- **Confianza**: Alta confianza (×1.1), baja confianza (×0.8)

### Niveles de Riesgo
- **CRITICAL**: 75-100 puntos
- **HIGH**: 50-74 puntos
- **MEDIUM**: 25-49 puntos
- **LOW**: 0-24 puntos

## 🛠️ Desarrollo

### Configurar Entorno de Desarrollo
```bash
# Clonar repositorio
git clone https://github.com/Origonlabs/CVE_Security.git
cd repo-scan

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias de desarrollo
pip install -e ".[dev]"

# Instalar pre-commit hooks
pre-commit install

# Ejecutar tests
pytest

# Ejecutar linting
black src/
isort src/
flake8 src/
mypy src/
```

### Estructura del Proyecto
```
repo-scan/
├── src/repo_scan/           # Código fuente principal
│   ├── cli.py              # Interfaz de línea de comandos
│   ├── orchestrator.py     # Orquestador principal
│   ├── detectors/          # Detectores de seguridad
│   ├── report/             # Generadores de reportes
│   ├── scoring.py          # Sistema de scoring
│   └── core/               # Componentes centrales
├── packaging/              # Archivos de empaquetado
├── tests/                  # Tests unitarios
├── docs/                   # Documentación
└── examples/               # Ejemplos de uso
```

## 📈 Monitoreo y Logs

### Logs del Sistema
```bash
# Ver logs del servicio
journalctl -u repo-scan -f

# Ver logs de aplicación
tail -f /var/log/repo-scan/repo-scan.log

# Ver logs de errores
journalctl -u repo-scan --priority=err
```

### Métricas y Monitoreo
- Métricas de escaneo (duración, hallazgos, errores)
- Uso de recursos (CPU, memoria, disco)
- Disponibilidad de scanners
- Estadísticas de uso de API

## 🔒 Seguridad

### Mejores Prácticas
- Ejecutar con usuario no privilegiado
- Limitar acceso a directorios de trabajo
- Validar entradas de usuario
- Usar HTTPS para API
- Rotar secretos regularmente
- Monitorear logs de seguridad

### Configuración de Seguridad
```yaml
# Configuración de seguridad
security:
  verify_gpg_signatures: true
  allowed_git_protocols: ["https", "ssh"]
  max_scan_duration: 3600
  max_file_size: 10485760  # 10MB
  quarantine_suspicious_files: true
```

## 🤝 Contribuir

1. Fork el repositorio
2. Crear rama de feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

### Guías de Contribución
- Seguir PEP 8 para código Python
- Escribir tests para nuevas funcionalidades
- Actualizar documentación
- Usar conventional commits

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para detalles.

## 🆘 Soporte

- **Documentación**: [https://repo-scan.readthedocs.io](https://repo-scan.readthedocs.io)
- **Issues**: [https://github.com/Origonlabs/CVE_Security/issues](https://github.com/Origonlabs/CVE_Security/issues)
- **Discusiones**: [https://github.com/Origonlabs/CVE_Security/discussions](https://github.com/Origonlabs/CVE_Security/discussions)
- **Email**: security@example.com

## 🙏 Agradecimientos

- [Semgrep](https://semgrep.dev/) - SAST engine
- [Gitleaks](https://github.com/zricethezav/gitleaks) - Secret detection
- [Trivy](https://trivy.dev/) - SCA and container security
- [Bandit](https://bandit.readthedocs.io/) - Python security linter
- [Checkov](https://www.checkov.io/) - IaC security scanner
- [Typer](https://typer.tiangolo.com/) - CLI framework
- [FastAPI](https://fastapi.tiangolo.com/) - Web framework
