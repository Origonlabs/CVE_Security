# 🚀 Repo-Scan v1.1.1 - Release Notes

## 📋 Resumen

Esta versión incluye actualizaciones importantes en la configuración del proyecto, corrección de enlaces y preparación para el lanzamiento oficial con paquetes RPM.

## ✨ Nuevas Características

### 🔗 Actualización de Enlaces
- **Todos los enlaces de GitHub actualizados** al repositorio oficial `https://github.com/Origonlabs/CVE_Security`
- **Metadatos del proyecto corregidos** en `pyproject.toml`
- **Documentación actualizada** con enlaces funcionales

### 📦 Mejoras en Empaquetado
- **Preparación para lanzamiento oficial** con paquetes RPM
- **Configuración de empaquetado mejorada**
- **Scripts de instalación actualizados**

## 🔧 Cambios Técnicos

### Archivos Actualizados
- `README.md` - Enlaces de GitHub corregidos
- `docs/README.md` - Documentación actualizada
- `CHANGELOG.md` - Registro de cambios
- `pyproject.toml` - Metadatos y versión actualizada
- `README_RPM.md` - Enlaces de instalación
- `packaging/installer.sh` - Script de instalación
- `src/repo_scan/gui/main_window.py` - Enlaces en GUI
- `packaging/repo-scan.service` - Documentación del servicio

### Versión
- **Versión anterior**: 1.1.0
- **Versión actual**: 1.1.1

## 📥 Instalación

### Opción 1: Instalación desde RPM (Recomendado)
```bash
# Descargar el paquete RPM desde GitHub Releases
wget https://github.com/Origonlabs/CVE_Security/releases/download/v1.1.1/repo-scan-1.1.1-1.fc43.noarch.rpm

# Instalar el paquete
sudo dnf install repo-scan-1.1.1-1.fc43.noarch.rpm
```

### Opción 2: Instalación desde Código Fuente
```bash
# Clonar el repositorio
git clone https://github.com/Origonlabs/CVE_Security.git
cd CVE_Security

# Instalar dependencias
pip install -r requirements.txt

# Instalar el paquete
pip install .
```

### Opción 3: Instalación Automática
```bash
# Ejecutar el instalador automático
curl -sSL https://raw.githubusercontent.com/Origonlabs/CVE_Security/main/install_repo_scan.sh | bash
```

## 🎯 Uso Rápido

### Interfaz Gráfica
```bash
# Lanzar GUI de escritorio
repo-scan-gui

# Lanzar interfaz web
repo-scan-gui --web
```

### Línea de Comandos
```bash
# Escanear repositorio local
repo-scan scan --path /path/to/repository

# Escanear con scanners específicos
repo-scan scan --path /path/to/repository --scanner semgrep --scanner gitleaks
```

## 🔍 Características Principales

- **🔍 Múltiples Motores de Escaneo**: Semgrep, Gitleaks, Trivy, Bandit, Checkov
- **📊 Sistema de Scoring Avanzado**: Puntuación de riesgo 0-100
- **🎨 Interfaces Múltiples**: GUI, Web, CLI, API REST
- **📈 Reportes Avanzados**: JSON, HTML, JUnit, SARIF, PDF
- **🔌 Sistema de Plugins**: Arquitectura extensible
- **🔗 Integraciones**: CI/CD, SIEM, Notificaciones

## 🛠️ Requisitos del Sistema

- **Sistema Operativo**: Fedora 38+ (recomendado)
- **Python**: 3.11+
- **Memoria**: 2GB RAM mínimo
- **Espacio**: 1GB de espacio libre

## 📚 Documentación

- **[README Principal](README.md)** - Guía de inicio rápido
- **[Documentación Completa](docs/)** - Guías detalladas
- **[API Reference](docs/API_REFERENCE.md)** - Referencia de API
- **[Configuración](docs/CONFIGURATION.md)** - Guía de configuración

## 🤝 Soporte

- **Issues**: [GitHub Issues](https://github.com/Origonlabs/CVE_Security/issues)
- **Discusiones**: [GitHub Discussions](https://github.com/Origonlabs/CVE_Security/discussions)
- **Documentación**: [docs/](docs/)

## 🙏 Agradecimientos

Gracias a todos los contribuidores y a la comunidad de seguridad por hacer posible este proyecto.

---

**Repo-Scan v1.1.1** - Escaneo de seguridad avanzado para repositorios modernos 🚀
