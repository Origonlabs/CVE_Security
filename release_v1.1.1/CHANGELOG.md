# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Pending
- (sin entradas)

## [1.1.1] - 2025-01-21

### Added
- Actualización de todos los enlaces de GitHub al repositorio oficial
- Mejoras en la documentación y configuración del proyecto
- Preparación para lanzamiento oficial con paquetes RPM

### Changed
- Todos los enlaces ahora apuntan a `https://github.com/Origonlabs/CVE_Security`
- Actualización de metadatos del proyecto en pyproject.toml
- Mejoras en la configuración de empaquetado

### Fixed
- Enlaces rotos en documentación
- Configuración de metadatos del proyecto

## [1.1.0] - 2025-09-21

### Added
- FastAPI backend con gestor de colas asincrónicas y API `/api/v1/*` lista para producción.
- Interfaz web rediseñada con dashboards “glassmorphism”, tarjetas dinámicas y gráficos Chart.js.
- Paquete RPM reforzado con logrotate, completions para bash/zsh y página man.
- Documentación ampliada en `docs/` (API, configuración, integraciones y plugins).

### Changed
- Merge inteligente de variables de entorno para configuraciones API/notifications.
- Makefile y build scripts actualizados para automatizar `rpmbuild` y versionado 1.1.0.

### Fixed
- Evitar instalaciones duplicadas del servicio systemd en el SPEC.
- Formularios web ahora serializan correctamente múltiples motores y mantienen progreso en vivo.

### Security
- Se mantienen límites de tiempo, usuario dedicado y rotación de logs por defecto.

## [1.0.0] - 2024-01-XX

### Added
- **Core Features**
  - Repository security scanning with multiple engines
  - Support for local and remote repositories
  - Git history analysis for secret detection
  - Technology stack detection
  - Risk scoring and prioritization

- **Security Scanners**
  - Semgrep for SAST (Static Application Security Testing)
  - Gitleaks for secret detection
  - Trivy for SCA (Software Composition Analysis) and container security
  - Bandit for Python security analysis
  - Checkov for IaC (Infrastructure as Code) security

- **Reporting**
  - JSON reports for programmatic consumption
  - HTML reports with interactive interface
  - JUnit reports for CI/CD integration
  - Risk breakdown and statistics

- **API and Integration**
  - REST API with FastAPI
  - CLI interface with Typer
  - CI/CD integration examples (GitHub Actions, GitLab CI)
  - Notification support (Slack, Email)

- **Configuration**
  - YAML configuration files
  - Environment variable support
  - Customizable risk scoring parameters
  - Scanner-specific configuration options

- **Packaging and Distribution**
  - RPM package for Fedora
  - Python package with pip
  - Systemd service integration
  - Shell completion support

### Technical Details
- **Architecture**
  - Modular detector system
  - Plugin architecture for extensibility
  - Asynchronous scanning with parallel execution
  - Resource management and limits

- **Security**
  - Non-privileged execution
  - Input validation
  - Secure file handling
  - GPG signature verification

- **Performance**
  - Parallel scanner execution
  - Configurable resource limits
  - Efficient file processing
  - Caching mechanisms

### Documentation
- Comprehensive README with usage examples
- API documentation
- Configuration reference
- Installation guides
- Development setup instructions

## [0.9.0] - 2024-01-XX (Pre-release)

### Added
- Initial development version
- Basic scanner integration
- Core architecture implementation
- CLI interface prototype

### Changed
- Multiple refactoring iterations
- Improved error handling
- Enhanced configuration system

### Fixed
- Various bug fixes during development
- Performance optimizations
- Memory leak fixes

## [0.8.0] - 2024-01-XX (Alpha)

### Added
- First alpha release
- Basic SAST scanning
- Simple risk scoring
- JSON report generation

### Known Issues
- Limited scanner support
- Basic error handling
- No API interface
- Limited documentation

---

## Release Notes

### Version 1.0.0
This is the first stable release of repo-scan. It provides a comprehensive security scanning solution for software repositories with support for multiple scanning engines, advanced risk scoring, and extensive reporting capabilities.

**Key Features:**
- Multi-engine security scanning
- Advanced risk assessment
- Multiple report formats
- REST API for automation
- CI/CD integration
- Fedora RPM packaging

**Installation:**
```bash
# From PyPI
pip install repo-scan

# From RPM (Fedora)
sudo dnf install repo-scan-1.0.0-1.fc38.noarch.rpm

# From source
git clone https://github.com/Origonlabs/CVE_Security.git
cd repo-scan
pip install .
```

**Quick Start:**
```bash
# Scan local repository
repo-scan --path /path/to/repo

# Scan remote repository
repo-scan --url https://github.com/user/repo.git

# Generate HTML report
repo-scan --path /path/to/repo --format html --output ./reports
```

### Breaking Changes
None (first release)

### Migration Guide
N/A (first release)

### Deprecations
None

### Security Advisories
None

---

## Contributing

When contributing to this project, please update this changelog with your changes. Follow the format:

```markdown
### Added
- New features

### Changed
- Changes to existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security improvements
```

## Links

- [Keep a Changelog](https://keepachangelog.com/)
- [Semantic Versioning](https://semver.org/)
- [Project Repository](https://github.com/Origonlabs/CVE_Security)
- [Documentation](https://repo-scan.readthedocs.io)
- [Issue Tracker](https://github.com/Origonlabs/CVE_Security/issues)
