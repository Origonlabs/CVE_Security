# Repo-Scan v1.1.1 - Release Notes

## Summary

This version includes important updates to project configuration, link corrections, and preparation for official release with RPM packages.

## New Features

### GitHub Links Update
- **All GitHub links updated** to the official repository `https://github.com/Origonlabs/CVE_Security`
- **Project metadata corrected** in `pyproject.toml`
- **Documentation updated** with functional links

### Packaging Improvements
- **Preparation for official release** with RPM packages
- **Improved packaging configuration**
- **Updated installation scripts**

## Technical Changes

### Updated Files
- `README.md` - GitHub links corrected
- `docs/README.md` - Updated documentation
- `CHANGELOG.md` - Change log
- `pyproject.toml` - Updated metadata and version
- `README_RPM.md` - Installation links
- `packaging/installer.sh` - Installation script
- `src/repo_scan/gui/main_window.py` - GUI links
- `packaging/repo-scan.service` - Service documentation

### Version
- **Previous version**: 1.1.0
- **Current version**: 1.1.1

## Installation

### Option 1: Installation from RPM (Recommended)
```bash
# Download the RPM package from GitHub Releases
wget https://github.com/Origonlabs/CVE_Security/releases/download/v1.1.1/repo-scan-1.1.1-1.fc43.noarch.rpm

# Install the package
sudo dnf install repo-scan-1.1.1-1.fc43.noarch.rpm
```

### Option 2: Installation from Source Code
```bash
# Clone the repository
git clone https://github.com/Origonlabs/CVE_Security.git
cd CVE_Security

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install .
```

### Option 3: Automatic Installation
```bash
# Run the automatic installer
curl -sSL https://raw.githubusercontent.com/Origonlabs/CVE_Security/main/install_repo_scan.sh | bash
```

## Quick Usage

### Graphical Interface
```bash
# Launch desktop GUI
repo-scan-gui

# Launch web interface
repo-scan-gui --web
```

### Command Line
```bash
# Scan local repository
repo-scan scan --path /path/to/repository

# Scan with specific scanners
repo-scan scan --path /path/to/repository --scanner semgrep --scanner gitleaks
```

## Key Features

- **Multiple Scanning Engines**: Semgrep, Gitleaks, Trivy, Bandit, Checkov
- **Advanced Risk Scoring**: Risk scoring 0-100
- **Multiple Interfaces**: GUI, Web, CLI, REST API
- **Advanced Reports**: JSON, HTML, JUnit, SARIF, PDF
- **Plugin System**: Extensible architecture
- **Integrations**: CI/CD, SIEM, Notifications

## System Requirements

- **Operating System**: Fedora 38+ (recommended)
- **Python**: 3.11+
- **Memory**: 2GB RAM minimum
- **Storage**: 1GB free space

## Documentation

- **[Main README](README.md)** - Quick start guide
- **[Complete Documentation](docs/)** - Detailed guides
- **[API Reference](docs/API_REFERENCE.md)** - API reference
- **[Configuration](docs/CONFIGURATION.md)** - Configuration guide

## Support

- **Issues**: [GitHub Issues](https://github.com/Origonlabs/CVE_Security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Origonlabs/CVE_Security/discussions)
- **Documentation**: [docs/](docs/)

## Acknowledgments

Thanks to all contributors and the security community for making this project possible.

---

**Repo-Scan v1.1.1** - Advanced security scanning for modern repositories