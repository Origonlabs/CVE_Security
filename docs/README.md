# Repo-Scan: Advanced Repository Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Fedora](https://img.shields.io/badge/Fedora-38+-blue.svg)](https://fedoraproject.org/)
[![Security](https://img.shields.io/badge/security-scanner-red.svg)](https://github.com/Origonlabs/CVE_Security)

**Repo-Scan** is an advanced repository security scanning tool that provides comprehensive security analysis with multiple scanning engines, advanced risk scoring, and enterprise-level reporting and integration capabilities.

## Key Features

### Multiple Scanning Engines
- **SAST (Static Application Security Testing)**: Semgrep, Bandit, SonarQube
- **SCA (Software Composition Analysis)**: Trivy, Grype, Snyk
- **Secret Detection**: Gitleaks, TruffleHog, Detect-secrets
- **IaC Security**: Checkov, Terrascan, TFSec, Kube-score
- **Container Security**: Trivy, Clair, Anchore
- **Supply Chain**: Sigstore, Cosign, SLSA
- **License Analysis**: Licensee, FOSSology

### Advanced Scoring System
- **Multi-dimensional algorithm** with contextual factors
- **Risk scoring 0-100** with automatic prioritization
- **Exposure analysis** in Git history
- **Exploitability detection** with CVE/CWE mapping
- **Contextual multipliers** (main branch, production, etc.)

### User Interfaces
- **Desktop GUI**: Native interface with Tkinter
- **Web Interface**: Modern dashboard with FastAPI and WebSockets
- **Advanced CLI**: Command line with autocompletion and colors
- **REST API**: Automatic documentation with Swagger/OpenAPI

### Advanced Reporting
- **Structured JSON**: For SIEM/SOAR integration
- **Interactive HTML**: With charts, filters and search
- **JUnit XML**: CI/CD compatible
- **SARIF**: For security tool compatibility
- **PDF**: Automated executive reports
- **Custom Formats**: Extensible template system

### Plugin System
- **Extensible Architecture**: Plugins for custom scanners
- **Plugin API**: Easy integration development
- **Automatic Management**: Installation, update and configuration
- **Plugin Types**: Scanner, Notifier, Reporter, Integrator, Analyzer

### Enterprise Integrations
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins, Azure DevOps
- **SIEM**: Splunk, Elasticsearch, QRadar, Sentinel
- **Ticketing**: Jira, ServiceNow, GitHub Issues
- **Notifications**: Slack, Teams, Email, Webhooks
- **APIs**: Complete REST API with OIDC authentication

## Installation

### Installation from RPM (Recommended)
```bash
# Download and install RPM
sudo ./install_repo_scan.sh

# Verify installation
repo-scan --version
repo-scan-gui --help
```

### Installation from Source Code
```bash
# Clone repository
git clone https://github.com/Origonlabs/CVE_Security.git
cd CVE_Security

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Or install normally
pip install .
```

### Dependency Installation
```bash
# Required scanners
sudo dnf install gitleaks semgrep trivy bandit checkov

# Or install individually
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

## Basic Usage

### Graphical User Interface (GUI)
```bash
# Launch desktop GUI
repo-scan-gui

# Launch web interface
repo-scan-gui --web

# Web interface on custom port
repo-scan-gui --web --port 8080
```

### Local Repository Scanning
```bash
# Scan local repository
repo-scan scan --path /path/to/repository

# Scan with specific scanners
repo-scan scan --path /path/to/repository --scanner semgrep --scanner gitleaks

# Scan with exclusion patterns
repo-scan scan --path /path/to/repository --exclude "*.test.js" --exclude "node_modules/*"
```

### Remote Repository Scanning
```bash
# Clone and scan remote repository
repo-scan scan --url https://github.com/user/repo.git

# Scan specific branch
repo-scan scan --url https://github.com/user/repo.git --branch develop

# Scan specific commit
repo-scan scan --url https://github.com/user/repo.git --commit abc123
```

### Advanced Options
```bash
# Scan with custom configuration
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

## Configuration

### Configuration File
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

### Environment Variables
```bash
# General configuration
export REPO_SCAN_WORKSPACE_DIR="/var/lib/repo-scan"
export REPO_SCAN_LOG_LEVEL="INFO"
export REPO_SCAN_MAX_WORKERS="4"

# Notifications
export REPO_SCAN_SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export REPO_SCAN_SLACK_CHANNEL="#security-alerts"
export REPO_SCAN_EMAIL_SMTP_SERVER="smtp.company.com"
export REPO_SCAN_EMAIL_SMTP_USERNAME="alerts@company.com"
export REPO_SCAN_EMAIL_SMTP_PASSWORD="password"
```

## Advanced Commands

### Configuration Management
```bash
# View current configuration
repo-scan config show

# Set configuration
repo-scan config set scanners.semgrep.timeout 1800

# Export/import configuration
repo-scan config export --output config-backup.yaml
repo-scan config import --file config-backup.yaml
```

### Plugin Management
```bash
# List plugins
repo-scan plugins list

# Install plugin
repo-scan plugins install custom-scanner

# Enable/disable plugin
repo-scan plugins enable custom-scanner
repo-scan plugins disable custom-scanner
```

### Report Management
```bash
# List reports
repo-scan reports list

# View specific report
repo-scan reports show scan_20241221_143022

# Compare reports
repo-scan reports compare scan_old scan_new

# Generate consolidated report
repo-scan reports consolidate --from 2024-01-01 --to 2024-12-31
```

### API Server
```bash
# Start API server
repo-scan server start --host 0.0.0.0 --port 8000

# With OIDC authentication
repo-scan server start \
  --auth-enabled \
  --auth-provider oidc \
  --oidc-client-id client-id \
  --oidc-client-secret client-secret \
  --oidc-issuer https://auth.company.com
```

## CI/CD Integration

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

## Output Examples

### JSON Report
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

### HTML Report
- Interactive dashboard with charts
- Filters by severity, scanner, file
- Real-time search
- PDF export
- Remediation links

## Development

### Project Structure
```
repo-scan/
├── src/repo_scan/           # Main source code
│   ├── core/               # Models and configuration
│   ├── detectors/          # Scanner implementations
│   ├── gui/               # Graphical interfaces
│   ├── plugins/           # Plugin system
│   ├── notifications/     # Notification system
│   └── report/            # Report generators
├── docs/                  # Documentation
├── examples/              # Usage examples
├── packaging/             # Packaging files
└── tests/                 # Unit tests
```

### Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Plugin Development
```python
from repo_scan.plugins.base import BasePlugin, PluginType

class CustomScanner(BasePlugin):
    def get_metadata(self):
        return PluginMetadata(
            name="custom-scanner",
            type=PluginType.SCANNER,
            # ... more metadata
        )
    
    def scan_repository(self, repo_path):
        # Implement scanning logic
        return findings
```

## Complete Documentation

- **[Advanced Features](ADVANCED_FEATURES.md)** - Advanced functionality
- **[CLI Reference](CLI_REFERENCE.md)** - Complete commands
- **[API Reference](API_REFERENCE.md)** - Complete REST API
- **[Configuration](CONFIGURATION.md)** - Advanced configuration
- **[Plugin Development](PLUGIN_DEVELOPMENT.md)** - Create plugins
- **[Integration Guide](INTEGRATION_GUIDE.md)** - CI/CD and SIEM integrations

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/Origonlabs/CVE_Security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Origonlabs/CVE_Security/discussions)
- **Email**: security-team@company.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Semgrep](https://semgrep.dev/) - Static code analysis
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret detection
- [Trivy](https://trivy.dev/) - Vulnerability analysis
- [Bandit](https://bandit.readthedocs.io/) - Python security analysis
- [Checkov](https://www.checkov.io/) - Infrastructure as code analysis

---

**Repo-Scan** - Advanced security scanning for modern repositories