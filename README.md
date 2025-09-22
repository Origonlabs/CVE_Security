# Repo-Scan: Advanced Repository Security Scanning Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Fedora](https://img.shields.io/badge/Fedora-supported-green.svg)](https://getfedora.org/)

Repo-Scan is an advanced repository security scanning tool that provides comprehensive security analysis for software repositories. It supports multiple scanning engines including SAST, SCA, secret detection, IaC scanning, and more.

## Features

### Security Scanning Engines
- **SAST (Static Application Security Testing)**: Static code analysis with Semgrep and Bandit
- **SCA (Software Composition Analysis)**: Dependency analysis with Trivy
- **Secret Detection**: Secret and credential detection with Gitleaks
- **IaC (Infrastructure as Code)**: Infrastructure security analysis with Checkov
- **Container Security**: Container security analysis with Trivy
- **Supply Chain**: Supply chain verification

### Advanced Risk Scoring System
- Customizable risk scoring (0-100)
- Context-based multiplier factors
- Automatic finding prioritization
- Git history exposure analysis
- Exploitability detection

### Reporting and Output Formats
- **JSON**: Structured format for integration
- **HTML**: Interactive and visual reports
- **JUnit**: CI/CD compatible
- **SARIF**: Security tool compatibility
- **PDF**: Executive reports

### User Interfaces
- **Desktop GUI**: Native interface with Tkinter
- **Web Interface**: Modern dashboard with FastAPI
- **CLI**: Command line interface for automation
- **REST API**: Programmatic access

### Integration and Automation
- CI/CD integration (GitHub Actions, GitLab CI, Jenkins)
- Notification systems (Slack, Email, Webhooks)
- REST API with authentication
- Extensible plugin system
- Local and remote repository support

## Installation

### Fedora Installation

#### Option 1: Automatic Installation
```bash
# Clone the repository
git clone https://github.com/Origonlabs/CVE_Security.git
cd CVE_Security

# Run the installer
sudo ./packaging/installer.sh
```

#### Option 2: Manual Installation
```bash
# Install system dependencies
sudo dnf install python3 python3-pip git curl wget

# Install security tools
pip3 install semgrep bandit checkov
# Install Gitleaks and Trivy (see documentation)

# Install repo-scan
pip3 install repo-scan
```

#### Option 3: RPM Package
```bash
# Build the RPM package
./build_rpm.sh

# Install the package
sudo dnf install dist/repo-scan-1.1.1-1*.noarch.rpm
```

#### Option 4: Official RPM Installation
Download the published artifacts from the releases section (`repo-scan-1.1.1-1.<dist>.noarch.rpm`) and install:

```bash
sudo dnf install ./repo-scan-1.1.1-1.fc$(rpm -E %fedora).noarch.rpm
```

The package installs:
- systemd service `repo-scan.service` (FastAPI backend)
- Configuration in `/etc/repo-scan/config.yaml`
- Runtime directories in `/var/lib/repo-scan`
- Log rotation in `/etc/logrotate.d/repo-scan`
- Bash/zsh completions and man page `repo-scan(1)`

### Source Code Installation
```bash
# Clone the repository
git clone https://github.com/Origonlabs/CVE_Security.git
cd CVE_Security

# Install in development mode
pip install -e .

# Or install normally
pip install .
```

## Usage

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
repo-scan --path /path/to/repository

# Scan with specific scanners
repo-scan --path /path/to/repository --scanner semgrep --scanner gitleaks

# Scan with exclusion patterns
repo-scan --path /path/to/repository --exclude "*.test.js" --exclude "node_modules/*"
```

### Remote Repository Scanning
```bash
# Clone and scan remote repository
repo-scan --url https://github.com/user/repo.git

# Scan specific branch
repo-scan --url https://github.com/user/repo.git --branch develop
```

### Report Generation
```bash
# Generate JSON report
repo-scan --path /path/to/repository --format json --output ./reports

# Generate HTML report
repo-scan --path /path/to/repository --format html --output ./reports

# Generate all formats
repo-scan --path /path/to/repository --format all --output ./reports
```

### Verbose and Debug Modes
```bash
# Verbose mode for more information
repo-scan --path /path/to/repository --verbose

# Debug mode for detailed information
repo-scan --path /path/to/repository --debug
```

## Configuration

### Configuration File
The configuration file is located at `/etc/repo-scan/config.yaml` (system installation) or `~/.repo-scan/config.yaml` (user installation).

```yaml
# General configuration
debug: false
verbose: false
workspace_dir: "/var/tmp/repo-scan"
max_workers: 4
scan_timeout: 3600

# Scanner configuration
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

# Notification configuration
notifications:
  slack_webhook: "https://hooks.slack.com/services/..."
  email_smtp_server: "smtp.gmail.com"
  email_username: "user@example.com"
  email_to: ["admin@example.com"]

# Risk scoring configuration
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

### Environment Variables
```bash
export REPO_SCAN_DEBUG=true
export REPO_SCAN_VERBOSE=true
export REPO_SCAN_WORKSPACE="/custom/workspace"
export DATABASE_URL="postgresql://user:pass@localhost/repo_scan"
export SLACK_WEBHOOK="https://hooks.slack.com/services/..."
```

## REST API

### Starting the API Server
```bash
# Start API server
repo-scan serve --host 0.0.0.0 --port 8000

# With authentication
repo-scan serve --host 0.0.0.0 --port 8000 --auth-enabled
```

### Main Endpoints
```bash
# Scan repository
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/path/to/repo", "scanners": ["semgrep", "gitleaks"]}'

# Get scan results
curl http://localhost:8000/api/v1/scan/{scan_id}

# List available scanners
curl http://localhost:8000/api/v1/scanners

# Get statistics
curl http://localhost:8000/api/v1/stats
```

## Plugin System

### Creating Custom Plugins
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
        return True  # Implement availability check
    
    def scan(self, scan_config: ScanConfig) -> List[Finding]:
        findings = []
        # Implement scanning logic
        return findings

# Register the plugin
register_detector(CustomDetector)
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
      - uses: actions/checkout@v3
      
      - name: Install repo-scan
        run: |
          pip install repo-scan
          # Install scanners
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

## Risk Scoring System

### Scoring Factors
- **Base Severity**: LOW (10), MEDIUM (40), HIGH (75), CRITICAL (100)
- **History Exposure**: ×1.25 if found in previous commits
- **Secret Type**: Private keys (×2.0), API tokens (×1.8)
- **Exploitability**: ×1.5 if published exploits exist
- **Production Branch**: ×1.3 if in main/master/prod
- **Confidence**: High confidence (×1.1), low confidence (×0.8)

### Risk Levels
- **CRITICAL**: 75-100 points
- **HIGH**: 50-74 points
- **MEDIUM**: 25-49 points
- **LOW**: 0-24 points

## Development

### Setting Up Development Environment
```bash
# Clone repository
git clone https://github.com/Origonlabs/CVE_Security.git
cd CVE_Security

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Run linting
black src/
isort src/
flake8 src/
mypy src/
```

### Project Structure
```
repo-scan/
├── src/repo_scan/           # Main source code
│   ├── cli.py              # Command line interface
│   ├── orchestrator.py     # Main orchestrator
│   ├── detectors/          # Security detectors
│   ├── report/             # Report generators
│   ├── scoring.py          # Scoring system
│   └── core/               # Core components
├── packaging/              # Packaging files
├── tests/                  # Unit tests
├── docs/                   # Documentation
└── examples/               # Usage examples
```

## Monitoring and Logs

### System Logs
```bash
# View service logs
journalctl -u repo-scan -f

# View application logs
tail -f /var/log/repo-scan/repo-scan.log

# View error logs
journalctl -u repo-scan --priority=err
```

### Metrics and Monitoring
- Scanning metrics (duration, findings, errors)
- Resource usage (CPU, memory, disk)
- Scanner availability
- API usage statistics

## Security

### Best Practices
- Run with non-privileged user
- Limit access to working directories
- Validate user inputs
- Use HTTPS for API
- Rotate secrets regularly
- Monitor security logs

### Security Configuration
```yaml
# Security configuration
security:
  verify_gpg_signatures: true
  allowed_git_protocols: ["https", "ssh"]
  max_scan_duration: 3600
  max_file_size: 10485760  # 10MB
  quarantine_suspicious_files: true
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

### Contribution Guidelines
- Follow PEP 8 for Python code
- Write tests for new features
- Update documentation
- Use conventional commits

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/Origonlabs/CVE_Security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Origonlabs/CVE_Security/discussions)
- **Email**: security@example.com

## Acknowledgments

- [Semgrep](https://semgrep.dev/) - SAST engine
- [Gitleaks](https://github.com/zricethezav/gitleaks) - Secret detection
- [Trivy](https://trivy.dev/) - SCA and container security
- [Bandit](https://bandit.readthedocs.io/) - Python security linter
- [Checkov](https://www.checkov.io/) - IaC security scanner
- [Typer](https://typer.tiangolo.com/) - CLI framework
- [FastAPI](https://fastapi.tiangolo.com/) - Web framework