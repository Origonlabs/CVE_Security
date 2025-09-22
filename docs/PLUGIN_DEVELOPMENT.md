# 🔌 Desarrollo de Plugins

## 🎯 Sistema de Plugins Avanzado

### Arquitectura de Plugins
```python
# Estructura de un plugin
plugin_name/
├── __init__.py
├── plugin.py          # Plugin principal
├── config.yaml        # Configuración del plugin
├── requirements.txt   # Dependencias
├── README.md         # Documentación
└── tests/
    ├── __init__.py
    └── test_plugin.py
```

### Plugin Base Class
```python
# src/repo_scan/plugins/base.py
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class PluginType(Enum):
    SCANNER = "scanner"
    NOTIFIER = "notifier"
    REPORTER = "reporter"
    INTEGRATOR = "integrator"
    ANALYZER = "analyzer"

@dataclass
class PluginMetadata:
    name: str
    version: str
    description: str
    author: str
    license: str
    type: PluginType
    dependencies: List[str]
    config_schema: Dict[str, Any]
    supported_languages: List[str]
    supported_formats: List[str]

class BasePlugin(ABC):
    """Base class for all repo-scan plugins."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metadata = self.get_metadata()
        self.validate_config()
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        pass
    
    @abstractmethod
    def validate_config(self) -> None:
        """Validate plugin configuration."""
        pass
    
    @abstractmethod
    def initialize(self) -> None:
        """Initialize the plugin."""
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Cleanup plugin resources."""
        pass
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)
    
    def set_config(self, key: str, value: Any) -> None:
        """Set configuration value."""
        self.config[key] = value
```

### Plugin Scanner Example
```python
# custom_scanner/plugin.py
import requests
import json
from typing import List, Dict, Any
from repo_scan.plugins.base import BasePlugin, PluginType, PluginMetadata
from repo_scan.core.models import Finding, Severity

class CustomSecurityScanner(BasePlugin):
    """Custom security scanner plugin."""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom-security-scanner",
            version="1.0.0",
            description="Custom security scanner for proprietary vulnerabilities",
            author="Security Team",
            license="MIT",
            type=PluginType.SCANNER,
            dependencies=["requests>=2.25.0"],
            config_schema={
                "api_endpoint": {"type": "string", "required": True},
                "api_key": {"type": "string", "required": True},
                "timeout": {"type": "integer", "default": 300},
                "severity_threshold": {"type": "string", "default": "LOW"}
            },
            supported_languages=["python", "javascript", "java"],
            supported_formats=["json", "yaml"]
        )
    
    def validate_config(self) -> None:
        """Validate plugin configuration."""
        required_keys = ["api_endpoint", "api_key"]
        for key in required_keys:
            if key not in self.config:
                raise ValueError(f"Missing required config: {key}")
    
    def initialize(self) -> None:
        """Initialize the plugin."""
        self.api_endpoint = self.get_config("api_endpoint")
        self.api_key = self.get_config("api_key")
        self.timeout = self.get_config("timeout", 300)
        self.severity_threshold = self.get_config("severity_threshold", "LOW")
        
        # Test API connection
        self._test_connection()
    
    def cleanup(self) -> None:
        """Cleanup plugin resources."""
        pass
    
    def _test_connection(self) -> None:
        """Test API connection."""
        try:
            response = requests.get(
                f"{self.api_endpoint}/health",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=10
            )
            response.raise_for_status()
        except Exception as e:
            raise ConnectionError(f"Failed to connect to API: {e}")
    
    def scan_repository(self, repo_path: str) -> List[Finding]:
        """Scan repository for security issues."""
        findings = []
        
        try:
            # Prepare scan request
            scan_request = {
                "repository_path": repo_path,
                "options": {
                    "timeout": self.timeout,
                    "severity_threshold": self.severity_threshold
                }
            }
            
            # Send scan request
            response = requests.post(
                f"{self.api_endpoint}/scan",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json=scan_request,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            # Process results
            results = response.json()
            findings = self._process_results(results)
            
        except Exception as e:
            # Log error and return empty findings
            self.logger.error(f"Scan failed: {e}")
            findings = []
        
        return findings
    
    def _process_results(self, results: Dict[str, Any]) -> List[Finding]:
        """Process API results into Finding objects."""
        findings = []
        
        for result in results.get("findings", []):
            finding = Finding(
                id=f"custom_{result['id']}",
                scanner="custom-security-scanner",
                severity=Severity(result["severity"]),
                title=result["title"],
                description=result["description"],
                file_path=result.get("file_path"),
                line_number=result.get("line_number"),
                column_number=result.get("column_number"),
                code_snippet=result.get("code_snippet"),
                risk_score=self._calculate_risk_score(result),
                confidence=result.get("confidence", 0.8),
                tags=result.get("tags", []),
                cwe_id=result.get("cwe_id"),
                cve_id=result.get("cve_id"),
                cvss_score=result.get("cvss_score"),
                remediation=self._create_remediation(result)
            )
            findings.append(finding)
        
        return findings
    
    def _calculate_risk_score(self, result: Dict[str, Any]) -> float:
        """Calculate risk score for finding."""
        base_scores = {
            "CRITICAL": 100,
            "HIGH": 75,
            "MEDIUM": 40,
            "LOW": 10
        }
        
        base_score = base_scores.get(result["severity"], 20)
        
        # Apply multipliers
        multiplier = 1.0
        if result.get("exploitable"):
            multiplier *= 1.5
        if result.get("publicly_exposed"):
            multiplier *= 1.3
        if result.get("in_production"):
            multiplier *= 1.2
        
        return min(100, base_score * multiplier)
    
    def _create_remediation(self, result: Dict[str, Any]) -> Remediation:
        """Create remediation object."""
        return Remediation(
            description=result.get("remediation", "No remediation provided"),
            confidence=result.get("remediation_confidence", 0.7),
            automation_suggested=result.get("automation_suggested", False),
            steps=result.get("remediation_steps", []),
            references=result.get("references", [])
        )
```

### Plugin Notifier Example
```python
# slack_notifier/plugin.py
import requests
import json
from typing import Dict, Any, List
from repo_scan.plugins.base import BasePlugin, PluginType, PluginMetadata
from repo_scan.core.models import ScanResult

class SlackNotifier(BasePlugin):
    """Slack notification plugin."""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="slack-notifier",
            version="1.0.0",
            description="Send scan results to Slack",
            author="Security Team",
            license="MIT",
            type=PluginType.NOTIFIER,
            dependencies=["requests>=2.25.0"],
            config_schema={
                "webhook_url": {"type": "string", "required": True},
                "channel": {"type": "string", "default": "#security-alerts"},
                "username": {"type": "string", "default": "repo-scan"},
                "icon_emoji": {"type": "string", "default": ":shield:"},
                "severity_threshold": {"type": "string", "default": "HIGH"},
                "include_findings": {"type": "boolean", "default": True},
                "max_findings": {"type": "integer", "default": 10}
            },
            supported_languages=[],
            supported_formats=[]
        )
    
    def validate_config(self) -> None:
        """Validate plugin configuration."""
        if "webhook_url" not in self.config:
            raise ValueError("Missing required config: webhook_url")
    
    def initialize(self) -> None:
        """Initialize the plugin."""
        self.webhook_url = self.get_config("webhook_url")
        self.channel = self.get_config("channel", "#security-alerts")
        self.username = self.get_config("username", "repo-scan")
        self.icon_emoji = self.get_config("icon_emoji", ":shield:")
        self.severity_threshold = self.get_config("severity_threshold", "HIGH")
        self.include_findings = self.get_config("include_findings", True)
        self.max_findings = self.get_config("max_findings", 10)
    
    def cleanup(self) -> None:
        """Cleanup plugin resources."""
        pass
    
    def send_notification(self, scan_result: ScanResult) -> bool:
        """Send notification to Slack."""
        try:
            # Check if notification should be sent
            if not self._should_send_notification(scan_result):
                return True
            
            # Prepare message
            message = self._prepare_message(scan_result)
            
            # Send to Slack
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=30
            )
            response.raise_for_status()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {e}")
            return False
    
    def _should_send_notification(self, scan_result: ScanResult) -> bool:
        """Check if notification should be sent."""
        severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        threshold_index = severity_levels.index(self.severity_threshold)
        
        # Check if any finding meets severity threshold
        for finding in scan_result.findings:
            finding_index = severity_levels.index(finding.severity.value)
            if finding_index >= threshold_index:
                return True
        
        # Check risk score threshold
        if scan_result.risk_score >= 70:  # HIGH risk threshold
            return True
        
        return False
    
    def _prepare_message(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Prepare Slack message."""
        # Determine color based on risk level
        color_map = {
            "CRITICAL": "#FF0000",  # Red
            "HIGH": "#FF8C00",      # Orange
            "MEDIUM": "#FFD700",    # Gold
            "LOW": "#00FF00"        # Green
        }
        color = color_map.get(scan_result.risk_level, "#808080")
        
        # Prepare attachments
        attachments = []
        
        # Main scan result
        main_attachment = {
            "color": color,
            "title": f"Security Scan Results: {scan_result.repository}",
            "title_link": scan_result.repository_url,
            "fields": [
                {
                    "title": "Risk Level",
                    "value": scan_result.risk_level,
                    "short": True
                },
                {
                    "title": "Risk Score",
                    "value": f"{scan_result.risk_score:.1f}/100",
                    "short": True
                },
                {
                    "title": "Total Findings",
                    "value": str(len(scan_result.findings)),
                    "short": True
                },
                {
                    "title": "Scan Duration",
                    "value": f"{scan_result.scan_duration:.1f}s",
                    "short": True
                }
            ],
            "footer": "repo-scan",
            "ts": int(scan_result.scan_timestamp.timestamp())
        }
        attachments.append(main_attachment)
        
        # Findings summary
        if self.include_findings and scan_result.findings:
            findings_text = self._format_findings(scan_result.findings)
            findings_attachment = {
                "color": color,
                "title": "Top Findings",
                "text": findings_text,
                "mrkdwn_in": ["text"]
            }
            attachments.append(findings_attachment)
        
        return {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": attachments
        }
    
    def _format_findings(self, findings: List[Finding]) -> str:
        """Format findings for Slack message."""
        # Sort by risk score (highest first)
        sorted_findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)
        
        # Take top findings
        top_findings = sorted_findings[:self.max_findings]
        
        formatted = []
        for finding in top_findings:
            severity_emoji = {
                "CRITICAL": ":red_circle:",
                "HIGH": ":orange_circle:",
                "MEDIUM": ":yellow_circle:",
                "LOW": ":green_circle:"
            }.get(finding.severity.value, ":white_circle:")
            
            file_info = f"`{finding.file_path}:{finding.line_number}`" if finding.file_path else "N/A"
            
            formatted.append(
                f"{severity_emoji} *{finding.title}* ({finding.risk_score:.1f})\n"
                f"   {file_info} - {finding.scanner}"
            )
        
        return "\n".join(formatted)
```

### Plugin Configuration
```yaml
# custom_scanner/config.yaml
name: "custom-security-scanner"
version: "1.0.0"
description: "Custom security scanner for proprietary vulnerabilities"
author: "Security Team"
license: "MIT"
type: "scanner"

dependencies:
  - "requests>=2.25.0"
  - "pyyaml>=6.0"

config_schema:
  api_endpoint:
    type: "string"
    required: true
    description: "API endpoint for the custom scanner"
  api_key:
    type: "string"
    required: true
    description: "API key for authentication"
  timeout:
    type: "integer"
    default: 300
    description: "Timeout in seconds"
  severity_threshold:
    type: "string"
    default: "LOW"
    enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: "Minimum severity to report"

supported_languages:
  - "python"
  - "javascript"
  - "java"
  - "go"

supported_formats:
  - "json"
  - "yaml"
```

### Plugin Installation
```bash
# Instalar plugin desde directorio local
repo-scan plugins install ./custom_scanner

# Instalar plugin desde Git
repo-scan plugins install https://github.com/company/custom-scanner.git

# Instalar plugin desde PyPI
repo-scan plugins install custom-security-scanner

# Instalar plugin con configuración
repo-scan plugins install custom_scanner --config api_endpoint=https://api.company.com --config api_key=secret
```

### Plugin Development Tools
```bash
# Crear estructura de plugin
repo-scan plugins create my-plugin --type scanner

# Validar plugin
repo-scan plugins validate my-plugin

# Test plugin
repo-scan plugins test my-plugin

# Empaquetar plugin
repo-scan plugins package my-plugin --output my-plugin.tar.gz
```

### Plugin API
```python
# Plugin API para integración
from repo_scan.plugins import PluginManager

# Cargar plugin
plugin_manager = PluginManager()
plugin = plugin_manager.load_plugin("custom-security-scanner", config)

# Ejecutar plugin
if plugin.type == PluginType.SCANNER:
    findings = plugin.scan_repository("/path/to/repo")
elif plugin.type == PluginType.NOTIFIER:
    success = plugin.send_notification(scan_result)

# Limpiar plugin
plugin.cleanup()
```
