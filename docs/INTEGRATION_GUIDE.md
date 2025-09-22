# 🔗 Guía de Integración

## 🎯 Integraciones CI/CD

### GitHub Actions
```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0  # Full history for gitleaks
    
    - name: Setup repo-scan
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install repo-scan
      run: |
        pip install repo-scan
        # Install required scanners
        curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz -C /usr/local/bin
        pip install semgrep
        pip install bandit
    
    - name: Run security scan
      run: |
        repo-scan scan \
          --path . \
          --scanner semgrep \
          --scanner gitleaks \
          --scanner bandit \
          --output-format json,html,junit \
          --output-dir ./security-reports \
          --fail-on-critical \
          --fail-on-high \
          --risk-threshold 70 \
          --ci github-actions
      env:
        REPO_SCAN_SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
        REPO_SCAN_SLACK_CHANNEL: "#security-alerts"
    
    - name: Upload security reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: security-reports
        path: security-reports/
    
    - name: Comment PR with results
      if: github.event_name == 'pull_request'
      run: |
        repo-scan reports comment-pr \
          --report-dir ./security-reports \
          --github-token ${{ secrets.GITHUB_TOKEN }}
    
    - name: Create security issues
      if: failure()
      run: |
        repo-scan reports create-issues \
          --report-dir ./security-reports \
          --github-token ${{ secrets.GITHUB_TOKEN }} \
          --severity-threshold HIGH
```

### GitLab CI
```yaml
# .gitlab-ci.yml
stages:
  - security

security-scan:
  stage: security
  image: python:3.11
  before_script:
    - pip install repo-scan
    - curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz -C /usr/local/bin
    - pip install semgrep bandit
  script:
    - repo-scan scan
        --path .
        --scanner semgrep
        --scanner gitleaks
        --scanner bandit
        --output-format json,html,junit
        --output-dir ./security-reports
        --fail-on-critical
        --fail-on-high
        --risk-threshold 70
        --ci gitlab-ci
  artifacts:
    when: always
    paths:
      - security-reports/
    reports:
      junit: security-reports/scan_*.xml
  variables:
    REPO_SCAN_SLACK_WEBHOOK_URL: $SLACK_WEBHOOK_URL
    REPO_SCAN_SLACK_CHANNEL: "#security-alerts"
```

### Jenkins Pipeline
```groovy
// Jenkinsfile
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Install repo-scan
                    sh '''
                        pip install repo-scan
                        curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz -C /usr/local/bin
                        pip install semgrep bandit
                    '''
                    
                    // Run security scan
                    sh '''
                        repo-scan scan \\
                            --path . \\
                            --scanner semgrep \\
                            --scanner gitleaks \\
                            --scanner bandit \\
                            --output-format json,html,junit \\
                            --output-dir ./security-reports \\
                            --fail-on-critical \\
                            --fail-on-high \\
                            --risk-threshold 70 \\
                            --ci jenkins
                    '''
                }
            }
            post {
                always {
                    // Archive reports
                    archiveArtifacts artifacts: 'security-reports/**', fingerprint: true
                    
                    // Publish JUnit results
                    junit 'security-reports/scan_*.xml'
                }
                failure {
                    // Send notification on failure
                    sh '''
                        repo-scan notifications send \\
                            --report-dir ./security-reports \\
                            --channel slack \\
                            --severity-threshold HIGH
                    '''
                }
            }
        }
    }
}
```

### Azure DevOps
```yaml
# azure-pipelines.yml
trigger:
- main
- develop

pool:
  vmImage: 'ubuntu-latest'

stages:
- stage: Security
  displayName: 'Security Scan'
  jobs:
  - job: SecurityScan
    displayName: 'Run Security Scan'
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.11'
    
    - script: |
        pip install repo-scan
        curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz -C /usr/local/bin
        pip install semgrep bandit
      displayName: 'Install repo-scan and scanners'
    
    - script: |
        repo-scan scan \
          --path . \
          --scanner semgrep \
          --scanner gitleaks \
          --scanner bandit \
          --output-format json,html,junit \
          --output-dir ./security-reports \
          --fail-on-critical \
          --fail-on-high \
          --risk-threshold 70 \
          --ci azure-devops
      displayName: 'Run Security Scan'
      env:
        REPO_SCAN_SLACK_WEBHOOK_URL: $(SLACK_WEBHOOK_URL)
        REPO_SCAN_SLACK_CHANNEL: "#security-alerts"
    
    - task: PublishTestResults@2
      condition: always()
      inputs:
        testResultsFormat: 'JUnit'
        testResultsFiles: 'security-reports/scan_*.xml'
        testRunTitle: 'Security Scan Results'
    
    - task: PublishBuildArtifacts@1
      condition: always()
      inputs:
        pathToPublish: 'security-reports'
        artifactName: 'security-reports'
```

## 🔗 Integraciones SIEM

### Splunk Integration
```python
# splunk_integration.py
import requests
import json
from typing import Dict, Any, List
from repo_scan.core.models import ScanResult, Finding

class SplunkIntegration:
    """Splunk SIEM integration."""
    
    def __init__(self, config: Dict[str, Any]):
        self.splunk_host = config["splunk_host"]
        self.splunk_port = config["splunk_port"]
        self.splunk_token = config["splunk_token"]
        self.index = config.get("index", "security")
        self.sourcetype = config.get("sourcetype", "repo-scan")
    
    def send_scan_results(self, scan_result: ScanResult) -> bool:
        """Send scan results to Splunk."""
        try:
            # Prepare events
            events = self._prepare_events(scan_result)
            
            # Send to Splunk
            for event in events:
                self._send_event(event)
            
            return True
            
        except Exception as e:
            print(f"Failed to send to Splunk: {e}")
            return False
    
    def _prepare_events(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """Prepare events for Splunk."""
        events = []
        
        # Main scan event
        scan_event = {
            "time": scan_result.scan_timestamp.isoformat(),
            "source": "repo-scan",
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": {
                "scan_id": scan_result.scan_id,
                "repository": scan_result.repository,
                "risk_score": scan_result.risk_score,
                "risk_level": scan_result.risk_level,
                "total_findings": len(scan_result.findings),
                "scan_duration": scan_result.scan_duration,
                "event_type": "scan_completed"
            }
        }
        events.append(scan_event)
        
        # Individual finding events
        for finding in scan_result.findings:
            finding_event = {
                "time": scan_result.scan_timestamp.isoformat(),
                "source": "repo-scan",
                "sourcetype": self.sourcetype,
                "index": self.index,
                "event": {
                    "scan_id": scan_result.scan_id,
                    "finding_id": finding.id,
                    "scanner": finding.scanner,
                    "severity": finding.severity.value,
                    "title": finding.title,
                    "description": finding.description,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "risk_score": finding.risk_score,
                    "confidence": finding.confidence,
                    "tags": finding.tags,
                    "cwe_id": finding.cwe_id,
                    "cve_id": finding.cve_id,
                    "cvss_score": finding.cvss_score,
                    "event_type": "security_finding"
                }
            }
            events.append(finding_event)
        
        return events
    
    def _send_event(self, event: Dict[str, Any]) -> None:
        """Send event to Splunk."""
        url = f"https://{self.splunk_host}:{self.splunk_port}/services/collector/event"
        
        headers = {
            "Authorization": f"Splunk {self.splunk_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(url, json=event, headers=headers, verify=False)
        response.raise_for_status()
```

### Elasticsearch Integration
```python
# elasticsearch_integration.py
from elasticsearch import Elasticsearch
from typing import Dict, Any, List
from repo_scan.core.models import ScanResult, Finding

class ElasticsearchIntegration:
    """Elasticsearch integration."""
    
    def __init__(self, config: Dict[str, Any]):
        self.es_host = config["elasticsearch_host"]
        self.es_port = config["elasticsearch_port"]
        self.es_username = config.get("elasticsearch_username")
        self.es_password = config.get("elasticsearch_password")
        self.index = config.get("index", "repo-scan-security")
        
        # Initialize Elasticsearch client
        self.es = Elasticsearch(
            [{"host": self.es_host, "port": self.es_port}],
            http_auth=(self.es_username, self.es_password) if self.es_username else None,
            verify_certs=False
        )
    
    def send_scan_results(self, scan_result: ScanResult) -> bool:
        """Send scan results to Elasticsearch."""
        try:
            # Create index if it doesn't exist
            self._create_index()
            
            # Send scan metadata
            self._index_scan_metadata(scan_result)
            
            # Send individual findings
            for finding in scan_result.findings:
                self._index_finding(finding, scan_result.scan_id)
            
            return True
            
        except Exception as e:
            print(f"Failed to send to Elasticsearch: {e}")
            return False
    
    def _create_index(self) -> None:
        """Create index with mapping."""
        mapping = {
            "mappings": {
                "properties": {
                    "scan_id": {"type": "keyword"},
                    "repository": {"type": "keyword"},
                    "risk_score": {"type": "float"},
                    "risk_level": {"type": "keyword"},
                    "scanner": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "title": {"type": "text"},
                    "description": {"type": "text"},
                    "file_path": {"type": "keyword"},
                    "line_number": {"type": "integer"},
                    "risk_score": {"type": "float"},
                    "confidence": {"type": "float"},
                    "tags": {"type": "keyword"},
                    "cwe_id": {"type": "keyword"},
                    "cve_id": {"type": "keyword"},
                    "cvss_score": {"type": "float"},
                    "timestamp": {"type": "date"}
                }
            }
        }
        
        if not self.es.indices.exists(index=self.index):
            self.es.indices.create(index=self.index, body=mapping)
    
    def _index_scan_metadata(self, scan_result: ScanResult) -> None:
        """Index scan metadata."""
        doc = {
            "scan_id": scan_result.scan_id,
            "repository": scan_result.repository,
            "risk_score": scan_result.risk_score,
            "risk_level": scan_result.risk_level,
            "total_findings": len(scan_result.findings),
            "scan_duration": scan_result.scan_duration,
            "timestamp": scan_result.scan_timestamp,
            "event_type": "scan_completed"
        }
        
        self.es.index(
            index=self.index,
            id=f"scan_{scan_result.scan_id}",
            body=doc
        )
    
    def _index_finding(self, finding: Finding, scan_id: str) -> None:
        """Index individual finding."""
        doc = {
            "scan_id": scan_id,
            "finding_id": finding.id,
            "scanner": finding.scanner,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "risk_score": finding.risk_score,
            "confidence": finding.confidence,
            "tags": finding.tags,
            "cwe_id": finding.cwe_id,
            "cve_id": finding.cve_id,
            "cvss_score": finding.cvss_score,
            "timestamp": finding.timestamp,
            "event_type": "security_finding"
        }
        
        self.es.index(
            index=self.index,
            id=f"finding_{finding.id}",
            body=doc
        )
```

## 🎫 Integraciones de Ticketing

### Jira Integration
```python
# jira_integration.py
from jira import JIRA
from typing import Dict, Any, List
from repo_scan.core.models import ScanResult, Finding

class JiraIntegration:
    """Jira ticketing integration."""
    
    def __init__(self, config: Dict[str, Any]):
        self.jira_url = config["jira_url"]
        self.jira_username = config["jira_username"]
        self.jira_password = config["jira_password"]
        self.project_key = config["project_key"]
        self.issue_type = config.get("issue_type", "Bug")
        
        # Initialize Jira client
        self.jira = JIRA(
            server=self.jira_url,
            basic_auth=(self.jira_username, self.jira_password)
        )
    
    def create_issues_from_scan(self, scan_result: ScanResult) -> List[str]:
        """Create Jira issues from scan results."""
        created_issues = []
        
        # Filter findings that need issues
        critical_findings = [
            f for f in scan_result.findings 
            if f.severity.value in ["CRITICAL", "HIGH"] and f.risk_score >= 70
        ]
        
        for finding in critical_findings:
            issue_key = self._create_issue(finding, scan_result)
            if issue_key:
                created_issues.append(issue_key)
        
        return created_issues
    
    def _create_issue(self, finding: Finding, scan_result: ScanResult) -> str:
        """Create Jira issue for finding."""
        try:
            # Prepare issue data
            issue_data = {
                "project": {"key": self.project_key},
                "summary": f"Security Finding: {finding.title}",
                "description": self._format_description(finding, scan_result),
                "issuetype": {"name": self.issue_type},
                "priority": {"name": self._map_priority(finding.severity)},
                "labels": finding.tags + ["security", "repo-scan"],
                "customfield_10001": finding.risk_score,  # Risk score field
                "customfield_10002": finding.scanner,     # Scanner field
            }
            
            # Create issue
            issue = self.jira.create_issue(fields=issue_data)
            
            # Add file attachment if available
            if finding.file_path:
                self._add_file_attachment(issue, finding.file_path)
            
            return issue.key
            
        except Exception as e:
            print(f"Failed to create Jira issue: {e}")
            return None
    
    def _format_description(self, finding: Finding, scan_result: ScanResult) -> str:
        """Format finding description for Jira."""
        description = f"""
h2. Security Finding Details

*Scanner:* {finding.scanner}
*Severity:* {finding.severity.value}
*Risk Score:* {finding.risk_score:.1f}/100
*Confidence:* {finding.confidence:.1f}

h3. Description
{finding.description}

h3. Location
*File:* {finding.file_path or 'N/A'}
*Line:* {finding.line_number or 'N/A'}

h3. Code Snippet
{{
{finding.code_snippet or 'N/A'}
}}

h3. Remediation
{finding.remediation.description if finding.remediation else 'No remediation provided'}

h3. References
{finding.remediation.references if finding.remediation else 'No references provided'}

h3. Scan Information
*Scan ID:* {scan_result.scan_id}
*Repository:* {scan_result.repository}
*Scan Date:* {scan_result.scan_timestamp}
        """
        
        return description.strip()
    
    def _map_priority(self, severity: str) -> str:
        """Map severity to Jira priority."""
        priority_map = {
            "CRITICAL": "Highest",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low"
        }
        return priority_map.get(severity, "Medium")
    
    def _add_file_attachment(self, issue, file_path: str) -> None:
        """Add file as attachment to Jira issue."""
        try:
            with open(file_path, 'rb') as f:
                self.jira.add_attachment(issue=issue, attachment=f)
        except Exception as e:
            print(f"Failed to add file attachment: {e}")
```

## 🔔 Integraciones de Notificaciones

### Microsoft Teams Integration
```python
# teams_integration.py
import requests
import json
from typing import Dict, Any
from repo_scan.core.models import ScanResult

class TeamsIntegration:
    """Microsoft Teams integration."""
    
    def __init__(self, config: Dict[str, Any]):
        self.webhook_url = config["webhook_url"]
        self.severity_threshold = config.get("severity_threshold", "HIGH")
    
    def send_notification(self, scan_result: ScanResult) -> bool:
        """Send notification to Teams."""
        try:
            # Check if notification should be sent
            if not self._should_send_notification(scan_result):
                return True
            
            # Prepare message
            message = self._prepare_message(scan_result)
            
            # Send to Teams
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=30
            )
            response.raise_for_status()
            
            return True
            
        except Exception as e:
            print(f"Failed to send Teams notification: {e}")
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
        
        return False
    
    def _prepare_message(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Prepare Teams message."""
        # Determine color based on risk level
        color_map = {
            "CRITICAL": "FF0000",  # Red
            "HIGH": "FF8C00",      # Orange
            "MEDIUM": "FFD700",    # Gold
            "LOW": "00FF00"        # Green
        }
        color = color_map.get(scan_result.risk_level, "808080")
        
        # Prepare facts
        facts = [
            {"name": "Risk Level", "value": scan_result.risk_level},
            {"name": "Risk Score", "value": f"{scan_result.risk_score:.1f}/100"},
            {"name": "Total Findings", "value": str(len(scan_result.findings))},
            {"name": "Scan Duration", "value": f"{scan_result.scan_duration:.1f}s"}
        ]
        
        # Prepare sections
        sections = [
            {
                "activityTitle": f"Security Scan Results: {scan_result.repository}",
                "activitySubtitle": f"Scan completed with {scan_result.risk_level} risk level",
                "activityImage": "https://img.icons8.com/color/48/000000/security-checked.png",
                "facts": facts,
                "markdown": True
            }
        ]
        
        # Add findings section if there are critical/high findings
        critical_findings = [
            f for f in scan_result.findings 
            if f.severity.value in ["CRITICAL", "HIGH"]
        ]
        
        if critical_findings:
            findings_text = "\n".join([
                f"**{finding.title}** ({finding.severity.value})\n"
                f"*{finding.file_path}:{finding.line_number}* - {finding.scanner}"
                for finding in critical_findings[:5]  # Top 5 findings
            ])
            
            sections.append({
                "activityTitle": "Critical/High Findings",
                "text": findings_text,
                "markdown": True
            })
        
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"Security Scan: {scan_result.risk_level} risk level",
            "sections": sections
        }
```

## 🎯 Configuración de Integraciones

### Configuración Global
```yaml
# config.yaml
integrations:
  # SIEM
  siem:
    enabled: true
    type: "splunk"
    splunk:
      host: "splunk.company.com"
      port: 8089
      token: "splunk-token"
      index: "security"
      sourcetype: "repo-scan"
  
  # Ticketing
  ticketing:
    enabled: true
    type: "jira"
    jira:
      url: "https://company.atlassian.net"
      username: "repo-scan@company.com"
      password: "jira-password"
      project_key: "SEC"
      issue_type: "Bug"
  
  # Notifications
  notifications:
    teams:
      enabled: true
      webhook_url: "https://company.webhook.office.com/..."
      severity_threshold: "HIGH"
```

### Variables de Entorno
```bash
# SIEM
export REPO_SCAN_SIEM_ENABLED="true"
export REPO_SCAN_SIEM_TYPE="splunk"
export REPO_SCAN_SPLUNK_HOST="splunk.company.com"
export REPO_SCAN_SPLUNK_TOKEN="splunk-token"

# Jira
export REPO_SCAN_JIRA_URL="https://company.atlassian.net"
export REPO_SCAN_JIRA_USERNAME="repo-scan@company.com"
export REPO_SCAN_JIRA_PASSWORD="jira-password"
export REPO_SCAN_JIRA_PROJECT_KEY="SEC"

# Teams
export REPO_SCAN_TEAMS_WEBHOOK_URL="https://company.webhook.office.com/..."
```
