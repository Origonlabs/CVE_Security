"""
Checkov IaC security detector implementation.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseDetector
from ..core.models import Finding, FindingType, ScanConfig, Severity
from ..utils import retry_on_exception


class CheckovDetector(BaseDetector):
    """
    Checkov detector for Infrastructure as Code security analysis.
    """
    
    def __init__(self) -> None:
        """Initialize the Checkov detector."""
        super().__init__(
            name="checkov",
            scanner_type=FindingType.IAC,
            description="Infrastructure as Code security analysis with Checkov"
        )
    
    def is_available(self) -> bool:
        """Check if Checkov is available."""
        try:
            result = self.run_command(["checkov", "--version"], capture_output=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_version(self) -> Optional[str]:
        """Get Checkov version."""
        try:
            result = self.run_command(["checkov", "--version"], capture_output=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def get_required_dependencies(self) -> List[str]:
        """Get required dependencies."""
        return ["checkov"]
    
    def get_supported_file_extensions(self) -> List[str]:
        """Get supported file extensions."""
        return [
            ".tf", ".tfvars",  # Terraform
            ".yaml", ".yml",  # Kubernetes, CloudFormation
            ".json",  # CloudFormation, ARM templates
            ".dockerfile", "Dockerfile",  # Docker
            ".py",  # Serverless framework
            ".js", ".ts",  # CDK
        ]
    
    @retry_on_exception(max_retries=2, delay=1.0)
    def scan(self, scan_config: ScanConfig) -> List[Finding]:
        """
        Scan repository with Checkov.
        
        Args:
            scan_config: Scan configuration
            
        Returns:
            List of security findings
        """
        findings = []
        
        # Only scan if IaC files are present
        if not self._has_iac_files(scan_config.repository.path):
            return findings
        
        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name
            
            # Build Checkov command
            command = [
                "checkov",
                "-d", str(scan_config.repository.path),
                "--framework", "all",  # Scan all supported frameworks
                "--output", "json",
                "--output-file-path", output_file,
                "--quiet",  # Reduce output verbosity
                "--no-guide",  # Don't show remediation guide in output
            ]
            
            # Add custom config if specified
            if self._config.get("custom_config"):
                command.extend(["--config-file", self._config["custom_config"]])
            
            # Add skip patterns
            for pattern in scan_config.exclude_patterns:
                command.extend(["--skip-path", pattern])
            
            # Add specific frameworks if configured
            if self._config.get("frameworks"):
                command.extend(["--framework"] + self._config["frameworks"])
            
            # Run Checkov
            result = self.run_command(
                command,
                cwd=scan_config.repository.path,
                timeout=self._config.get("timeout", 300)
            )
            
            # Parse results
            if Path(output_file).exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    checkov_results = json.load(f)
                
                findings = self._parse_checkov_results(checkov_results, scan_config)
            
            # Cleanup
            Path(output_file).unlink(missing_ok=True)
            
        except Exception as e:
            # If Checkov fails, return empty results rather than crashing
            print(f"Checkov scan failed: {e}")
        
        return findings
    
    def _has_iac_files(self, repo_path: str) -> bool:
        """
        Check if repository contains IaC files.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            True if IaC files are found, False otherwise
        """
        try:
            path = Path(repo_path)
            iac_patterns = [
                "*.tf", "*.tfvars",  # Terraform
                "*.yaml", "*.yml",  # Kubernetes, CloudFormation
                "Dockerfile", "*.dockerfile",  # Docker
                "*.json",  # CloudFormation, ARM
            ]
            
            for pattern in iac_patterns:
                if list(path.rglob(pattern)):
                    return True
            
            return False
        except Exception:
            return False
    
    def _parse_checkov_results(
        self, results: Dict[str, Any], scan_config: ScanConfig
    ) -> List[Finding]:
        """
        Parse Checkov JSON results into Finding objects.
        
        Args:
            results: Checkov JSON results
            scan_config: Scan configuration
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        if "results" not in results:
            return findings
        
        for result in results["results"]:
            if "failed_checks" not in result:
                continue
            
            for check in result["failed_checks"]:
                try:
                    # Extract basic information
                    check_id = check.get("check_id", "unknown")
                    check_name = check.get("check_name", "Unknown check")
                    severity = self._map_checkov_severity(check.get("severity", "MEDIUM"))
                    
                    # Extract location information
                    file_path = check.get("file_path", "")
                    file_line_range = check.get("file_line_range", [0, 0])
                    line_number = file_line_range[0] if file_line_range else 0
                    
                    # Extract resource information
                    resource = check.get("resource", "unknown")
                    resource_type = check.get("resource_type", "unknown")
                    
                    # Extract description
                    description = check.get("check_result", {}).get("evaluated_keys", [])
                    if description:
                        description = f"Failed check: {check_name}\nResource: {resource}\nEvaluated keys: {', '.join(description)}"
                    else:
                        description = f"Failed check: {check_name}\nResource: {resource}"
                    
                    # Extract guidance
                    guidance = check.get("guideline", "")
                    if guidance:
                        description += f"\n\nGuidance: {guidance}"
                    
                    # Create metadata
                    metadata = {
                        "check_id": check_id,
                        "check_name": check_name,
                        "resource": resource,
                        "resource_type": resource_type,
                        "file_line_range": file_line_range,
                        "evaluated_keys": check.get("check_result", {}).get("evaluated_keys", []),
                        "guideline": guidance,
                        "check_class": check.get("check_class", ""),
                        "check_category": check.get("check_category", ""),
                    }
                    
                    # Create tags
                    tags = [
                        f"check:{check_id}",
                        f"resource:{resource_type}",
                        f"severity:{check.get('severity', 'MEDIUM').lower()}",
                        "checkov",
                    ]
                    
                    if check.get("check_category"):
                        tags.append(f"category:{check['check_category']}")
                    
                    # Create finding
                    finding = self.create_finding(
                        title=f"Checkov: {check_name}",
                        description=description,
                        severity=severity,
                        file_path=file_path,
                        line_number=line_number,
                        confidence=0.8,  # Checkov has good confidence
                        tags=tags,
                        metadata=metadata,
                    )
                    
                    findings.append(finding)
                    
                except Exception as e:
                    # Skip malformed results
                    print(f"Error parsing Checkov result: {e}")
                    continue
        
        return findings
    
    def _map_checkov_severity(self, checkov_severity: str) -> Severity:
        """
        Map Checkov severity to our Severity enum.
        
        Args:
            checkov_severity: Checkov severity string
            
        Returns:
            Mapped Severity
        """
        severity_mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        
        return severity_mapping.get(checkov_severity.upper(), Severity.MEDIUM)
    
    def get_help_text(self) -> str:
        """Get help text for Checkov detector."""
        return """
Checkov IaC Security Detector

This detector uses Checkov for Infrastructure as Code security analysis.
It can detect security issues in various IaC frameworks including:
- Terraform
- Kubernetes
- Docker
- CloudFormation
- ARM templates
- Serverless framework
- CDK

Configuration options:
- custom_config: Path to custom Checkov configuration file
- frameworks: List of specific frameworks to scan
- timeout: Scan timeout in seconds (default: 300)

Installation:
pip install checkov

Usage examples:
checkov -d /path/to/terraform/code
checkov -d /path/to/k8s/manifests --framework kubernetes
checkov -d /path/to/iac --framework terraform,kubernetes,docker
"""
