"""
Trivy SCA and container security detector implementation.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseDetector
from ..core.models import Finding, FindingType, ScanConfig, Severity
from ..utils import retry_on_exception


class TrivyDetector(BaseDetector):
    """
    Trivy detector for Software Composition Analysis and container security.
    """
    
    def __init__(self) -> None:
        """Initialize the Trivy detector."""
        super().__init__(
            name="trivy",
            scanner_type=FindingType.SCA,
            description="Software Composition Analysis and container security with Trivy"
        )
    
    def is_available(self) -> bool:
        """Check if Trivy is available."""
        try:
            result = self.run_command(["trivy", "--version"], capture_output=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_version(self) -> Optional[str]:
        """Get Trivy version."""
        try:
            result = self.run_command(["trivy", "--version"], capture_output=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def get_required_dependencies(self) -> List[str]:
        """Get required dependencies."""
        return ["trivy"]
    
    def get_supported_file_extensions(self) -> List[str]:
        """Get supported file extensions."""
        return [
            ".json", ".lock", ".toml", ".yaml", ".yml",  # Package files
            "Dockerfile", "Containerfile",  # Container files
            ".tar", ".gz", ".bz2", ".xz",  # Archive files
        ]
    
    @retry_on_exception(max_retries=2, delay=1.0)
    def scan(self, scan_config: ScanConfig) -> List[Finding]:
        """
        Scan repository with Trivy.
        
        Args:
            scan_config: Scan configuration
            
        Returns:
            List of security findings
        """
        findings = []
        
        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name
            
            # Build Trivy command
            command = [
                "trivy",
                "fs",
                "--format", "json",
                "--output", output_file,
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                "--no-progress",
                "--quiet",
                str(scan_config.repository.path)
            ]
            
            # Add custom config if specified
            if self._config.get("custom_config"):
                command.extend(["--config", self._config["custom_config"]])
            
            # Add skip files
            for pattern in scan_config.exclude_patterns:
                command.extend(["--skip-files", pattern])
            
            # Run Trivy
            result = self.run_command(
                command,
                cwd=scan_config.repository.path,
                timeout=self._config.get("timeout", 300)
            )
            
            # Parse results
            if Path(output_file).exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    trivy_results = json.load(f)
                
                findings = self._parse_trivy_results(trivy_results, scan_config)
            
            # Cleanup
            Path(output_file).unlink(missing_ok=True)
            
        except Exception as e:
            # If Trivy fails, return empty results rather than crashing
            print(f"Trivy scan failed: {e}")
        
        return findings
    
    def _parse_trivy_results(
        self, results: Dict[str, Any], scan_config: ScanConfig
    ) -> List[Finding]:
        """
        Parse Trivy JSON results into Finding objects.
        
        Args:
            results: Trivy JSON results
            scan_config: Scan configuration
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        if "Results" not in results:
            return findings
        
        for result in results["Results"]:
            target = result.get("Target", "")
            vulnerabilities = result.get("Vulnerabilities", [])
            
            for vuln in vulnerabilities:
                try:
                    # Extract vulnerability information
                    vuln_id = vuln.get("VulnerabilityID", "unknown")
                    pkg_name = vuln.get("PkgName", "unknown")
                    pkg_version = vuln.get("InstalledVersion", "unknown")
                    severity = self._map_trivy_severity(vuln.get("Severity", "UNKNOWN"))
                    
                    # Extract description
                    description = vuln.get("Description", "No description available")
                    if vuln.get("Title"):
                        description = f"{vuln['Title']}\n\n{description}"
                    
                    # Extract CVSS score
                    cvss_score = None
                    if "CVSS" in vuln:
                        cvss_data = vuln["CVSS"]
                        if isinstance(cvss_data, dict):
                            cvss_score = cvss_data.get("v3", {}).get("Score") or cvss_data.get("v2", {}).get("Score")
                        elif isinstance(cvss_data, (int, float)):
                            cvss_score = float(cvss_data)
                    
                    # Extract CWE information
                    cwe_id = None
                    if "CweIDs" in vuln and vuln["CweIDs"]:
                        cwe_id = vuln["CweIDs"][0]
                    
                    # Extract references
                    references = []
                    if "References" in vuln:
                        references = vuln["References"]
                    
                    # Create metadata
                    metadata = {
                        "vulnerability_id": vuln_id,
                        "package_name": pkg_name,
                        "package_version": pkg_version,
                        "target": target,
                        "cvss": vuln.get("CVSS", {}),
                        "cwe_ids": vuln.get("CweIDs", []),
                        "references": references,
                        "published_date": vuln.get("PublishedDate", ""),
                        "last_modified_date": vuln.get("LastModifiedDate", ""),
                        "primary_url": vuln.get("PrimaryURL", ""),
                    }
                    
                    # Create tags
                    tags = [
                        f"vuln:{vuln_id}",
                        f"package:{pkg_name}",
                        f"version:{pkg_version}",
                        "trivy",
                    ]
                    
                    if cwe_id:
                        tags.append(f"cwe:{cwe_id}")
                    
                    # Create finding
                    finding = self.create_finding(
                        title=f"Vulnerability: {vuln_id} in {pkg_name}",
                        description=description,
                        severity=severity,
                        file_path=target,
                        cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                        cvss_score=cvss_score,
                        cwe_id=cwe_id,
                        confidence=0.9,  # Trivy has high confidence
                        tags=tags,
                        metadata=metadata,
                    )
                    
                    findings.append(finding)
                    
                except Exception as e:
                    # Skip malformed results
                    print(f"Error parsing Trivy vulnerability: {e}")
                    continue
        
        return findings
    
    def _map_trivy_severity(self, trivy_severity: str) -> Severity:
        """
        Map Trivy severity to our Severity enum.
        
        Args:
            trivy_severity: Trivy severity string
            
        Returns:
            Mapped Severity
        """
        severity_mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        
        return severity_mapping.get(trivy_severity.upper(), Severity.MEDIUM)
    
    def get_help_text(self) -> str:
        """Get help text for Trivy detector."""
        return """
Trivy SCA and Container Security Detector

This detector uses Trivy for Software Composition Analysis and container security scanning.
It can detect vulnerabilities in dependencies, container images, and filesystem scans.

Configuration options:
- custom_config: Path to custom Trivy configuration file
- timeout: Scan timeout in seconds (default: 300)

Installation:
# Using package managers
# Ubuntu/Debian
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# macOS
brew install trivy

# Windows
choco install trivy

# Using Go
go install github.com/aquasecurity/trivy/cmd/trivy@latest

# Using Docker
docker pull aquasec/trivy:latest
"""
