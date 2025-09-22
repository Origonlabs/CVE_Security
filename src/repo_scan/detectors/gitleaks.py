"""
Gitleaks secret detection implementation.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseDetector
from ..core.models import Finding, FindingType, ScanConfig, Severity
from ..utils import retry_on_exception


class GitleaksDetector(BaseDetector):
    """
    Gitleaks detector for secret detection in Git repositories.
    """
    
    def __init__(self) -> None:
        """Initialize the Gitleaks detector."""
        super().__init__(
            name="gitleaks",
            scanner_type=FindingType.SECRET,
            description="Secret detection in Git repositories with Gitleaks"
        )
    
    def is_available(self) -> bool:
        """Check if Gitleaks is available."""
        try:
            result = self.run_command(["gitleaks", "version"], capture_output=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_version(self) -> Optional[str]:
        """Get Gitleaks version."""
        try:
            result = self.run_command(["gitleaks", "version"], capture_output=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def get_required_dependencies(self) -> List[str]:
        """Get required dependencies."""
        return ["gitleaks"]
    
    def get_supported_file_extensions(self) -> List[str]:
        """Get supported file extensions."""
        return [".git"]  # Gitleaks works on Git repositories
    
    @retry_on_exception(max_retries=2, delay=1.0)
    def scan(self, scan_config: ScanConfig) -> List[Finding]:
        """
        Scan repository with Gitleaks.
        
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
            
            # Build Gitleaks command
            command = [
                "gitleaks",
                "detect",
                "--source", str(scan_config.repository.path),
                "--report-format", "json",
                "--report-path", output_file,
                "--verbose",
                "--no-git",  # Don't use git commands, scan files directly
            ]
            
            # Add custom config if specified
            if self._config.get("custom_config"):
                command.extend(["--config", self._config["custom_config"]])
            
            # Add exclude patterns
            for pattern in scan_config.exclude_patterns:
                command.extend(["--exclude", pattern])
            
            # Run Gitleaks
            result = self.run_command(
                command,
                cwd=scan_config.repository.path,
                timeout=self._config.get("timeout", 300)
            )
            
            # Parse results
            if Path(output_file).exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    gitleaks_results = json.load(f)
                
                findings = self._parse_gitleaks_results(gitleaks_results, scan_config)
            
            # Cleanup
            Path(output_file).unlink(missing_ok=True)
            
        except Exception as e:
            # If Gitleaks fails, return empty results rather than crashing
            print(f"Gitleaks scan failed: {e}")
        
        return findings
    
    def _parse_gitleaks_results(
        self, results: List[Dict[str, Any]], scan_config: ScanConfig
    ) -> List[Finding]:
        """
        Parse Gitleaks JSON results into Finding objects.
        
        Args:
            results: Gitleaks JSON results
            scan_config: Scan configuration
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        for result in results:
            try:
                # Extract basic information
                rule_id = result.get("RuleID", "unknown")
                description = result.get("Description", "Secret detected")
                secret_type = result.get("Secret", "unknown")
                
                # Extract location information
                file_path = result.get("File", "")
                line_number = result.get("StartLine", 0)
                end_line = result.get("EndLine", 0)
                
                # Extract commit information
                commit_hash = result.get("Commit", "")
                author = result.get("Author", "")
                email = result.get("Email", "")
                date = result.get("Date", "")
                
                # Determine severity based on secret type
                severity = self._determine_secret_severity(secret_type, rule_id)
                
                # Create metadata
                metadata = {
                    "rule_id": rule_id,
                    "secret_type": secret_type,
                    "commit_hash": commit_hash,
                    "author": author,
                    "email": email,
                    "date": date,
                    "start_line": line_number,
                    "end_line": end_line,
                    "entropy": result.get("Entropy", 0.0),
                    "context": result.get("Context", ""),
                }
                
                # Create tags
                tags = [
                    f"secret:{secret_type}",
                    f"rule:{rule_id}",
                    "gitleaks",
                ]
                
                if commit_hash:
                    tags.append(f"commit:{commit_hash[:8]}")
                
                # Create finding
                finding = self.create_finding(
                    title=f"Secret detected: {secret_type}",
                    description=f"{description}\nSecret type: {secret_type}\nFile: {file_path}",
                    severity=severity,
                    file_path=file_path,
                    line_number=line_number,
                    confidence=0.9,  # Gitleaks has high confidence
                    tags=tags,
                    metadata=metadata,
                )
                
                findings.append(finding)
                
            except Exception as e:
                # Skip malformed results
                print(f"Error parsing Gitleaks result: {e}")
                continue
        
        return findings
    
    def _determine_secret_severity(self, secret_type: str, rule_id: str) -> Severity:
        """
        Determine severity based on secret type and rule.
        
        Args:
            secret_type: Type of secret detected
            rule_id: Gitleaks rule ID
            
        Returns:
            Severity level
        """
        # High severity secrets
        high_severity_secrets = [
            "private-key", "rsa-private-key", "ec-private-key", "dsa-private-key",
            "aws-access-key", "aws-secret-key", "github-token", "gitlab-token",
            "slack-token", "discord-token", "jwt-secret", "api-key"
        ]
        
        # Critical severity secrets
        critical_severity_secrets = [
            "master-key", "root-password", "admin-password", "database-password",
            "encryption-key", "signing-key", "certificate-private-key"
        ]
        
        secret_lower = secret_type.lower()
        rule_lower = rule_id.lower()
        
        # Check for critical severity
        for critical_secret in critical_severity_secrets:
            if critical_secret in secret_lower or critical_secret in rule_lower:
                return Severity.CRITICAL
        
        # Check for high severity
        for high_secret in high_severity_secrets:
            if high_secret in secret_lower or high_secret in rule_lower:
                return Severity.HIGH
        
        # Default to medium severity for other secrets
        return Severity.MEDIUM
    
    def get_help_text(self) -> str:
        """Get help text for Gitleaks detector."""
        return """
Gitleaks Secret Detector

This detector uses Gitleaks to find secrets and sensitive information in Git repositories.
It can detect various types of secrets including API keys, passwords, tokens, and private keys.

Configuration options:
- custom_config: Path to custom Gitleaks configuration file
- timeout: Scan timeout in seconds (default: 300)

Installation:
# Using Go
go install github.com/zricethezav/gitleaks/v8@latest

# Using Docker
docker pull zricethezav/gitleaks:latest

# Using package managers
# Ubuntu/Debian
sudo apt install gitleaks

# macOS
brew install gitleaks

# Windows
choco install gitleaks
"""
