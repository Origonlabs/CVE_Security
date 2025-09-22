"""
Bandit Python SAST detector implementation.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseDetector
from ..core.models import Finding, FindingType, ScanConfig, Severity
from ..utils import retry_on_exception


class BanditDetector(BaseDetector):
    """
    Bandit detector for Python static security analysis.
    """
    
    def __init__(self) -> None:
        """Initialize the Bandit detector."""
        super().__init__(
            name="bandit",
            scanner_type=FindingType.SAST,
            description="Python static security analysis with Bandit"
        )
    
    def is_available(self) -> bool:
        """Check if Bandit is available."""
        try:
            result = self.run_command(["bandit", "--version"], capture_output=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_version(self) -> Optional[str]:
        """Get Bandit version."""
        try:
            result = self.run_command(["bandit", "--version"], capture_output=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def get_required_dependencies(self) -> List[str]:
        """Get required dependencies."""
        return ["bandit"]
    
    def get_supported_file_extensions(self) -> List[str]:
        """Get supported file extensions."""
        return [".py"]
    
    @retry_on_exception(max_retries=2, delay=1.0)
    def scan(self, scan_config: ScanConfig) -> List[Finding]:
        """
        Scan repository with Bandit.
        
        Args:
            scan_config: Scan configuration
            
        Returns:
            List of security findings
        """
        findings = []
        
        # Only scan if Python files are present
        if not self._has_python_files(scan_config.repository.path):
            return findings
        
        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name
            
            # Build Bandit command
            command = [
                "bandit",
                "-r",  # Recursive scan
                "-f", "json",  # JSON output format
                "-o", output_file,  # Output file
                "-ll",  # Low confidence, low severity (include all)
                str(scan_config.repository.path)
            ]
            
            # Add custom config if specified
            if self._config.get("custom_config"):
                command.extend(["-c", self._config["custom_config"]])
            
            # Add exclude patterns
            for pattern in scan_config.exclude_patterns:
                command.extend(["-x", pattern])
            
            # Add include patterns
            for pattern in scan_config.include_patterns:
                command.extend(["-i", pattern])
            
            # Run Bandit
            result = self.run_command(
                command,
                cwd=scan_config.repository.path,
                timeout=self._config.get("timeout", 300)
            )
            
            # Parse results
            if Path(output_file).exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    bandit_results = json.load(f)
                
                findings = self._parse_bandit_results(bandit_results, scan_config)
            
            # Cleanup
            Path(output_file).unlink(missing_ok=True)
            
        except Exception as e:
            # If Bandit fails, return empty results rather than crashing
            print(f"Bandit scan failed: {e}")
        
        return findings
    
    def _has_python_files(self, repo_path: str) -> bool:
        """
        Check if repository contains Python files.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            True if Python files are found, False otherwise
        """
        try:
            path = Path(repo_path)
            return any(path.rglob("*.py"))
        except Exception:
            return False
    
    def _parse_bandit_results(
        self, results: Dict[str, Any], scan_config: ScanConfig
    ) -> List[Finding]:
        """
        Parse Bandit JSON results into Finding objects.
        
        Args:
            results: Bandit JSON results
            scan_config: Scan configuration
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        if "results" not in results:
            return findings
        
        for result in results["results"]:
            try:
                # Extract basic information
                test_id = result.get("test_id", "unknown")
                test_name = result.get("test_name", "Unknown test")
                issue_severity = result.get("issue_severity", "MEDIUM")
                issue_confidence = result.get("issue_confidence", "MEDIUM")
                
                # Extract location information
                file_path = result.get("filename", "")
                line_number = result.get("line_number", 0)
                col_offset = result.get("col_offset", 0)
                
                # Extract code snippet
                code_snippet = None
                if "code" in result:
                    code_snippet = result["code"]
                
                # Extract description
                description = result.get("issue_text", "No description available")
                if "more_info" in result:
                    description += f"\n\nMore info: {result['more_info']}"
                
                # Map severity and confidence
                severity = self._map_bandit_severity(issue_severity)
                confidence = self._map_bandit_confidence(issue_confidence)
                
                # Create metadata
                metadata = {
                    "test_id": test_id,
                    "test_name": test_name,
                    "issue_severity": issue_severity,
                    "issue_confidence": issue_confidence,
                    "col_offset": col_offset,
                    "more_info": result.get("more_info", ""),
                }
                
                # Create tags
                tags = [
                    f"test:{test_id}",
                    f"severity:{issue_severity.lower()}",
                    f"confidence:{issue_confidence.lower()}",
                    "bandit",
                ]
                
                # Create finding
                finding = self.create_finding(
                    title=f"Bandit: {test_name}",
                    description=description,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_number,
                    column_number=col_offset,
                    code_snippet=code_snippet,
                    confidence=confidence,
                    tags=tags,
                    metadata=metadata,
                )
                
                findings.append(finding)
                
            except Exception as e:
                # Skip malformed results
                print(f"Error parsing Bandit result: {e}")
                continue
        
        return findings
    
    def _map_bandit_severity(self, bandit_severity: str) -> Severity:
        """
        Map Bandit severity to our Severity enum.
        
        Args:
            bandit_severity: Bandit severity string
            
        Returns:
            Mapped Severity
        """
        severity_mapping = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        
        return severity_mapping.get(bandit_severity.upper(), Severity.MEDIUM)
    
    def _map_bandit_confidence(self, bandit_confidence: str) -> float:
        """
        Map Bandit confidence to float value.
        
        Args:
            bandit_confidence: Bandit confidence string
            
        Returns:
            Confidence as float (0-1)
        """
        confidence_mapping = {
            "HIGH": 0.9,
            "MEDIUM": 0.7,
            "LOW": 0.5,
        }
        
        return confidence_mapping.get(bandit_confidence.upper(), 0.7)
    
    def get_help_text(self) -> str:
        """Get help text for Bandit detector."""
        return """
Bandit Python SAST Detector

This detector uses Bandit for Python static security analysis.
It can detect various security issues in Python code including:
- Hardcoded passwords and secrets
- SQL injection vulnerabilities
- Use of insecure random number generators
- SSL/TLS issues
- And many more Python-specific security issues

Configuration options:
- custom_config: Path to custom Bandit configuration file
- timeout: Scan timeout in seconds (default: 300)

Installation:
pip install bandit

Usage examples:
bandit -r /path/to/python/code
bandit -r -f json -o results.json /path/to/python/code
bandit -r -c bandit.yaml /path/to/python/code
"""
