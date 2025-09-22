"""
Semgrep SAST detector implementation.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseDetector
from ..core.models import Finding, FindingType, ScanConfig, Severity
from ..utils import retry_on_exception


class SemgrepDetector(BaseDetector):
    """
    Semgrep SAST detector for static code analysis.
    """
    
    def __init__(self) -> None:
        """Initialize the Semgrep detector."""
        super().__init__(
            name="semgrep",
            scanner_type=FindingType.SAST,
            description="Static Application Security Testing with Semgrep"
        )
    
    def is_available(self) -> bool:
        """Check if Semgrep is available."""
        try:
            result = self.run_command(["semgrep", "--version"], capture_output=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_version(self) -> Optional[str]:
        """Get Semgrep version."""
        try:
            result = self.run_command(["semgrep", "--version"], capture_output=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def get_required_dependencies(self) -> List[str]:
        """Get required dependencies."""
        return ["semgrep"]
    
    def get_supported_file_extensions(self) -> List[str]:
        """Get supported file extensions."""
        return [
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".php",
            ".rb", ".cs", ".cpp", ".c", ".h", ".hpp", ".kt", ".scala", ".swift",
            ".yaml", ".yml", ".json", ".dockerfile", ".tf", ".hcl"
        ]
    
    @retry_on_exception(max_retries=2, delay=1.0)
    def scan(self, scan_config: ScanConfig) -> List[Finding]:
        """
        Scan repository with Semgrep.
        
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
            
            # Build Semgrep command
            command = [
                "semgrep",
                "--config=auto",  # Use Semgrep's built-in rules
                "--json",
                f"--output={output_file}",
                "--no-git-ignore",  # Don't respect .gitignore
                "--max-target-bytes=1000000",  # 1MB limit per file
                "--timeout=30",  # 30 second timeout per file
                "--max-memory=5000",  # 5GB memory limit
                "--severity=INFO",  # Include all severities
                str(scan_config.repository.path)
            ]
            
            # Add custom rules if specified
            if self._config.get("custom_rules"):
                command.extend(["--config", self._config["custom_rules"]])
            
            # Add exclude patterns
            for pattern in scan_config.exclude_patterns:
                command.extend(["--exclude", pattern])
            
            # Run Semgrep
            result = self.run_command(
                command,
                cwd=scan_config.repository.path,
                timeout=self._config.get("timeout", 300)
            )
            
            # Parse results
            if Path(output_file).exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    semgrep_results = json.load(f)
                
                findings = self._parse_semgrep_results(semgrep_results, scan_config)
            
            # Cleanup
            Path(output_file).unlink(missing_ok=True)
            
        except Exception as e:
            # If Semgrep fails, return empty results rather than crashing
            print(f"Semgrep scan failed: {e}")
        
        return findings
    
    def _parse_semgrep_results(
        self, results: Dict[str, Any], scan_config: ScanConfig
    ) -> List[Finding]:
        """
        Parse Semgrep JSON results into Finding objects.
        
        Args:
            results: Semgrep JSON results
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
                rule_id = result.get("check_id", "unknown")
                message = result.get("message", "No description available")
                severity = self._map_semgrep_severity(result.get("extra", {}).get("severity", "INFO"))
                
                # Extract location information
                path = result.get("path", "")
                start_line = result.get("start", {}).get("line", 0)
                end_line = result.get("end", {}).get("line", 0)
                start_col = result.get("start", {}).get("col", 0)
                end_col = result.get("end", {}).get("col", 0)
                
                # Extract code snippet
                code_snippet = None
                if "extra" in result and "lines" in result["extra"]:
                    code_snippet = result["extra"]["lines"]
                
                # Extract metadata
                metadata = {
                    "rule_id": rule_id,
                    "rule_url": result.get("extra", {}).get("metadata", {}).get("source", ""),
                    "confidence": result.get("extra", {}).get("metadata", {}).get("confidence", "MEDIUM"),
                    "cwe": result.get("extra", {}).get("metadata", {}).get("cwe", []),
                    "owasp": result.get("extra", {}).get("metadata", {}).get("owasp", []),
                    "semgrep_severity": result.get("extra", {}).get("severity", "INFO"),
                }
                
                # Extract CWE and OWASP information
                cwe_id = None
                if metadata["cwe"]:
                    cwe_id = metadata["cwe"][0] if isinstance(metadata["cwe"], list) else str(metadata["cwe"])
                
                # Create tags
                tags = []
                if metadata["owasp"]:
                    tags.extend([f"owasp:{owasp}" for owasp in metadata["owasp"]])
                if cwe_id:
                    tags.append(f"cwe:{cwe_id}")
                tags.append(f"rule:{rule_id}")
                
                # Create finding
                finding = self.create_finding(
                    title=f"Semgrep: {rule_id}",
                    description=message,
                    severity=severity,
                    file_path=path,
                    line_number=start_line,
                    column_number=start_col,
                    code_snippet=code_snippet,
                    cwe_id=cwe_id,
                    confidence=self._map_confidence(metadata["confidence"]),
                    tags=tags,
                    metadata=metadata,
                )
                
                findings.append(finding)
                
            except Exception as e:
                # Skip malformed results
                print(f"Error parsing Semgrep result: {e}")
                continue
        
        return findings
    
    def _map_semgrep_severity(self, semgrep_severity: str) -> Severity:
        """
        Map Semgrep severity to our Severity enum.
        
        Args:
            semgrep_severity: Semgrep severity string
            
        Returns:
            Mapped Severity
        """
        severity_mapping = {
            "ERROR": Severity.CRITICAL,
            "WARNING": Severity.HIGH,
            "INFO": Severity.MEDIUM,
        }
        
        return severity_mapping.get(semgrep_severity.upper(), Severity.MEDIUM)
    
    def _map_confidence(self, confidence: str) -> float:
        """
        Map Semgrep confidence to float value.
        
        Args:
            confidence: Semgrep confidence string
            
        Returns:
            Confidence as float (0-1)
        """
        confidence_mapping = {
            "HIGH": 0.9,
            "MEDIUM": 0.7,
            "LOW": 0.5,
        }
        
        return confidence_mapping.get(confidence.upper(), 0.7)
    
    def get_help_text(self) -> str:
        """Get help text for Semgrep detector."""
        return """
Semgrep SAST Detector

This detector uses Semgrep for static application security testing.
It can detect various security issues in multiple programming languages.

Configuration options:
- custom_rules: Path to custom Semgrep rules
- timeout: Scan timeout in seconds (default: 300)
- max_target_bytes: Maximum bytes per target file (default: 1000000)
- max_memory: Maximum memory usage in MB (default: 5000)

Installation:
pip install semgrep

Or using the official installer:
python -m pip install semgrep
"""
