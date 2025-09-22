"""
Base detector class for security scanners.
"""

import json
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.exceptions import ScannerError
from ..core.models import Finding, FindingType, ScanConfig, Severity
from ..utils import generate_finding_id


class BaseDetector(ABC):
    """
    Abstract base class for all security detectors.
    
    This class defines the interface that all security scanners must implement.
    """
    
    def __init__(self, name: str, scanner_type: FindingType, description: str) -> None:
        """Initialize the detector."""
        self.name = name
        self.scanner_type = scanner_type
        self.description = description
        self._config = {}
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the scanner is available on the system.
        
        Returns:
            True if the scanner is available, False otherwise
        """
        pass
    
    @abstractmethod
    def scan(self, scan_config: ScanConfig) -> List[Finding]:
        """
        Scan the repository for security issues.
        
        Args:
            scan_config: Configuration for the scan
            
        Returns:
            List of security findings
        """
        pass
    
    def validate_configuration(self) -> None:
        """
        Validate the detector's configuration.
        
        Raises:
            ScannerError: If configuration is invalid
        """
        if not self.is_available():
            raise ScannerError(
                self.name,
                f"Scanner {self.name} is not available on this system"
            )
    
    def set_config(self, config: Dict[str, Any]) -> None:
        """Set detector configuration."""
        self._config = config
    
    def get_config(self) -> Dict[str, Any]:
        """Get detector configuration."""
        return self._config.copy()
    
    def run_command(
        self,
        command: List[str],
        cwd: Optional[str] = None,
        timeout: int = 300,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess:
        """
        Run a command and return the result.
        
        Args:
            command: Command to run
            cwd: Working directory
            timeout: Command timeout in seconds
            capture_output: Whether to capture stdout/stderr
            
        Returns:
            CompletedProcess result
            
        Raises:
            ScannerError: If command fails
        """
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                timeout=timeout,
                capture_output=capture_output,
                text=True,
                check=False,
            )
            
            if result.returncode != 0:
                error_msg = result.stderr or f"Command failed with return code {result.returncode}"
                raise ScannerError(
                    self.name,
                    f"Command failed: {' '.join(command)}\n{error_msg}"
                )
            
            return result
            
        except subprocess.TimeoutExpired as e:
            raise ScannerError(
                self.name,
                f"Command timed out after {timeout} seconds: {' '.join(command)}"
            ) from e
        except FileNotFoundError as e:
            raise ScannerError(
                self.name,
                f"Command not found: {command[0]}"
            ) from e
    
    def create_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        column_number: Optional[int] = None,
        code_snippet: Optional[str] = None,
        cwe_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        confidence: float = 1.0,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """
        Create a standardized finding object.
        
        Args:
            title: Finding title
            description: Detailed description
            severity: Severity level
            file_path: Path to the file with the issue
            line_number: Line number of the issue
            column_number: Column number of the issue
            code_snippet: Code snippet showing the issue
            cwe_id: CWE identifier
            cve_id: CVE identifier
            cvss_score: CVSS score
            confidence: Confidence level (0-1)
            tags: List of tags
            metadata: Additional metadata
            
        Returns:
            Finding object
        """
        finding_id = generate_finding_id(self.name, title, file_path)
        
        return Finding(
            id=finding_id,
            scanner=self.name,
            finding_type=self.scanner_type,
            severity=severity,
            title=title,
            description=description,
            file_path=file_path,
            line_number=line_number,
            column_number=column_number,
            code_snippet=code_snippet,
            cwe_id=cwe_id,
            cve_id=cve_id,
            cvss_score=cvss_score,
            confidence=confidence,
            tags=tags or [],
            metadata=metadata or {},
        )
    
    def parse_json_output(self, json_str: str) -> List[Dict[str, Any]]:
        """
        Parse JSON output from scanner.
        
        Args:
            json_str: JSON string to parse
            
        Returns:
            List of parsed objects
            
        Raises:
            ScannerError: If JSON parsing fails
        """
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ScannerError(
                self.name,
                f"Failed to parse JSON output: {e}"
            ) from e
    
    def should_scan_file(self, file_path: str, scan_config: ScanConfig) -> bool:
        """
        Determine if a file should be scanned based on include/exclude patterns.
        
        Args:
            file_path: Path to the file
            scan_config: Scan configuration
            
        Returns:
            True if file should be scanned, False otherwise
        """
        from fnmatch import fnmatch
        
        # Check exclude patterns first
        for pattern in scan_config.exclude_patterns:
            if fnmatch(file_path, pattern):
                return False
        
        # If include patterns are specified, file must match at least one
        if scan_config.include_patterns:
            for pattern in scan_config.include_patterns:
                if fnmatch(file_path, pattern):
                    return True
            return False
        
        # If no include patterns, scan all files (except excluded ones)
        return True
    
    def get_supported_file_extensions(self) -> List[str]:
        """
        Get list of file extensions supported by this detector.
        
        Returns:
            List of file extensions (including dots)
        """
        return []
    
    def get_required_dependencies(self) -> List[str]:
        """
        Get list of required system dependencies.
        
        Returns:
            List of required command names
        """
        return []
    
    def get_optional_dependencies(self) -> List[str]:
        """
        Get list of optional system dependencies.
        
        Returns:
            List of optional command names
        """
        return []
    
    def get_version(self) -> Optional[str]:
        """
        Get the version of the scanner tool.
        
        Returns:
            Version string or None if not available
        """
        return None
    
    def get_help_text(self) -> str:
        """
        Get help text for this detector.
        
        Returns:
            Help text string
        """
        return f"{self.name}: {self.description}"
