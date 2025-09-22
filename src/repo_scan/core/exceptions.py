"""
Custom exceptions for repo-scan.
"""

from typing import Optional


class RepoScanError(Exception):
    """Base exception for repo-scan errors."""
    
    def __init__(self, message: str, details: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class ConfigError(RepoScanError):
    """Configuration-related errors."""
    pass


class ScannerError(RepoScanError):
    """Scanner execution errors."""
    
    def __init__(self, scanner_name: str, message: str, details: Optional[str] = None) -> None:
        super().__init__(f"Scanner '{scanner_name}' error: {message}", details)
        self.scanner_name = scanner_name


class RepositoryError(RepoScanError):
    """Repository-related errors."""
    
    def __init__(self, repo_path: str, message: str, details: Optional[str] = None) -> None:
        super().__init__(f"Repository '{repo_path}' error: {message}", details)
        self.repo_path = repo_path


class PluginError(RepoScanError):
    """Plugin-related errors."""
    
    def __init__(self, plugin_name: str, message: str, details: Optional[str] = None) -> None:
        super().__init__(f"Plugin '{plugin_name}' error: {message}", details)
        self.plugin_name = plugin_name


class ScoringError(RepoScanError):
    """Risk scoring errors."""
    pass


class ReportError(RepoScanError):
    """Report generation errors."""
    pass


class ValidationError(RepoScanError):
    """Data validation errors."""
    pass
