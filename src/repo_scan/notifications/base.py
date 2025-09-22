"""
Base notification class for repo-scan.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..core.models import ScanResult


class BaseNotifier(ABC):
    """
    Abstract base class for notification providers.
    """
    
    def __init__(self, name: str) -> None:
        """Initialize the notifier."""
        self.name = name
        self.enabled = True
        self.config = {}
    
    @abstractmethod
    def send_notification(self, scan_result: ScanResult, message: str) -> bool:
        """
        Send a notification.
        
        Args:
            scan_result: Scan result to notify about
            message: Custom message to include
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        pass
    
    @abstractmethod
    def is_configured(self) -> bool:
        """
        Check if the notifier is properly configured.
        
        Returns:
            True if configured, False otherwise
        """
        pass
    
    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the notifier.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
    
    def format_scan_summary(self, scan_result: ScanResult) -> str:
        """
        Format a scan result into a summary message.
        
        Args:
            scan_result: Scan result to format
            
        Returns:
            Formatted summary message
        """
        summary = f"🔒 Security Scan Results\n\n"
        summary += f"**Repository:** {scan_result.repository.path}\n"
        summary += f"**Risk Level:** {scan_result.risk_level} ({scan_result.risk_score:.1f}/100)\n"
        summary += f"**Total Findings:** {len(scan_result.findings)}\n"
        summary += f"**Scan Duration:** {scan_result.scan_duration:.1f}s\n"
        summary += f"**Status:** {'✅ Success' if scan_result.success else '❌ Failed'}\n\n"
        
        if scan_result.findings:
            # Count by severity
            severity_counts = {}
            for finding in scan_result.findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            summary += "**Findings by Severity:**\n"
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "✅"}[severity]
                    summary += f"- {emoji} {severity}: {count}\n"
            
            # Top findings
            top_findings = sorted(scan_result.findings, key=lambda f: f.risk_score, reverse=True)[:3]
            if top_findings:
                summary += "\n**Top Findings:**\n"
                for finding in top_findings:
                    emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "✅"}[finding.severity.value]
                    summary += f"- {emoji} {finding.title} ({finding.scanner})\n"
        
        return summary
    
    def should_notify(self, scan_result: ScanResult) -> bool:
        """
        Determine if a notification should be sent based on scan results.
        
        Args:
            scan_result: Scan result to evaluate
            
        Returns:
            True if notification should be sent, False otherwise
        """
        if not self.enabled:
            return False
        
        # Check if there are critical or high severity findings
        critical_high_findings = [
            f for f in scan_result.findings 
            if f.severity.value in ["CRITICAL", "HIGH"]
        ]
        
        return len(critical_high_findings) > 0 or scan_result.risk_score >= 50
