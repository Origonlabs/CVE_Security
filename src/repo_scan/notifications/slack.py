"""
Slack notification provider for repo-scan.
"""

import json
from typing import Any, Dict, Optional

import requests

from .base import BaseNotifier
from ..core.models import ScanResult


class SlackNotifier(BaseNotifier):
    """
    Slack notification provider using webhooks.
    """
    
    def __init__(self) -> None:
        """Initialize the Slack notifier."""
        super().__init__("slack")
    
    def is_configured(self) -> bool:
        """Check if Slack is properly configured."""
        return bool(self.config.get("webhook_url"))
    
    def send_notification(self, scan_result: ScanResult, message: str = "") -> bool:
        """
        Send notification to Slack.
        
        Args:
            scan_result: Scan result to notify about
            message: Custom message to include
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.is_configured():
            return False
        
        try:
            webhook_url = self.config["webhook_url"]
            channel = self.config.get("channel", "#security")
            
            # Format the message
            summary = self.format_scan_summary(scan_result)
            
            # Create Slack message payload
            payload = {
                "channel": channel,
                "username": "Repo-Scan",
                "icon_emoji": ":shield:",
                "text": f"Security Scan Alert: {scan_result.repository.path}",
                "attachments": [
                    {
                        "color": self._get_color(scan_result.risk_level),
                        "title": "Scan Results",
                        "text": summary,
                        "fields": [
                            {
                                "title": "Repository",
                                "value": scan_result.repository.path,
                                "short": True
                            },
                            {
                                "title": "Risk Score",
                                "value": f"{scan_result.risk_score:.1f}/100",
                                "short": True
                            },
                            {
                                "title": "Risk Level",
                                "value": scan_result.risk_level,
                                "short": True
                            },
                            {
                                "title": "Total Findings",
                                "value": str(len(scan_result.findings)),
                                "short": True
                            }
                        ],
                        "footer": "Repo-Scan Security Scanner",
                        "ts": int(scan_result.started_at.timestamp())
                    }
                ]
            }
            
            # Add custom message if provided
            if message:
                payload["attachments"][0]["text"] += f"\n\n**Message:** {message}"
            
            # Add action buttons for high-risk scans
            if scan_result.risk_score >= 75:
                payload["attachments"][0]["actions"] = [
                    {
                        "type": "button",
                        "text": "View Report",
                        "url": self._get_report_url(scan_result),
                        "style": "danger"
                    }
                ]
            
            # Send the request
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=30
            )
            
            response.raise_for_status()
            return True
            
        except Exception as e:
            print(f"Failed to send Slack notification: {e}")
            return False
    
    def _get_color(self, risk_level: str) -> str:
        """Get color for Slack message based on risk level."""
        colors = {
            "CRITICAL": "danger",
            "HIGH": "warning", 
            "MEDIUM": "good",
            "LOW": "good"
        }
        return colors.get(risk_level, "good")
    
    def _get_report_url(self, scan_result: ScanResult) -> str:
        """Get URL to view the scan report."""
        # This would typically be a URL to your report storage or API
        return f"https://security-reports.company.com/scan/{scan_result.scan_id}"
    
    def send_daily_summary(self, scan_results: list) -> bool:
        """
        Send daily summary of all scans.
        
        Args:
            scan_results: List of scan results from the day
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.is_configured() or not scan_results:
            return False
        
        try:
            webhook_url = self.config["webhook_url"]
            channel = self.config.get("channel", "#security")
            
            # Calculate summary statistics
            total_scans = len(scan_results)
            total_findings = sum(len(result.findings) for result in scan_results)
            high_risk_scans = len([r for r in scan_results if r.risk_score >= 75])
            
            # Count findings by severity
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for result in scan_results:
                for finding in result.findings:
                    severity_counts[finding.severity.value] += 1
            
            # Create summary message
            summary = f"📊 Daily Security Scan Summary\n\n"
            summary += f"**Total Scans:** {total_scans}\n"
            summary += f"**Total Findings:** {total_findings}\n"
            summary += f"**High Risk Scans:** {high_risk_scans}\n\n"
            
            summary += "**Findings by Severity:**\n"
            for severity, count in severity_counts.items():
                if count > 0:
                    emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "✅"}[severity]
                    summary += f"- {emoji} {severity}: {count}\n"
            
            # Top repositories by risk
            top_risky = sorted(scan_results, key=lambda r: r.risk_score, reverse=True)[:5]
            if top_risky:
                summary += "\n**Top Risky Repositories:**\n"
                for result in top_risky:
                    summary += f"- {result.repository.path}: {result.risk_score:.1f}/100\n"
            
            # Create Slack message payload
            payload = {
                "channel": channel,
                "username": "Repo-Scan Daily",
                "icon_emoji": ":bar_chart:",
                "text": "Daily Security Scan Summary",
                "attachments": [
                    {
                        "color": "good" if high_risk_scans == 0 else "warning",
                        "title": "Daily Summary",
                        "text": summary,
                        "footer": "Repo-Scan Security Scanner",
                        "ts": int(scan_results[0].started_at.timestamp())
                    }
                ]
            }
            
            # Send the request
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=30
            )
            
            response.raise_for_status()
            return True
            
        except Exception as e:
            print(f"Failed to send Slack daily summary: {e}")
            return False
