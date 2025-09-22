"""
Email notification provider for repo-scan.
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

from .base import BaseNotifier
from ..core.models import ScanResult


class EmailNotifier(BaseNotifier):
    """
    Email notification provider using SMTP.
    """
    
    def __init__(self) -> None:
        """Initialize the email notifier."""
        super().__init__("email")
    
    def is_configured(self) -> bool:
        """Check if email is properly configured."""
        required_fields = ["smtp_server", "smtp_port", "username", "password", "from_email", "to_emails"]
        return all(self.config.get(field) for field in required_fields)
    
    def send_notification(self, scan_result: ScanResult, message: str = "") -> bool:
        """
        Send notification via email.
        
        Args:
            scan_result: Scan result to notify about
            message: Custom message to include
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.is_configured():
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"Security Alert: {scan_result.repository.path} - {scan_result.risk_level}"
            msg['From'] = self.config["from_email"]
            msg['To'] = ", ".join(self.config["to_emails"])
            
            # Create HTML content
            html_content = self._create_html_email(scan_result, message)
            text_content = self._create_text_email(scan_result, message)
            
            # Attach parts
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            with smtplib.SMTP(self.config["smtp_server"], self.config["smtp_port"]) as server:
                if self.config.get("use_tls", True):
                    server.starttls()
                
                server.login(self.config["username"], self.config["password"])
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Failed to send email notification: {e}")
            return False
    
    def _create_html_email(self, scan_result: ScanResult, message: str) -> str:
        """Create HTML email content."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 800px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 8px 8px 0 0; margin: -20px -20px 20px -20px; }}
                .risk-critical {{ color: #e74c3c; }}
                .risk-high {{ color: #f39c12; }}
                .risk-medium {{ color: #f1c40f; }}
                .risk-low {{ color: #27ae60; }}
                .finding {{ background-color: #f8f9fa; border-left: 4px solid #007bff; padding: 15px; margin: 10px 0; border-radius: 4px; }}
                .finding-critical {{ border-left-color: #e74c3c; }}
                .finding-high {{ border-left-color: #f39c12; }}
                .finding-medium {{ border-left-color: #f1c40f; }}
                .finding-low {{ border-left-color: #27ae60; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat {{ text-align: center; padding: 15px; background-color: #ecf0f1; border-radius: 8px; }}
                .stat-value {{ font-size: 24px; font-weight: bold; }}
                .stat-label {{ font-size: 14px; color: #7f8c8d; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Security Scan Alert</h1>
                    <p>Repository: {scan_result.repository.path}</p>
                </div>
                
                <div class="stats">
                    <div class="stat">
                        <div class="stat-value risk-{scan_result.risk_level.lower()}">{scan_result.risk_score:.1f}/100</div>
                        <div class="stat-label">Risk Score</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{len(scan_result.findings)}</div>
                        <div class="stat-label">Total Findings</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{scan_result.scan_duration:.1f}s</div>
                        <div class="stat-label">Scan Duration</div>
                    </div>
                </div>
                
                <h2>Risk Level: <span class="risk-{scan_result.risk_level.lower()}">{scan_result.risk_level}</span></h2>
                
                {f'<p><strong>Message:</strong> {message}</p>' if message else ''}
                
                <h3>Findings Summary</h3>
        """
        
        # Add findings by severity
        severity_counts = {}
        for finding in scan_result.findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        html += "<ul>"
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "✅"}[severity]
                html += f"<li>{emoji} {severity}: {count} findings</li>"
        html += "</ul>"
        
        # Add top findings
        if scan_result.findings:
            html += "<h3>Top Findings</h3>"
            top_findings = sorted(scan_result.findings, key=lambda f: f.risk_score, reverse=True)[:5]
            
            for finding in top_findings:
                severity_class = f"finding-{finding.severity.value.lower()}"
                html += f"""
                <div class="finding {severity_class}">
                    <h4>{finding.title}</h4>
                    <p><strong>Scanner:</strong> {finding.scanner}</p>
                    <p><strong>Severity:</strong> {finding.severity.value}</p>
                    <p><strong>Risk Score:</strong> {finding.risk_score:.1f}</p>
                    <p><strong>File:</strong> {finding.file_path or 'N/A'}</p>
                    {f'<p><strong>Line:</strong> {finding.line_number}</p>' if finding.line_number else ''}
                    <p><strong>Description:</strong> {finding.description}</p>
                </div>
                """
        
        html += """
                <hr>
                <p><small>Generated by Repo-Scan Security Scanner</small></p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_text_email(self, scan_result: ScanResult, message: str) -> str:
        """Create plain text email content."""
        text = f"""
SECURITY SCAN ALERT
==================

Repository: {scan_result.repository.path}
Risk Level: {scan_result.risk_level} ({scan_result.risk_score:.1f}/100)
Total Findings: {len(scan_result.findings)}
Scan Duration: {scan_result.scan_duration:.1f}s
Status: {'Success' if scan_result.success else 'Failed'}

{message if message else ''}

FINDINGS SUMMARY
================
"""
        
        # Add findings by severity
        severity_counts = {}
        for finding in scan_result.findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                text += f"{severity}: {count} findings\n"
        
        # Add top findings
        if scan_result.findings:
            text += "\nTOP FINDINGS\n============\n"
            top_findings = sorted(scan_result.findings, key=lambda f: f.risk_score, reverse=True)[:5]
            
            for i, finding in enumerate(top_findings, 1):
                text += f"""
{i}. {finding.title}
   Scanner: {finding.scanner}
   Severity: {finding.severity.value}
   Risk Score: {finding.risk_score:.1f}
   File: {finding.file_path or 'N/A'}
   {f'Line: {finding.line_number}' if finding.line_number else ''}
   Description: {finding.description}
"""
        
        text += "\n---\nGenerated by Repo-Scan Security Scanner"
        
        return text
    
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
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"Daily Security Scan Summary - {len(scan_results)} repositories scanned"
            msg['From'] = self.config["from_email"]
            msg['To'] = ", ".join(self.config["to_emails"])
            
            # Create content
            html_content = self._create_daily_summary_html(scan_results)
            text_content = self._create_daily_summary_text(scan_results)
            
            # Attach parts
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            with smtplib.SMTP(self.config["smtp_server"], self.config["smtp_port"]) as server:
                if self.config.get("use_tls", True):
                    server.starttls()
                
                server.login(self.config["username"], self.config["password"])
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Failed to send daily summary email: {e}")
            return False
    
    def _create_daily_summary_html(self, scan_results: list) -> str:
        """Create HTML daily summary content."""
        total_scans = len(scan_results)
        total_findings = sum(len(result.findings) for result in scan_results)
        high_risk_scans = len([r for r in scan_results if r.risk_score >= 75])
        
        # Count findings by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for result in scan_results:
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 800px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 8px 8px 0 0; margin: -20px -20px 20px -20px; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat {{ text-align: center; padding: 15px; background-color: #ecf0f1; border-radius: 8px; }}
                .stat-value {{ font-size: 24px; font-weight: bold; }}
                .stat-label {{ font-size: 14px; color: #7f8c8d; }}
                .repo-list {{ margin: 20px 0; }}
                .repo-item {{ padding: 10px; border-bottom: 1px solid #ecf0f1; }}
                .repo-name {{ font-weight: bold; }}
                .repo-risk {{ float: right; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📊 Daily Security Scan Summary</h1>
                    <p>Summary for {total_scans} repositories scanned</p>
                </div>
                
                <div class="stats">
                    <div class="stat">
                        <div class="stat-value">{total_scans}</div>
                        <div class="stat-label">Total Scans</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{total_findings}</div>
                        <div class="stat-label">Total Findings</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{high_risk_scans}</div>
                        <div class="stat-label">High Risk Scans</div>
                    </div>
                </div>
                
                <h3>Findings by Severity</h3>
                <ul>
        """
        
        for severity, count in severity_counts.items():
            if count > 0:
                emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "✅"}[severity]
                html += f"<li>{emoji} {severity}: {count} findings</li>"
        
        html += "</ul>"
        
        # Top risky repositories
        top_risky = sorted(scan_results, key=lambda r: r.risk_score, reverse=True)[:10]
        if top_risky:
            html += "<h3>Top Risky Repositories</h3><div class='repo-list'>"
            for result in top_risky:
                html += f"""
                <div class="repo-item">
                    <span class="repo-name">{result.repository.path}</span>
                    <span class="repo-risk">{result.risk_score:.1f}/100</span>
                </div>
                """
            html += "</div>"
        
        html += """
                <hr>
                <p><small>Generated by Repo-Scan Security Scanner</small></p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_daily_summary_text(self, scan_results: list) -> str:
        """Create plain text daily summary content."""
        total_scans = len(scan_results)
        total_findings = sum(len(result.findings) for result in scan_results)
        high_risk_scans = len([r for r in scan_results if r.risk_score >= 75])
        
        # Count findings by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for result in scan_results:
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1
        
        text = f"""
DAILY SECURITY SCAN SUMMARY
===========================

Total Scans: {total_scans}
Total Findings: {total_findings}
High Risk Scans: {high_risk_scans}

FINDINGS BY SEVERITY
====================
"""
        
        for severity, count in severity_counts.items():
            if count > 0:
                text += f"{severity}: {count} findings\n"
        
        # Top risky repositories
        top_risky = sorted(scan_results, key=lambda r: r.risk_score, reverse=True)[:10]
        if top_risky:
            text += "\nTOP RISKY REPOSITORIES\n======================\n"
            for result in top_risky:
                text += f"{result.repository.path}: {result.risk_score:.1f}/100\n"
        
        text += "\n---\nGenerated by Repo-Scan Security Scanner"
        
        return text
