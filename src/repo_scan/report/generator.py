"""
Report generation system for repo-scan.
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, Template

from ..core.exceptions import ReportError
from ..core.models import ScanResult, Severity
from ..scoring import RiskScorer


class ReportGenerator:
    """
    Generator for various report formats (JSON, HTML, JUnit).
    """
    
    def __init__(self) -> None:
        """Initialize the report generator."""
        self.template_dir = Path(__file__).parent / "templates"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )
    
    def generate_json_report(self, scan_result: ScanResult, output_path: Path) -> None:
        """
        Generate JSON report.
        
        Args:
            scan_result: Scan result to report
            output_path: Output file path
        """
        try:
            # Convert scan result to dictionary
            report_data = self._scan_result_to_dict(scan_result)
            
            # Write JSON file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
                
        except Exception as e:
            raise ReportError(f"Failed to generate JSON report: {e}") from e
    
    def generate_html_report(self, scan_result: ScanResult, output_path: Path) -> None:
        """
        Generate HTML report.
        
        Args:
            scan_result: Scan result to report
            output_path: Output file path
        """
        try:
            # Prepare template data
            template_data = self._prepare_html_template_data(scan_result)
            
            # Load and render template
            template = self.jinja_env.get_template("report.html")
            html_content = template.render(**template_data)
            
            # Write HTML file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
        except Exception as e:
            raise ReportError(f"Failed to generate HTML report: {e}") from e
    
    def generate_junit_report(self, scan_result: ScanResult, output_path: Path) -> None:
        """
        Generate JUnit XML report.
        
        Args:
            scan_result: Scan result to report
            output_path: Output file path
        """
        try:
            # Create root element
            root = ET.Element("testsuites")
            root.set("name", "repo-scan")
            root.set("tests", str(len(scan_result.findings)))
            root.set("failures", str(len([f for f in scan_result.findings if f.severity in [Severity.HIGH, Severity.CRITICAL]])))
            root.set("errors", str(len([f for f in scan_result.findings if f.severity == Severity.CRITICAL])))
            root.set("time", str(scan_result.scan_duration))
            
            # Create testsuite element
            testsuite = ET.SubElement(root, "testsuite")
            testsuite.set("name", f"repo-scan-{scan_result.scan_id}")
            testsuite.set("tests", str(len(scan_result.findings)))
            testsuite.set("failures", str(len([f for f in scan_result.findings if f.severity in [Severity.HIGH, Severity.CRITICAL]])))
            testsuite.set("errors", str(len([f for f in scan_result.findings if f.severity == Severity.CRITICAL])))
            testsuite.set("time", str(scan_result.scan_duration))
            testsuite.set("timestamp", scan_result.started_at.isoformat())
            
            # Add properties
            properties = ET.SubElement(testsuite, "properties")
            
            prop = ET.SubElement(properties, "property")
            prop.set("name", "repository.path")
            prop.set("value", scan_result.repository.path)
            
            prop = ET.SubElement(properties, "property")
            prop.set("name", "risk.score")
            prop.set("value", str(scan_result.risk_score))
            
            prop = ET.SubElement(properties, "property")
            prop.set("name", "risk.level")
            prop.set("value", scan_result.risk_level)
            
            # Add test cases for each finding
            for finding in scan_result.findings:
                testcase = ET.SubElement(testsuite, "testcase")
                testcase.set("name", finding.title)
                testcase.set("classname", f"{finding.scanner}.{finding.finding_type.value}")
                testcase.set("time", "0")
                
                # Add failure or error based on severity
                if finding.severity == Severity.CRITICAL:
                    error = ET.SubElement(testcase, "error")
                    error.set("message", finding.title)
                    error.set("type", "CRITICAL")
                    error.text = f"File: {finding.file_path or 'N/A'}\nLine: {finding.line_number or 'N/A'}\n{finding.description}"
                elif finding.severity == Severity.HIGH:
                    failure = ET.SubElement(testcase, "failure")
                    failure.set("message", finding.title)
                    failure.set("type", "HIGH")
                    failure.text = f"File: {finding.file_path or 'N/A'}\nLine: {finding.line_number or 'N/A'}\n{finding.description}"
                elif finding.severity == Severity.MEDIUM:
                    failure = ET.SubElement(testcase, "failure")
                    failure.set("message", finding.title)
                    failure.set("type", "MEDIUM")
                    failure.text = f"File: {finding.file_path or 'N/A'}\nLine: {finding.line_number or 'N/A'}\n{finding.description}"
                
                # Add system-out with additional details
                system_out = ET.SubElement(testcase, "system-out")
                system_out.text = f"Scanner: {finding.scanner}\nRisk Score: {finding.risk_score}\nTags: {', '.join(finding.tags)}"
            
            # Write XML file
            tree = ET.ElementTree(root)
            ET.indent(tree, space="  ", level=0)
            tree.write(output_path, encoding='utf-8', xml_declaration=True)
            
        except Exception as e:
            raise ReportError(f"Failed to generate JUnit report: {e}") from e
    
    def generate_summary_report(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Generate summary report data.
        
        Args:
            scan_result: Scan result to summarize
            
        Returns:
            Summary data dictionary
        """
        try:
            # Count findings by severity
            severity_counts = {}
            for severity in Severity:
                severity_counts[severity.value] = len([
                    f for f in scan_result.findings if f.severity == severity
                ])
            
            # Count findings by type
            type_counts = {}
            for finding in scan_result.findings:
                finding_type = finding.finding_type.value
                type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
            
            # Count findings by scanner
            scanner_counts = {}
            for finding in scan_result.findings:
                scanner = finding.scanner
                scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
            
            # Top findings by risk score
            top_findings = sorted(
                scan_result.findings,
                key=lambda f: f.risk_score,
                reverse=True
            )[:10]
            
            return {
                "scan_id": scan_result.scan_id,
                "repository": {
                    "path": scan_result.repository.path,
                    "url": scan_result.repository.url,
                    "branch": scan_result.repository.branch,
                    "commit_hash": scan_result.repository.commit_hash,
                },
                "summary": {
                    "total_findings": len(scan_result.findings),
                    "risk_score": scan_result.risk_score,
                    "risk_level": scan_result.risk_level,
                    "scan_duration": scan_result.scan_duration,
                    "success": scan_result.success,
                },
                "severity_breakdown": severity_counts,
                "type_breakdown": type_counts,
                "scanner_breakdown": scanner_counts,
                "top_findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "risk_score": f.risk_score,
                        "scanner": f.scanner,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                    }
                    for f in top_findings
                ],
                "scan_metadata": {
                    "started_at": scan_result.started_at.isoformat(),
                    "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                    "error_message": scan_result.error_message,
                }
            }
            
        except Exception as e:
            raise ReportError(f"Failed to generate summary report: {e}") from e
    
    def _scan_result_to_dict(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Convert scan result to dictionary for JSON serialization."""
        return {
            "scan_id": scan_result.scan_id,
            "repository": {
                "path": scan_result.repository.path,
                "url": scan_result.repository.url,
                "branch": scan_result.repository.branch,
                "commit_hash": scan_result.repository.commit_hash,
                "tech_stack": {
                    "languages": scan_result.repository.tech_stack.languages,
                    "frameworks": scan_result.repository.tech_stack.frameworks,
                    "package_managers": scan_result.repository.tech_stack.package_managers,
                    "containers": scan_result.repository.tech_stack.containers,
                    "infrastructure": scan_result.repository.tech_stack.infrastructure,
                },
                "size_bytes": scan_result.repository.size_bytes,
                "file_count": scan_result.repository.file_count,
                "last_modified": scan_result.repository.last_modified.isoformat() if scan_result.repository.last_modified else None,
                "gpg_verified": scan_result.repository.gpg_verified,
            },
            "config": {
                "enabled_scanners": scan_result.config.enabled_scanners,
                "exclude_patterns": scan_result.config.exclude_patterns,
                "include_patterns": scan_result.config.include_patterns,
                "timeout": scan_result.config.timeout,
                "parallel_scans": scan_result.config.parallel_scans,
            },
            "findings": [
                {
                    "id": f.id,
                    "scanner": f.scanner,
                    "finding_type": f.finding_type.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "column_number": f.column_number,
                    "code_snippet": f.code_snippet,
                    "cwe_id": f.cwe_id,
                    "cve_id": f.cve_id,
                    "cvss_score": f.cvss_score,
                    "confidence": f.confidence,
                    "tags": f.tags,
                    "risk_score": f.risk_score,
                    "exposure_multiplier": f.exposure_multiplier,
                    "exploitability_multiplier": f.exploitability_multiplier,
                    "metadata": f.metadata,
                    "discovered_at": f.discovered_at.isoformat(),
                    "remediation": {
                        "description": f.remediation.description if f.remediation else None,
                        "confidence": f.remediation.confidence if f.remediation else None,
                        "automation_suggested": f.remediation.automation_suggested if f.remediation else None,
                        "steps": f.remediation.steps if f.remediation else None,
                        "references": f.remediation.references if f.remediation else None,
                        "estimated_effort": f.remediation.estimated_effort if f.remediation else None,
                    } if f.remediation else None,
                }
                for f in scan_result.findings
            ],
            "risk_score": scan_result.risk_score,
            "risk_level": scan_result.risk_level,
            "scan_duration": scan_result.scan_duration,
            "started_at": scan_result.started_at.isoformat(),
            "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
            "success": scan_result.success,
            "error_message": scan_result.error_message,
            "scanner_results": scan_result.scanner_results,
            "metadata": scan_result.metadata,
        }
    
    def _prepare_html_template_data(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Prepare data for HTML template."""
        # Generate summary
        summary = self.generate_summary_report(scan_result)
        
        # Prepare findings data
        findings_data = []
        for finding in scan_result.findings:
            findings_data.append({
                "id": finding.id,
                "scanner": finding.scanner,
                "finding_type": finding.finding_type.value,
                "severity": finding.severity.value,
                "title": finding.title,
                "description": finding.description,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "column_number": finding.column_number,
                "code_snippet": finding.code_snippet,
                "cwe_id": finding.cwe_id,
                "cve_id": finding.cve_id,
                "cvss_score": finding.cvss_score,
                "confidence": finding.confidence,
                "tags": finding.tags,
                "risk_score": finding.risk_score,
                "metadata": finding.metadata,
                "discovered_at": finding.discovered_at,
                "remediation": finding.remediation,
            })
        
        return {
            "scan_result": scan_result,
            "summary": summary,
            "findings": findings_data,
            "generated_at": datetime.utcnow(),
            "repo_scan_version": "1.0.0",
        }
