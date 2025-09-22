"""
Advanced risk scoring system for security findings.
"""

import re
from typing import Any, Dict, List, Optional

from .core.config import Config
from .core.exceptions import ScoringError
from .core.models import Finding, FindingType, Severity


class RiskScorer:
    """
    Advanced risk scoring system that calculates risk scores for individual findings
    and overall repository risk based on multiple factors.
    """
    
    def __init__(self, config: Config) -> None:
        """Initialize the risk scorer."""
        self.config = config
        self.risk_config = config.risk_scoring
        
        # Severity weights
        self.severity_weights = self.risk_config.get("severity_weights", {
            "LOW": 10,
            "MEDIUM": 40,
            "HIGH": 75,
            "CRITICAL": 100
        })
        
        # Multipliers for various factors
        self.multipliers = self.risk_config.get("multipliers", {
            "history_exposure": 1.25,
            "private_key": 2.0,
            "api_token": 1.8,
            "published_exploit": 1.5,
            "production_branch": 1.3,
            "world_writable": 1.2,
            "high_confidence": 1.1,
            "low_confidence": 0.8,
        })
        
        # Maximum number of findings to consider for repository score
        self.max_findings_for_score = self.risk_config.get("max_findings_for_score", 20)
    
    def calculate_finding_risk_score(self, finding: Finding) -> float:
        """
        Calculate risk score for an individual finding.
        
        Args:
            finding: Finding to score
            
        Returns:
            Risk score (0-100)
        """
        try:
            # Start with base severity score
            base_score = self.severity_weights.get(finding.severity.value, 40)
            
            # Apply multipliers based on various factors
            final_score = base_score
            
            # History exposure multiplier
            if finding.exposure_multiplier > 1.0:
                final_score *= finding.exposure_multiplier
            
            # Exploitability multiplier
            if finding.exploitability_multiplier > 1.0:
                final_score *= finding.exploitability_multiplier
            
            # Secret type multipliers
            if finding.finding_type == FindingType.SECRET:
                final_score *= self._get_secret_type_multiplier(finding)
            
            # Confidence multiplier
            final_score *= self._get_confidence_multiplier(finding.confidence)
            
            # CVE/CWE specific multipliers
            if finding.cve_id:
                final_score *= self._get_cve_multiplier(finding)
            
            if finding.cwe_id:
                final_score *= self._get_cwe_multiplier(finding)
            
            # File path multipliers
            final_score *= self._get_file_path_multiplier(finding.file_path)
            
            # Tag-based multipliers
            final_score *= self._get_tag_multipliers(finding.tags)
            
            # Ensure score is within bounds
            final_score = max(0.0, min(100.0, final_score))
            
            return final_score
            
        except Exception as e:
            raise ScoringError(f"Error calculating finding risk score: {e}") from e
    
    def calculate_repository_risk_score(self, findings: List[Finding]) -> float:
        """
        Calculate overall repository risk score.
        
        Args:
            findings: List of all findings
            
        Returns:
            Repository risk score (0-100)
        """
        try:
            if not findings:
                return 0.0
            
            # Calculate individual finding scores
            scored_findings = []
            for finding in findings:
                finding.risk_score = self.calculate_finding_risk_score(finding)
                scored_findings.append(finding)
            
            # Sort by risk score (highest first)
            scored_findings.sort(key=lambda f: f.risk_score, reverse=True)
            
            # Take top N findings for repository score calculation
            top_findings = scored_findings[:self.max_findings_for_score]
            
            if not top_findings:
                return 0.0
            
            # Calculate weighted average
            total_weight = 0.0
            weighted_sum = 0.0
            
            for i, finding in enumerate(top_findings):
                # Weight decreases with position (top findings have more impact)
                weight = 1.0 / (i + 1)
                total_weight += weight
                weighted_sum += finding.risk_score * weight
            
            if total_weight == 0:
                return 0.0
            
            repository_score = weighted_sum / total_weight
            
            # Apply repository-level multipliers
            repository_score *= self._get_repository_multipliers(findings)
            
            # Ensure score is within bounds
            repository_score = max(0.0, min(100.0, repository_score))
            
            return repository_score
            
        except Exception as e:
            raise ScoringError(f"Error calculating repository risk score: {e}") from e
    
    def _get_secret_type_multiplier(self, finding: Finding) -> float:
        """Get multiplier based on secret type."""
        if not finding.metadata:
            return 1.0
        
        secret_type = finding.metadata.get("secret_type", "").lower()
        
        # High-value secrets
        if any(keyword in secret_type for keyword in ["private-key", "master-key", "root-password"]):
            return self.multipliers.get("private_key", 2.0)
        
        # API tokens and keys
        if any(keyword in secret_type for keyword in ["api-key", "token", "access-key"]):
            return self.multipliers.get("api_token", 1.8)
        
        return 1.0
    
    def _get_confidence_multiplier(self, confidence: float) -> float:
        """Get multiplier based on confidence level."""
        if confidence >= 0.9:
            return self.multipliers.get("high_confidence", 1.1)
        elif confidence <= 0.5:
            return self.multipliers.get("low_confidence", 0.8)
        else:
            return 1.0
    
    def _get_cve_multiplier(self, finding: Finding) -> float:
        """Get multiplier based on CVE information."""
        if not finding.cve_id:
            return 1.0
        
        # Check if CVE has published exploits
        # This would typically involve checking external databases
        # For now, we'll use a simple heuristic based on CVSS score
        if finding.cvss_score and finding.cvss_score >= 7.0:
            return self.multipliers.get("published_exploit", 1.5)
        
        return 1.0
    
    def _get_cwe_multiplier(self, finding: Finding) -> float:
        """Get multiplier based on CWE information."""
        if not finding.cwe_id:
            return 1.0
        
        # High-risk CWE categories
        high_risk_cwes = [
            "CWE-79",  # Cross-site Scripting
            "CWE-89",  # SQL Injection
            "CWE-78",  # OS Command Injection
            "CWE-22",  # Path Traversal
            "CWE-352", # Cross-Site Request Forgery
            "CWE-434", # Unrestricted Upload of File
            "CWE-798", # Use of Hard-coded Credentials
        ]
        
        if finding.cwe_id in high_risk_cwes:
            return 1.3
        
        return 1.0
    
    def _get_file_path_multiplier(self, file_path: Optional[str]) -> float:
        """Get multiplier based on file path."""
        if not file_path:
            return 1.0
        
        file_path_lower = file_path.lower()
        
        # Production/sensitive files
        if any(keyword in file_path_lower for keyword in [
            "config", "secret", "password", "key", "credential",
            "production", "prod", "live", "main", "master"
        ]):
            return self.multipliers.get("production_branch", 1.3)
        
        # World-writable files (heuristic based on common patterns)
        if any(pattern in file_path_lower for pattern in [
            "/tmp/", "/var/tmp/", "/dev/shm/", "777", "666"
        ]):
            return self.multipliers.get("world_writable", 1.2)
        
        return 1.0
    
    def _get_tag_multipliers(self, tags: List[str]) -> float:
        """Get multiplier based on finding tags."""
        multiplier = 1.0
        
        for tag in tags:
            tag_lower = tag.lower()
            
            # OWASP Top 10 tags
            if "owasp:a01" in tag_lower:  # Broken Access Control
                multiplier *= 1.4
            elif "owasp:a02" in tag_lower:  # Cryptographic Failures
                multiplier *= 1.3
            elif "owasp:a03" in tag_lower:  # Injection
                multiplier *= 1.5
            elif "owasp:a04" in tag_lower:  # Insecure Design
                multiplier *= 1.2
            elif "owasp:a05" in tag_lower:  # Security Misconfiguration
                multiplier *= 1.1
            
            # CWE-based multipliers
            if "cwe:79" in tag_lower:  # XSS
                multiplier *= 1.3
            elif "cwe:89" in tag_lower:  # SQL Injection
                multiplier *= 1.5
            elif "cwe:78" in tag_lower:  # Command Injection
                multiplier *= 1.6
            
            # Secret-specific tags
            if "secret:private-key" in tag_lower:
                multiplier *= self.multipliers.get("private_key", 2.0)
            elif "secret:api-key" in tag_lower:
                multiplier *= self.multipliers.get("api_token", 1.8)
        
        return multiplier
    
    def _get_repository_multipliers(self, findings: List[Finding]) -> float:
        """Get repository-level multipliers."""
        multiplier = 1.0
        
        # Count findings by type
        finding_counts = {}
        for finding in findings:
            finding_type = finding.finding_type.value
            finding_counts[finding_type] = finding_counts.get(finding_type, 0) + 1
        
        # Multiple findings of the same type increase risk
        for finding_type, count in finding_counts.items():
            if count > 5:  # Many findings of same type
                multiplier *= 1.2
            elif count > 10:  # Very many findings of same type
                multiplier *= 1.4
        
        # Critical findings have high impact
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        if critical_count > 0:
            multiplier *= 1.3
        
        # High findings also have significant impact
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        if high_count > 5:
            multiplier *= 1.2
        
        return multiplier
    
    def get_risk_level(self, score: float) -> str:
        """
        Get risk level based on score.
        
        Args:
            score: Risk score (0-100)
            
        Returns:
            Risk level string
        """
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_risk_breakdown(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Get detailed risk breakdown for findings.
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary with risk breakdown
        """
        if not findings:
            return {
                "total_findings": 0,
                "risk_score": 0.0,
                "risk_level": "LOW",
                "severity_breakdown": {},
                "type_breakdown": {},
                "top_findings": [],
            }
        
        # Calculate scores
        for finding in findings:
            finding.risk_score = self.calculate_finding_risk_score(finding)
        
        repository_score = self.calculate_repository_risk_score(findings)
        
        # Severity breakdown
        severity_breakdown = {}
        for severity in Severity:
            severity_findings = [f for f in findings if f.severity == severity]
            severity_breakdown[severity.value] = {
                "count": len(severity_findings),
                "avg_score": sum(f.risk_score for f in severity_findings) / len(severity_findings) if severity_findings else 0.0,
            }
        
        # Type breakdown
        type_breakdown = {}
        for finding_type in FindingType:
            type_findings = [f for f in findings if f.finding_type == finding_type]
            type_breakdown[finding_type.value] = {
                "count": len(type_findings),
                "avg_score": sum(f.risk_score for f in type_findings) / len(type_findings) if type_findings else 0.0,
            }
        
        # Top findings
        top_findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:10]
        
        return {
            "total_findings": len(findings),
            "risk_score": repository_score,
            "risk_level": self.get_risk_level(repository_score),
            "severity_breakdown": severity_breakdown,
            "type_breakdown": type_breakdown,
            "top_findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "risk_score": f.risk_score,
                    "file_path": f.file_path,
                }
                for f in top_findings
            ],
        }
