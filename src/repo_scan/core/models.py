"""
Data models for repo-scan.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pathlib import Path
from pydantic import BaseModel, Field, validator


class Severity(str, Enum):
    """Severity levels for findings."""
    
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingType(str, Enum):
    """Types of security findings."""
    
    SAST = "SAST"
    SCA = "SCA"
    SECRET = "SECRET"
    IAC = "IAC"
    CONTAINER = "CONTAINER"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    PERMISSIONS = "PERMISSIONS"
    LICENSE = "LICENSE"
    CUSTOM = "CUSTOM"


class TechStack(BaseModel):
    """Detected technology stack information."""
    
    languages: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    package_managers: List[str] = Field(default_factory=list)
    containers: List[str] = Field(default_factory=list)
    infrastructure: List[str] = Field(default_factory=list)
    
    def has_language(self, language: str) -> bool:
        """Check if a specific language is detected."""
        return language.lower() in [lang.lower() for lang in self.languages]
    
    def has_framework(self, framework: str) -> bool:
        """Check if a specific framework is detected."""
        return framework.lower() in [fw.lower() for fw in self.frameworks]


class Remediation(BaseModel):
    """Remediation information for a finding."""
    
    description: str
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in remediation (0-1)")
    automation_suggested: bool = False
    steps: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    estimated_effort: Optional[str] = None  # e.g., "low", "medium", "high"


class Finding(BaseModel):
    """Individual security finding."""
    
    id: str
    scanner: str
    finding_type: FindingType
    severity: Severity
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    tags: List[str] = Field(default_factory=list)
    remediation: Optional[Remediation] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Risk scoring fields
    risk_score: float = Field(ge=0.0, le=100.0, default=0.0)
    exposure_multiplier: float = Field(ge=1.0, default=1.0)
    exploitability_multiplier: float = Field(ge=1.0, default=1.0)
    
    @validator('risk_score')
    def validate_risk_score(cls, v: float) -> float:
        """Ensure risk score is within valid range."""
        return max(0.0, min(100.0, v))


class Repository(BaseModel):
    """Repository information."""
    
    path: str
    url: Optional[str] = None
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    tech_stack: TechStack = Field(default_factory=TechStack)
    size_bytes: Optional[int] = None
    file_count: Optional[int] = None
    last_modified: Optional[datetime] = None
    gpg_verified: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanConfig(BaseModel):
    """Configuration for a scan operation."""
    
    repository: Repository
    enabled_scanners: List[str] = Field(default_factory=list)
    exclude_patterns: List[str] = Field(default_factory=list)
    include_patterns: List[str] = Field(default_factory=list)
    max_depth: Optional[int] = None
    timeout: int = 3600
    parallel_scans: bool = True
    custom_rules: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Complete scan result."""
    
    scan_id: str
    repository: Repository
    config: ScanConfig
    findings: List[Finding] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=100.0, default=0.0)
    risk_level: str = "UNKNOWN"
    scan_duration: float = 0.0  # seconds
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    success: bool = True
    error_message: Optional[str] = None
    scanner_results: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('risk_level')
    def validate_risk_level(cls, v: str) -> str:
        """Validate risk level based on score."""
        if v == "UNKNOWN":
            return v
        valid_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid risk level: {v}")
        return v.upper()
    
    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_type(self, finding_type: FindingType) -> List[Finding]:
        """Get findings filtered by type."""
        return [f for f in self.findings if f.finding_type == finding_type]
    
    def get_findings_by_scanner(self, scanner: str) -> List[Finding]:
        """Get findings filtered by scanner."""
        return [f for f in self.findings if f.scanner == scanner]
    
    def get_top_findings(self, limit: int = 10) -> List[Finding]:
        """Get top findings sorted by risk score."""
        return sorted(self.findings, key=lambda f: f.risk_score, reverse=True)[:limit]


class ScanSummary(BaseModel):
    """Summary statistics for a scan."""
    
    total_findings: int = 0
    findings_by_severity: Dict[Severity, int] = Field(default_factory=dict)
    findings_by_type: Dict[FindingType, int] = Field(default_factory=dict)
    findings_by_scanner: Dict[str, int] = Field(default_factory=dict)
    risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    scan_duration: float = 0.0
    success: bool = True
    
    @classmethod
    def from_scan_result(cls, result: ScanResult) -> "ScanSummary":
        """Create summary from scan result."""
        findings_by_severity = {}
        findings_by_type = {}
        findings_by_scanner = {}
        
        for finding in result.findings:
            # Count by severity
            findings_by_severity[finding.severity] = findings_by_severity.get(finding.severity, 0) + 1
            
            # Count by type
            findings_by_type[finding.finding_type] = findings_by_type.get(finding.finding_type, 0) + 1
            
            # Count by scanner
            findings_by_scanner[finding.scanner] = findings_by_scanner.get(finding.scanner, 0) + 1
        
        return cls(
            total_findings=len(result.findings),
            findings_by_severity=findings_by_severity,
            findings_by_type=findings_by_type,
            findings_by_scanner=findings_by_scanner,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            scan_duration=result.scan_duration,
            success=result.success
        )
