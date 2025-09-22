"""
Repo-Scan: Advanced Repository Security Scanning Tool

A comprehensive security scanning tool for repositories that supports:
- SAST (Static Application Security Testing)
- SCA (Software Composition Analysis)
- Secret detection
- IaC (Infrastructure as Code) scanning
- Container security
- Supply chain verification
- And more through an extensible plugin system
"""

__version__ = "1.0.0"
__author__ = "Security Team"
__email__ = "security@example.com"

from .core.config import Config
from .core.models import ScanResult, Finding, Severity
from .orchestrator import ScanOrchestrator

__all__ = [
    "Config",
    "ScanResult", 
    "Finding",
    "Severity",
    "ScanOrchestrator",
]
