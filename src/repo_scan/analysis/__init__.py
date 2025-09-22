"""
Advanced Analysis module for repo-scan.

This module provides advanced analysis capabilities including:
- Dependency vulnerability graph analysis
- Threat correlation
- Code behavior analysis
- Dynamic scoring
- Compliance analysis
- Automated remediation
"""

from .dependency_analyzer import DependencyAnalyzer
from .threat_correlator import ThreatCorrelator
from .code_behavior_analyzer import CodeBehaviorAnalyzer
from .dynamic_scorer import DynamicScorer
from .compliance_analyzer import ComplianceAnalyzer
from .remediation_engine import RemediationEngine

__all__ = [
    'DependencyAnalyzer',
    'ThreatCorrelator',
    'CodeBehaviorAnalyzer',
    'DynamicScorer',
    'ComplianceAnalyzer',
    'RemediationEngine'
]
