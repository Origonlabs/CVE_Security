"""
Machine Learning module for repo-scan.

This module provides ML-based security analysis capabilities including:
- Pattern recognition for security vulnerabilities
- Anomaly detection in code patterns
- Risk prediction models
- Behavioral analysis
"""

from .pattern_detector import PatternDetector
from .anomaly_detector import AnomalyDetector
from .risk_predictor import RiskPredictor
from .behavior_analyzer import BehaviorAnalyzer

__all__ = [
    'PatternDetector',
    'AnomalyDetector', 
    'RiskPredictor',
    'BehaviorAnalyzer'
]
