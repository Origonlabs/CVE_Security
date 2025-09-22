"""
Security detectors module for repo-scan.
"""

from .base import BaseDetector
from .registry import DetectorRegistry

__all__ = ["BaseDetector", "DetectorRegistry"]
