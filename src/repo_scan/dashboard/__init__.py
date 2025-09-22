"""
Real-time Dashboard module for repo-scan.

This module provides real-time dashboard capabilities including:
- Live metrics monitoring
- Real-time alerts
- Interactive visualizations
- Performance monitoring
- Security status tracking
"""

from .metrics_collector import MetricsCollector
from .real_time_dashboard import RealTimeDashboard
from .alert_manager import AlertManager
from .visualization_engine import VisualizationEngine

__all__ = [
    'MetricsCollector',
    'RealTimeDashboard',
    'AlertManager',
    'VisualizationEngine'
]
