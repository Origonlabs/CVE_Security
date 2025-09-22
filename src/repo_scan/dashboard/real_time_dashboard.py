"""
Real-time Dashboard.

This module implements a real-time dashboard for monitoring
repo-scan metrics, alerts, and system status.
"""

import asyncio
import json
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
import threading
from collections import deque

from .metrics_collector import MetricsCollector
from .alert_manager import AlertManager
from .visualization_engine import VisualizationEngine


@dataclass
class DashboardConfig:
    """Dashboard configuration."""
    refresh_interval: float = 1.0
    max_data_points: int = 100
    enable_alerts: bool = True
    enable_visualizations: bool = True
    auto_refresh: bool = True


@dataclass
class DashboardData:
    """Dashboard data structure."""
    timestamp: datetime
    system_metrics: Dict[str, Any]
    security_metrics: Dict[str, Any]
    repository_metrics: Dict[str, Any]
    user_metrics: Dict[str, Any]
    alerts: List[Dict[str, Any]]
    visualizations: Dict[str, Any]


class RealTimeDashboard:
    """
    Real-time dashboard for repo-scan.
    
    Features:
    - Live metrics display
    - Real-time alerts
    - Interactive visualizations
    - System status monitoring
    - Performance tracking
    """
    
    def __init__(self, config: Optional[DashboardConfig] = None):
        """Initialize the real-time dashboard."""
        self.config = config or DashboardConfig()
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager()
        self.visualization_engine = VisualizationEngine()
        
        # Dashboard state
        self.is_running = False
        self.dashboard_thread = None
        self.dashboard_data = deque(maxlen=self.config.max_data_points)
        
        # Callbacks
        self.data_callbacks = []
        self.alert_callbacks = []
        
        # Initialize components
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize dashboard components."""
        # Start metrics collection
        self.metrics_collector.start_collection()
        
        # Register metric callbacks
        self.metrics_collector.register_callback('system', self._on_system_metric)
        self.metrics_collector.register_callback('security', self._on_security_metric)
        self.metrics_collector.register_callback('repository', self._on_repository_metric)
        self.metrics_collector.register_callback('user', self._on_user_metric)
        
        # Register alert callbacks
        self.alert_manager.register_callback(self._on_alert)
    
    def start(self):
        """Start the dashboard."""
        if self.is_running:
            return
        
        self.is_running = True
        self.dashboard_thread = threading.Thread(target=self._dashboard_loop, daemon=True)
        self.dashboard_thread.start()
    
    def stop(self):
        """Stop the dashboard."""
        self.is_running = False
        if self.dashboard_thread:
            self.dashboard_thread.join()
        
        # Stop metrics collection
        self.metrics_collector.stop_collection()
    
    def _dashboard_loop(self):
        """Main dashboard loop."""
        while self.is_running:
            try:
                # Collect dashboard data
                dashboard_data = self._collect_dashboard_data()
                
                # Store data
                self.dashboard_data.append(dashboard_data)
                
                # Process callbacks
                self._process_data_callbacks(dashboard_data)
                
                # Update visualizations
                if self.config.enable_visualizations:
                    self._update_visualizations(dashboard_data)
                
                time.sleep(self.config.refresh_interval)
                
            except Exception as e:
                print(f"Error in dashboard loop: {e}")
                time.sleep(self.config.refresh_interval)
    
    def _collect_dashboard_data(self) -> DashboardData:
        """Collect data for dashboard."""
        # Get aggregated metrics
        system_metrics = self.metrics_collector.get_system_metrics(300)
        security_metrics = self.metrics_collector.get_security_metrics(300)
        repository_metrics = self.metrics_collector.get_repository_metrics(300)
        user_metrics = self.metrics_collector.get_user_metrics(300)
        
        # Get alerts
        alerts = self.alert_manager.get_active_alerts()
        
        # Get visualizations
        visualizations = self.visualization_engine.get_visualizations()
        
        return DashboardData(
            timestamp=datetime.now(),
            system_metrics=self._aggregate_system_metrics(system_metrics),
            security_metrics=self._aggregate_security_metrics(security_metrics),
            repository_metrics=self._aggregate_repository_metrics(repository_metrics),
            user_metrics=self._aggregate_user_metrics(user_metrics),
            alerts=alerts,
            visualizations=visualizations
        )
    
    def _aggregate_system_metrics(self, metrics: List[Any]) -> Dict[str, Any]:
        """Aggregate system metrics."""
        if not metrics:
            return {}
        
        return {
            'cpu_percent': sum(m.cpu_percent for m in metrics) / len(metrics),
            'memory_percent': sum(m.memory_percent for m in metrics) / len(metrics),
            'disk_usage_percent': sum(m.disk_usage_percent for m in metrics) / len(metrics),
            'process_count': metrics[-1].process_count if metrics else 0,
            'network_io': metrics[-1].network_io if metrics else {},
            'status': self._determine_system_status(metrics)
        }
    
    def _aggregate_security_metrics(self, metrics: List[Any]) -> Dict[str, Any]:
        """Aggregate security metrics."""
        if not metrics:
            return {}
        
        return {
            'total_scans': metrics[-1].total_scans if metrics else 0,
            'active_scans': metrics[-1].active_scans if metrics else 0,
            'vulnerabilities_found': metrics[-1].vulnerabilities_found if metrics else 0,
            'critical_vulnerabilities': metrics[-1].critical_vulnerabilities if metrics else 0,
            'scan_duration_avg': metrics[-1].scan_duration_avg if metrics else 0,
            'status': self._determine_security_status(metrics)
        }
    
    def _aggregate_repository_metrics(self, metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate repository metrics."""
        if not metrics:
            return {}
        
        return {
            'repositories_analyzed': sum(m.get('repositories_analyzed', 0) for m in metrics),
            'files_analyzed': sum(m.get('files_analyzed', 0) for m in metrics),
            'dependencies_analyzed': sum(m.get('dependencies_analyzed', 0) for m in metrics),
            'vulnerabilities_found': sum(m.get('vulnerabilities_found', 0) for m in metrics),
            'status': self._determine_repository_status(metrics)
        }
    
    def _aggregate_user_metrics(self, metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate user metrics."""
        if not metrics:
            return {}
        
        return {
            'active_users': metrics[-1].get('active_users', 0) if metrics else 0,
            'total_sessions': sum(m.get('total_sessions', 0) for m in metrics),
            'api_requests': sum(m.get('api_requests', 0) for m in metrics),
            'gui_sessions': sum(m.get('gui_sessions', 0) for m in metrics),
            'status': self._determine_user_status(metrics)
        }
    
    def _determine_system_status(self, metrics: List[Any]) -> str:
        """Determine system status."""
        if not metrics:
            return 'unknown'
        
        latest = metrics[-1]
        
        if latest.cpu_percent > 90 or latest.memory_percent > 90 or latest.disk_usage_percent > 90:
            return 'critical'
        elif latest.cpu_percent > 70 or latest.memory_percent > 70 or latest.disk_usage_percent > 70:
            return 'warning'
        else:
            return 'healthy'
    
    def _determine_security_status(self, metrics: List[Any]) -> str:
        """Determine security status."""
        if not metrics:
            return 'unknown'
        
        latest = metrics[-1]
        
        if latest.critical_vulnerabilities > 0:
            return 'critical'
        elif latest.vulnerabilities_found > 10:
            return 'warning'
        else:
            return 'healthy'
    
    def _determine_repository_status(self, metrics: List[Dict[str, Any]]) -> str:
        """Determine repository status."""
        if not metrics:
            return 'unknown'
        
        total_vulnerabilities = sum(m.get('vulnerabilities_found', 0) for m in metrics)
        
        if total_vulnerabilities > 50:
            return 'critical'
        elif total_vulnerabilities > 20:
            return 'warning'
        else:
            return 'healthy'
    
    def _determine_user_status(self, metrics: List[Dict[str, Any]]) -> str:
        """Determine user status."""
        if not metrics:
            return 'unknown'
        
        active_users = metrics[-1].get('active_users', 0) if metrics else 0
        
        if active_users > 100:
            return 'high_load'
        elif active_users > 50:
            return 'moderate_load'
        else:
            return 'normal'
    
    def _update_visualizations(self, dashboard_data: DashboardData):
        """Update visualizations."""
        try:
            # Update system metrics visualization
            self.visualization_engine.update_system_metrics(dashboard_data.system_metrics)
            
            # Update security metrics visualization
            self.visualization_engine.update_security_metrics(dashboard_data.security_metrics)
            
            # Update repository metrics visualization
            self.visualization_engine.update_repository_metrics(dashboard_data.repository_metrics)
            
            # Update user metrics visualization
            self.visualization_engine.update_user_metrics(dashboard_data.user_metrics)
            
        except Exception as e:
            print(f"Error updating visualizations: {e}")
    
    def _process_data_callbacks(self, dashboard_data: DashboardData):
        """Process data callbacks."""
        for callback in self.data_callbacks:
            try:
                callback(dashboard_data)
            except Exception as e:
                print(f"Error in data callback: {e}")
    
    def _on_system_metric(self, name: str, metric: Any):
        """Handle system metric updates."""
        # Check for system alerts
        if hasattr(metric, 'cpu_percent') and metric.cpu_percent > 90:
            self.alert_manager.create_alert(
                'system',
                'HIGH',
                f'High CPU usage: {metric.cpu_percent:.1f}%',
                {'metric': 'cpu_percent', 'value': metric.cpu_percent}
            )
        
        if hasattr(metric, 'memory_percent') and metric.memory_percent > 90:
            self.alert_manager.create_alert(
                'system',
                'HIGH',
                f'High memory usage: {metric.memory_percent:.1f}%',
                {'metric': 'memory_percent', 'value': metric.memory_percent}
            )
    
    def _on_security_metric(self, name: str, metric: Any):
        """Handle security metric updates."""
        # Check for security alerts
        if hasattr(metric, 'critical_vulnerabilities') and metric.critical_vulnerabilities > 0:
            self.alert_manager.create_alert(
                'security',
                'CRITICAL',
                f'Critical vulnerabilities found: {metric.critical_vulnerabilities}',
                {'metric': 'critical_vulnerabilities', 'value': metric.critical_vulnerabilities}
            )
    
    def _on_repository_metric(self, name: str, metric: Any):
        """Handle repository metric updates."""
        # Check for repository alerts
        if isinstance(metric, dict) and metric.get('vulnerabilities_found', 0) > 20:
            self.alert_manager.create_alert(
                'repository',
                'MEDIUM',
                f'High number of vulnerabilities: {metric["vulnerabilities_found"]}',
                {'metric': 'vulnerabilities_found', 'value': metric['vulnerabilities_found']}
            )
    
    def _on_user_metric(self, name: str, metric: Any):
        """Handle user metric updates."""
        # Check for user alerts
        if isinstance(metric, dict) and metric.get('active_users', 0) > 100:
            self.alert_manager.create_alert(
                'user',
                'LOW',
                f'High user activity: {metric["active_users"]} active users',
                {'metric': 'active_users', 'value': metric['active_users']}
            )
    
    def _on_alert(self, alert: Dict[str, Any]):
        """Handle alert updates."""
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Error in alert callback: {e}")
    
    def register_data_callback(self, callback: Callable[[DashboardData], None]):
        """Register a data callback."""
        self.data_callbacks.append(callback)
    
    def unregister_data_callback(self, callback: Callable[[DashboardData], None]):
        """Unregister a data callback."""
        try:
            self.data_callbacks.remove(callback)
        except ValueError:
            pass
    
    def register_alert_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Register an alert callback."""
        self.alert_callbacks.append(callback)
    
    def unregister_alert_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Unregister an alert callback."""
        try:
            self.alert_callbacks.remove(callback)
        except ValueError:
            pass
    
    def get_dashboard_data(self, window: int = 300) -> List[DashboardData]:
        """Get dashboard data within a time window."""
        cutoff_time = datetime.now() - timedelta(seconds=window)
        return [data for data in self.dashboard_data if data.timestamp > cutoff_time]
    
    def get_latest_data(self) -> Optional[DashboardData]:
        """Get the latest dashboard data."""
        return self.dashboard_data[-1] if self.dashboard_data else None
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status."""
        latest_data = self.get_latest_data()
        if not latest_data:
            return {'status': 'unknown', 'message': 'No data available'}
        
        system_metrics = latest_data.system_metrics
        security_metrics = latest_data.security_metrics
        repository_metrics = latest_data.repository_metrics
        user_metrics = latest_data.user_metrics
        
        # Determine overall status
        statuses = [
            system_metrics.get('status', 'unknown'),
            security_metrics.get('status', 'unknown'),
            repository_metrics.get('status', 'unknown'),
            user_metrics.get('status', 'unknown')
        ]
        
        if 'critical' in statuses:
            overall_status = 'critical'
        elif 'warning' in statuses:
            overall_status = 'warning'
        else:
            overall_status = 'healthy'
        
        return {
            'status': overall_status,
            'system': system_metrics.get('status', 'unknown'),
            'security': security_metrics.get('status', 'unknown'),
            'repository': repository_metrics.get('status', 'unknown'),
            'user': user_metrics.get('status', 'unknown'),
            'timestamp': latest_data.timestamp.isoformat()
        }
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        latest_data = self.get_latest_data()
        if not latest_data:
            return {}
        
        return {
            'system': latest_data.system_metrics,
            'security': latest_data.security_metrics,
            'repository': latest_data.repository_metrics,
            'user': latest_data.user_metrics,
            'alerts': latest_data.alerts,
            'timestamp': latest_data.timestamp.isoformat()
        }
    
    def export_dashboard_data(self, format: str = 'json', window: int = 3600) -> str:
        """Export dashboard data."""
        data = self.get_dashboard_data(window)
        
        if format == 'json':
            return json.dumps([asdict(d) for d in data], indent=2, default=str)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def create_custom_metric(self, name: str, value: float, tags: Optional[Dict[str, str]] = None, metadata: Optional[Dict[str, Any]] = None):
        """Create a custom metric."""
        self.metrics_collector.add_metric(name, value, tags, metadata)
    
    def create_custom_alert(self, category: str, severity: str, message: str, metadata: Optional[Dict[str, Any]] = None):
        """Create a custom alert."""
        self.alert_manager.create_alert(category, severity, message, metadata)
    
    def get_visualization_data(self, visualization_type: str) -> Dict[str, Any]:
        """Get visualization data."""
        return self.visualization_engine.get_visualization_data(visualization_type)
    
    def update_config(self, config: DashboardConfig):
        """Update dashboard configuration."""
        self.config = config
        
        # Update refresh interval
        if hasattr(self, 'dashboard_thread') and self.dashboard_thread:
            # Restart dashboard with new config
            self.stop()
            self.start()
