"""
Real-time Metrics Collector.

This module implements real-time metrics collection including:
- System performance metrics
- Security scan metrics
- Repository analysis metrics
- User activity metrics
- Alert metrics
"""

import asyncio
import psutil
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import deque, defaultdict
import json
import threading
from pathlib import Path


@dataclass
class Metric:
    """Represents a single metric."""
    name: str
    value: float
    timestamp: datetime
    tags: Dict[str, str]
    metadata: Dict[str, Any]


@dataclass
class MetricSeries:
    """Represents a series of metrics."""
    name: str
    metrics: List[Metric]
    aggregation: str  # 'sum', 'avg', 'max', 'min', 'count'
    window_size: int  # in seconds


@dataclass
class SystemMetrics:
    """Represents system performance metrics."""
    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    network_io: Dict[str, float]
    process_count: int
    timestamp: datetime


@dataclass
class SecurityMetrics:
    """Represents security scan metrics."""
    total_scans: int
    active_scans: int
    vulnerabilities_found: int
    critical_vulnerabilities: int
    scan_duration_avg: float
    timestamp: datetime


class MetricsCollector:
    """
    Real-time metrics collector for repo-scan.
    
    Features:
    - System performance monitoring
    - Security scan metrics
    - Repository analysis metrics
    - User activity tracking
    - Custom metric collection
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """Initialize the metrics collector."""
        self.storage_path = storage_path or "data/metrics"
        self.metrics_storage = {}
        self.metric_series = {}
        self.collection_interval = 1.0  # seconds
        self.is_collecting = False
        self.collection_thread = None
        
        # Metric callbacks
        self.metric_callbacks = defaultdict(list)
        
        # Storage for different metric types
        self.system_metrics = deque(maxlen=3600)  # 1 hour of data
        self.security_metrics = deque(maxlen=3600)
        self.repository_metrics = deque(maxlen=3600)
        self.user_metrics = deque(maxlen=3600)
        
        # Initialize storage
        Path(self.storage_path).mkdir(parents=True, exist_ok=True)
    
    def start_collection(self):
        """Start metrics collection."""
        if self.is_collecting:
            return
        
        self.is_collecting = True
        self.collection_thread = threading.Thread(target=self._collection_loop, daemon=True)
        self.collection_thread.start()
    
    def stop_collection(self):
        """Stop metrics collection."""
        self.is_collecting = False
        if self.collection_thread:
            self.collection_thread.join()
    
    def _collection_loop(self):
        """Main collection loop."""
        while self.is_collecting:
            try:
                # Collect system metrics
                system_metrics = self._collect_system_metrics()
                self.system_metrics.append(system_metrics)
                
                # Collect security metrics
                security_metrics = self._collect_security_metrics()
                self.security_metrics.append(security_metrics)
                
                # Collect repository metrics
                repository_metrics = self._collect_repository_metrics()
                self.repository_metrics.append(repository_metrics)
                
                # Collect user metrics
                user_metrics = self._collect_user_metrics()
                self.user_metrics.append(user_metrics)
                
                # Process metric callbacks
                self._process_callbacks()
                
                # Save metrics to storage
                self._save_metrics()
                
                time.sleep(self.collection_interval)
                
            except Exception as e:
                print(f"Error in metrics collection: {e}")
                time.sleep(self.collection_interval)
    
    def _collect_system_metrics(self) -> SystemMetrics:
        """Collect system performance metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_usage_percent = (disk.used / disk.total) * 100
            
            # Network I/O
            network_io = psutil.net_io_counters()
            network_io_dict = {
                'bytes_sent': network_io.bytes_sent,
                'bytes_recv': network_io.bytes_recv,
                'packets_sent': network_io.packets_sent,
                'packets_recv': network_io.packets_recv
            }
            
            # Process count
            process_count = len(psutil.pids())
            
            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_usage_percent=disk_usage_percent,
                network_io=network_io_dict,
                process_count=process_count,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            print(f"Error collecting system metrics: {e}")
            return SystemMetrics(
                cpu_percent=0.0,
                memory_percent=0.0,
                disk_usage_percent=0.0,
                network_io={},
                process_count=0,
                timestamp=datetime.now()
            )
    
    def _collect_security_metrics(self) -> SecurityMetrics:
        """Collect security scan metrics."""
        try:
            # This would typically query a database or scan results
            # For now, return mock data
            return SecurityMetrics(
                total_scans=0,
                active_scans=0,
                vulnerabilities_found=0,
                critical_vulnerabilities=0,
                scan_duration_avg=0.0,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            print(f"Error collecting security metrics: {e}")
            return SecurityMetrics(
                total_scans=0,
                active_scans=0,
                vulnerabilities_found=0,
                critical_vulnerabilities=0,
                scan_duration_avg=0.0,
                timestamp=datetime.now()
            )
    
    def _collect_repository_metrics(self) -> Dict[str, Any]:
        """Collect repository analysis metrics."""
        try:
            # This would typically query repository analysis results
            # For now, return mock data
            return {
                'repositories_analyzed': 0,
                'files_analyzed': 0,
                'dependencies_analyzed': 0,
                'vulnerabilities_found': 0,
                'timestamp': datetime.now()
            }
            
        except Exception as e:
            print(f"Error collecting repository metrics: {e}")
            return {
                'repositories_analyzed': 0,
                'files_analyzed': 0,
                'dependencies_analyzed': 0,
                'vulnerabilities_found': 0,
                'timestamp': datetime.now()
            }
    
    def _collect_user_metrics(self) -> Dict[str, Any]:
        """Collect user activity metrics."""
        try:
            # This would typically query user activity logs
            # For now, return mock data
            return {
                'active_users': 0,
                'total_sessions': 0,
                'api_requests': 0,
                'gui_sessions': 0,
                'timestamp': datetime.now()
            }
            
        except Exception as e:
            print(f"Error collecting user metrics: {e}")
            return {
                'active_users': 0,
                'total_sessions': 0,
                'api_requests': 0,
                'gui_sessions': 0,
                'timestamp': datetime.now()
            }
    
    def _process_callbacks(self):
        """Process metric callbacks."""
        for metric_name, callbacks in self.metric_callbacks.items():
            for callback in callbacks:
                try:
                    callback(metric_name, self._get_latest_metric(metric_name))
                except Exception as e:
                    print(f"Error in metric callback: {e}")
    
    def _get_latest_metric(self, metric_name: str) -> Optional[Metric]:
        """Get the latest metric by name."""
        # This would typically query the appropriate storage
        # For now, return None
        return None
    
    def _save_metrics(self):
        """Save metrics to storage."""
        try:
            # Save system metrics
            if self.system_metrics:
                system_data = [asdict(metric) for metric in list(self.system_metrics)[-100:]]  # Last 100 entries
                with open(Path(self.storage_path) / "system_metrics.json", "w") as f:
                    json.dump(system_data, f, default=str)
            
            # Save security metrics
            if self.security_metrics:
                security_data = [asdict(metric) for metric in list(self.security_metrics)[-100:]]
                with open(Path(self.storage_path) / "security_metrics.json", "w") as f:
                    json.dump(security_data, f, default=str)
            
            # Save repository metrics
            if self.repository_metrics:
                repo_data = list(self.repository_metrics)[-100:]
                with open(Path(self.storage_path) / "repository_metrics.json", "w") as f:
                    json.dump(repo_data, f, default=str)
            
            # Save user metrics
            if self.user_metrics:
                user_data = list(self.user_metrics)[-100:]
                with open(Path(self.storage_path) / "user_metrics.json", "w") as f:
                    json.dump(user_data, f, default=str)
                    
        except Exception as e:
            print(f"Error saving metrics: {e}")
    
    def add_metric(self, name: str, value: float, tags: Optional[Dict[str, str]] = None, metadata: Optional[Dict[str, Any]] = None):
        """Add a custom metric."""
        metric = Metric(
            name=name,
            value=value,
            timestamp=datetime.now(),
            tags=tags or {},
            metadata=metadata or {}
        )
        
        # Store metric
        if name not in self.metrics_storage:
            self.metrics_storage[name] = deque(maxlen=1000)
        
        self.metrics_storage[name].append(metric)
        
        # Process callbacks
        for callback in self.metric_callbacks.get(name, []):
            try:
                callback(name, metric)
            except Exception as e:
                print(f"Error in metric callback: {e}")
    
    def get_metric(self, name: str, window: Optional[int] = None) -> List[Metric]:
        """Get metrics by name."""
        if name not in self.metrics_storage:
            return []
        
        metrics = list(self.metrics_storage[name])
        
        if window:
            cutoff_time = datetime.now() - timedelta(seconds=window)
            metrics = [m for m in metrics if m.timestamp > cutoff_time]
        
        return metrics
    
    def get_metric_series(self, name: str, window: int = 300) -> MetricSeries:
        """Get a metric series with aggregation."""
        metrics = self.get_metric(name, window)
        
        if not metrics:
            return MetricSeries(name=name, metrics=[], aggregation='avg', window_size=window)
        
        # Calculate aggregation
        values = [m.value for m in metrics]
        aggregation = 'avg'  # Default aggregation
        
        return MetricSeries(
            name=name,
            metrics=metrics,
            aggregation=aggregation,
            window_size=window
        )
    
    def register_callback(self, metric_name: str, callback: Callable[[str, Metric], None]):
        """Register a callback for a metric."""
        self.metric_callbacks[metric_name].append(callback)
    
    def unregister_callback(self, metric_name: str, callback: Callable[[str, Metric], None]):
        """Unregister a callback for a metric."""
        if metric_name in self.metric_callbacks:
            try:
                self.metric_callbacks[metric_name].remove(callback)
            except ValueError:
                pass
    
    def get_system_metrics(self, window: int = 300) -> List[SystemMetrics]:
        """Get system metrics within a time window."""
        cutoff_time = datetime.now() - timedelta(seconds=window)
        return [m for m in self.system_metrics if m.timestamp > cutoff_time]
    
    def get_security_metrics(self, window: int = 300) -> List[SecurityMetrics]:
        """Get security metrics within a time window."""
        cutoff_time = datetime.now() - timedelta(seconds=window)
        return [m for m in self.security_metrics if m.timestamp > cutoff_time]
    
    def get_repository_metrics(self, window: int = 300) -> List[Dict[str, Any]]:
        """Get repository metrics within a time window."""
        cutoff_time = datetime.now() - timedelta(seconds=window)
        return [m for m in self.repository_metrics if m.get('timestamp', datetime.min) > cutoff_time]
    
    def get_user_metrics(self, window: int = 300) -> List[Dict[str, Any]]:
        """Get user metrics within a time window."""
        cutoff_time = datetime.now() - timedelta(seconds=window)
        return [m for m in self.user_metrics if m.get('timestamp', datetime.min) > cutoff_time]
    
    def get_aggregated_metrics(self, window: int = 300) -> Dict[str, Any]:
        """Get aggregated metrics for dashboard."""
        system_metrics = self.get_system_metrics(window)
        security_metrics = self.get_security_metrics(window)
        repository_metrics = self.get_repository_metrics(window)
        user_metrics = self.get_user_metrics(window)
        
        aggregated = {
            'system': {
                'cpu_avg': sum(m.cpu_percent for m in system_metrics) / len(system_metrics) if system_metrics else 0,
                'memory_avg': sum(m.memory_percent for m in system_metrics) / len(system_metrics) if system_metrics else 0,
                'disk_avg': sum(m.disk_usage_percent for m in system_metrics) / len(system_metrics) if system_metrics else 0,
                'process_count': system_metrics[-1].process_count if system_metrics else 0
            },
            'security': {
                'total_scans': security_metrics[-1].total_scans if security_metrics else 0,
                'active_scans': security_metrics[-1].active_scans if security_metrics else 0,
                'vulnerabilities_found': security_metrics[-1].vulnerabilities_found if security_metrics else 0,
                'critical_vulnerabilities': security_metrics[-1].critical_vulnerabilities if security_metrics else 0,
                'scan_duration_avg': security_metrics[-1].scan_duration_avg if security_metrics else 0
            },
            'repository': {
                'repositories_analyzed': sum(m.get('repositories_analyzed', 0) for m in repository_metrics),
                'files_analyzed': sum(m.get('files_analyzed', 0) for m in repository_metrics),
                'dependencies_analyzed': sum(m.get('dependencies_analyzed', 0) for m in repository_metrics),
                'vulnerabilities_found': sum(m.get('vulnerabilities_found', 0) for m in repository_metrics)
            },
            'user': {
                'active_users': user_metrics[-1].get('active_users', 0) if user_metrics else 0,
                'total_sessions': sum(m.get('total_sessions', 0) for m in user_metrics),
                'api_requests': sum(m.get('api_requests', 0) for m in user_metrics),
                'gui_sessions': sum(m.get('gui_sessions', 0) for m in user_metrics)
            }
        }
        
        return aggregated
    
    def export_metrics(self, format: str = 'json', window: int = 3600) -> str:
        """Export metrics in specified format."""
        if format == 'json':
            metrics = self.get_aggregated_metrics(window)
            return json.dumps(metrics, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def clear_metrics(self, metric_name: Optional[str] = None):
        """Clear metrics storage."""
        if metric_name:
            if metric_name in self.metrics_storage:
                self.metrics_storage[metric_name].clear()
        else:
            self.metrics_storage.clear()
            self.system_metrics.clear()
            self.security_metrics.clear()
            self.repository_metrics.clear()
            self.user_metrics.clear()
