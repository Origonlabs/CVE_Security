"""
Anomaly Detection for Security Analysis.

This module implements advanced anomaly detection techniques to identify
unusual patterns, behaviors, and potential security threats in code repositories.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from pathlib import Path
from sklearn.ensemble import IsolationForest, LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
import joblib
import json
from datetime import datetime, timedelta


@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    anomaly_id: str
    anomaly_type: str
    severity: str
    confidence: float
    description: str
    file_path: str
    line_number: int
    context: Dict[str, Any]
    timestamp: datetime
    remediation: str


class AnomalyDetector:
    """
    Advanced anomaly detector for security analysis.
    
    Uses multiple ML algorithms to detect unusual patterns in:
    - Code structure and complexity
    - File access patterns
    - Network communication
    - User behavior
    - System resource usage
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the anomaly detector."""
        self.model_path = model_path or "models/anomaly_detector.joblib"
        
        # Multiple anomaly detection algorithms
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.local_outlier_factor = LocalOutlierFactor(
            n_neighbors=20,
            contamination=0.1
        )
        self.one_class_svm = OneClassSVM(
            nu=0.1,
            kernel='rbf',
            gamma='scale'
        )
        
        # Preprocessing
        self.scaler = RobustScaler()  # More robust to outliers
        self.pca = PCA(n_components=0.95)  # Keep 95% of variance
        
        # Baseline statistics
        self.baseline_stats = {}
        self.thresholds = {}
        
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models if available."""
        try:
            if Path(self.model_path).exists():
                models = joblib.load(self.model_path)
                self.isolation_forest = models.get('isolation_forest', self.isolation_forest)
                self.local_outlier_factor = models.get('local_outlier_factor', self.local_outlier_factor)
                self.one_class_svm = models.get('one_class_svm', self.one_class_svm)
                self.scaler = models.get('scaler', self.scaler)
                self.pca = models.get('pca', self.pca)
                self.baseline_stats = models.get('baseline_stats', {})
                self.thresholds = models.get('thresholds', {})
        except Exception as e:
            print(f"Warning: Could not load models: {e}")
    
    def _save_models(self):
        """Save trained models."""
        try:
            Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
            models = {
                'isolation_forest': self.isolation_forest,
                'local_outlier_factor': self.local_outlier_factor,
                'one_class_svm': self.one_class_svm,
                'scaler': self.scaler,
                'pca': self.pca,
                'baseline_stats': self.baseline_stats,
                'thresholds': self.thresholds
            }
            joblib.dump(models, self.model_path)
        except Exception as e:
            print(f"Warning: Could not save models: {e}")
    
    def extract_behavioral_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract behavioral features from repository data."""
        features = {}
        
        # Code structure features
        features.update(self._extract_code_structure_features(repo_data))
        
        # File access patterns
        features.update(self._extract_file_access_features(repo_data))
        
        # Network patterns
        features.update(self._extract_network_features(repo_data))
        
        # Temporal patterns
        features.update(self._extract_temporal_features(repo_data))
        
        # Resource usage patterns
        features.update(self._extract_resource_features(repo_data))
        
        return features
    
    def _extract_code_structure_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract code structure features."""
        features = {}
        
        files = repo_data.get('files', [])
        if not files:
            return features
        
        # File size distribution
        file_sizes = [f.get('size', 0) for f in files]
        features['avg_file_size'] = np.mean(file_sizes) if file_sizes else 0
        features['std_file_size'] = np.std(file_sizes) if file_sizes else 0
        features['max_file_size'] = np.max(file_sizes) if file_sizes else 0
        
        # File type distribution
        file_extensions = [Path(f.get('path', '')).suffix for f in files]
        extension_counts = {}
        for ext in file_extensions:
            extension_counts[ext] = extension_counts.get(ext, 0) + 1
        
        features['unique_extensions'] = len(extension_counts)
        features['most_common_extension_ratio'] = (
            max(extension_counts.values()) / len(files) if files else 0
        )
        
        # Code complexity features
        total_lines = sum(f.get('lines', 0) for f in files)
        features['total_lines'] = total_lines
        features['avg_lines_per_file'] = total_lines / len(files) if files else 0
        
        # Import patterns
        import_patterns = []
        for file_data in files:
            content = file_data.get('content', '')
            imports = self._extract_imports(content)
            import_patterns.extend(imports)
        
        features['unique_imports'] = len(set(import_patterns))
        features['avg_imports_per_file'] = len(import_patterns) / len(files) if files else 0
        
        return features
    
    def _extract_file_access_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract file access pattern features."""
        features = {}
        
        # File modification patterns
        modifications = repo_data.get('modifications', [])
        if modifications:
            mod_times = [m.get('timestamp', 0) for m in modifications]
            features['modification_frequency'] = len(modifications) / max(mod_times) if max(mod_times) > 0 else 0
            features['modification_variance'] = np.var(mod_times) if mod_times else 0
        
        # File access patterns
        access_patterns = repo_data.get('access_patterns', [])
        if access_patterns:
            features['concurrent_access'] = sum(1 for p in access_patterns if p.get('concurrent', False))
            features['unusual_access_time'] = sum(1 for p in access_patterns if p.get('unusual_time', False))
        
        return features
    
    def _extract_network_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract network communication features."""
        features = {}
        
        network_data = repo_data.get('network', {})
        
        # HTTP requests
        http_requests = network_data.get('http_requests', [])
        features['http_request_count'] = len(http_requests)
        features['unique_domains'] = len(set(r.get('domain', '') for r in http_requests))
        
        # API calls
        api_calls = network_data.get('api_calls', [])
        features['api_call_count'] = len(api_calls)
        features['unique_apis'] = len(set(c.get('endpoint', '') for c in api_calls))
        
        # Data transfer
        data_transfer = network_data.get('data_transfer', {})
        features['bytes_sent'] = data_transfer.get('bytes_sent', 0)
        features['bytes_received'] = data_transfer.get('bytes_received', 0)
        
        return features
    
    def _extract_temporal_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract temporal pattern features."""
        features = {}
        
        # Commit patterns
        commits = repo_data.get('commits', [])
        if commits:
            commit_times = [c.get('timestamp', 0) for c in commits]
            commit_times.sort()
            
            # Time intervals between commits
            intervals = [commit_times[i+1] - commit_times[i] for i in range(len(commit_times)-1)]
            features['avg_commit_interval'] = np.mean(intervals) if intervals else 0
            features['std_commit_interval'] = np.std(intervals) if intervals else 0
            
            # Commit frequency by hour
            hours = [datetime.fromtimestamp(t).hour for t in commit_times]
            hour_counts = {}
            for hour in hours:
                hour_counts[hour] = hour_counts.get(hour, 0) + 1
            
            features['unusual_hour_commits'] = sum(1 for h, c in hour_counts.items() if h < 6 or h > 22)
        
        return features
    
    def _extract_resource_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract resource usage features."""
        features = {}
        
        resource_data = repo_data.get('resources', {})
        
        # CPU usage
        cpu_usage = resource_data.get('cpu_usage', [])
        if cpu_usage:
            features['avg_cpu_usage'] = np.mean(cpu_usage)
            features['max_cpu_usage'] = np.max(cpu_usage)
            features['cpu_spikes'] = sum(1 for u in cpu_usage if u > 80)
        
        # Memory usage
        memory_usage = resource_data.get('memory_usage', [])
        if memory_usage:
            features['avg_memory_usage'] = np.mean(memory_usage)
            features['max_memory_usage'] = np.max(memory_usage)
            features['memory_spikes'] = sum(1 for u in memory_usage if u > 80)
        
        # Disk usage
        disk_usage = resource_data.get('disk_usage', {})
        features['disk_usage_percent'] = disk_usage.get('percent', 0)
        features['disk_io_operations'] = disk_usage.get('io_operations', 0)
        
        return features
    
    def _extract_imports(self, content: str) -> List[str]:
        """Extract import statements from code content."""
        import re
        imports = []
        
        # Python imports
        python_imports = re.findall(r'import\s+(\w+)', content)
        imports.extend(python_imports)
        
        # JavaScript imports
        js_imports = re.findall(r'import\s+.*from\s+[\'"]([^\'"]+)[\'"]', content)
        imports.extend(js_imports)
        
        # Java imports
        java_imports = re.findall(r'import\s+([\w.]+)', content)
        imports.extend(java_imports)
        
        return imports
    
    def detect_anomalies(self, repo_data: Dict[str, Any]) -> List[Anomaly]:
        """Detect anomalies in repository data."""
        anomalies = []
        
        # Extract features
        features = self.extract_behavioral_features(repo_data)
        if not features:
            return anomalies
        
        # Convert to array
        feature_values = list(features.values())
        X = np.array([feature_values])
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Apply PCA
        X_pca = self.pca.transform(X_scaled)
        
        # Detect anomalies using multiple algorithms
        isolation_pred = self.isolation_forest.predict(X_pca)[0]
        isolation_score = self.isolation_forest.score_samples(X_pca)[0]
        
        lof_pred = self.local_outlier_factor.fit_predict(X_pca)[0]
        lof_score = self.local_outlier_factor.negative_outlier_factor_[0]
        
        svm_pred = self.one_class_svm.predict(X_pca)[0]
        svm_score = self.one_class_svm.score_samples(X_pca)[0]
        
        # Combine predictions
        anomaly_scores = {
            'isolation_forest': (isolation_pred == -1, abs(isolation_score)),
            'local_outlier_factor': (lof_pred == -1, abs(lof_score)),
            'one_class_svm': (svm_pred == -1, abs(svm_score))
        }
        
        # Calculate overall anomaly score
        anomaly_count = sum(1 for is_anomaly, _ in anomaly_scores.values() if is_anomaly)
        avg_confidence = np.mean([score for _, score in anomaly_scores.values()])
        
        if anomaly_count >= 2:  # At least 2 algorithms agree
            anomaly = Anomaly(
                anomaly_id=f"anomaly_{datetime.now().timestamp()}",
                anomaly_type="behavioral_anomaly",
                severity=self._determine_severity(anomaly_count, avg_confidence),
                confidence=avg_confidence,
                description=self._generate_anomaly_description(anomaly_scores, features),
                file_path=repo_data.get('path', 'unknown'),
                line_number=0,
                context={
                    'features': features,
                    'scores': anomaly_scores,
                    'algorithms': list(anomaly_scores.keys())
                },
                timestamp=datetime.now(),
                remediation=self._get_anomaly_remediation(anomaly_scores, features)
            )
            anomalies.append(anomaly)
        
        return anomalies
    
    def _determine_severity(self, anomaly_count: int, confidence: float) -> str:
        """Determine anomaly severity based on count and confidence."""
        if anomaly_count == 3 and confidence > 0.8:
            return 'CRITICAL'
        elif anomaly_count >= 2 and confidence > 0.6:
            return 'HIGH'
        elif anomaly_count >= 2 and confidence > 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_anomaly_description(self, anomaly_scores: Dict, features: Dict) -> str:
        """Generate human-readable anomaly description."""
        descriptions = []
        
        if anomaly_scores['isolation_forest'][0]:
            descriptions.append("Isolation Forest detected unusual patterns")
        
        if anomaly_scores['local_outlier_factor'][0]:
            descriptions.append("Local Outlier Factor identified outliers")
        
        if anomaly_scores['one_class_svm'][0]:
            descriptions.append("One-Class SVM found anomalous behavior")
        
        # Add specific feature-based descriptions
        if features.get('unusual_hour_commits', 0) > 0:
            descriptions.append("Unusual commit times detected")
        
        if features.get('cpu_spikes', 0) > 0:
            descriptions.append("CPU usage spikes detected")
        
        if features.get('memory_spikes', 0) > 0:
            descriptions.append("Memory usage spikes detected")
        
        return "; ".join(descriptions) if descriptions else "General behavioral anomaly detected"
    
    def _get_anomaly_remediation(self, anomaly_scores: Dict, features: Dict) -> str:
        """Get remediation advice for anomalies."""
        remediations = []
        
        if features.get('unusual_hour_commits', 0) > 0:
            remediations.append("Review commit times and ensure they align with normal working hours")
        
        if features.get('cpu_spikes', 0) > 0:
            remediations.append("Investigate high CPU usage and optimize resource-intensive operations")
        
        if features.get('memory_spikes', 0) > 0:
            remediations.append("Review memory usage patterns and check for memory leaks")
        
        if features.get('concurrent_access', 0) > 0:
            remediations.append("Review concurrent file access patterns for potential race conditions")
        
        if not remediations:
            remediations.append("Review the detected behavioral patterns and investigate potential security implications")
        
        return "; ".join(remediations)
    
    def train_models(self, training_data: List[Dict[str, Any]]):
        """Train anomaly detection models on historical data."""
        if not training_data:
            return
        
        # Extract features from training data
        features_list = []
        for data in training_data:
            features = self.extract_behavioral_features(data)
            if features:
                features_list.append(list(features.values()))
        
        if not features_list:
            return
        
        # Convert to numpy array
        X = np.array(features_list)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Apply PCA
        X_pca = self.pca.fit_transform(X_scaled)
        
        # Train models
        self.isolation_forest.fit(X_pca)
        self.one_class_svm.fit(X_pca)
        
        # Calculate baseline statistics
        self.baseline_stats = {
            'mean': np.mean(X_pca, axis=0).tolist(),
            'std': np.std(X_pca, axis=0).tolist(),
            'min': np.min(X_pca, axis=0).tolist(),
            'max': np.max(X_pca, axis=0).tolist()
        }
        
        # Calculate thresholds
        self.thresholds = {
            'isolation_forest': np.percentile(self.isolation_forest.score_samples(X_pca), 10),
            'one_class_svm': np.percentile(self.one_class_svm.score_samples(X_pca), 10)
        }
        
        # Save models
        self._save_models()
    
    def update_baseline(self, new_data: Dict[str, Any]):
        """Update baseline statistics with new data."""
        features = self.extract_behavioral_features(new_data)
        if not features:
            return
        
        feature_values = list(features.values())
        X = np.array([feature_values])
        X_scaled = self.scaler.transform(X)
        X_pca = self.pca.transform(X_scaled)
        
        # Update baseline statistics (exponential moving average)
        alpha = 0.1  # Learning rate
        if self.baseline_stats:
            self.baseline_stats['mean'] = [
                (1 - alpha) * old_mean + alpha * new_mean
                for old_mean, new_mean in zip(self.baseline_stats['mean'], X_pca[0])
            ]
        
        # Save updated models
        self._save_models()
