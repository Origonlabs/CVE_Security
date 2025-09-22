"""
Behavior Analysis for Security Monitoring.

This module implements behavioral analysis techniques to identify
unusual patterns in code, commits, and user behavior that might
indicate security threats or policy violations.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional, Set
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import re
import json
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics.pairwise import cosine_similarity
import joblib


@dataclass
class BehaviorPattern:
    """Represents a detected behavior pattern."""
    pattern_id: str
    pattern_type: str
    confidence: float
    severity: str
    description: str
    entities: List[str]
    timeframe: str
    frequency: int
    context: Dict[str, Any]
    risk_score: float


@dataclass
class UserBehavior:
    """Represents user behavior analysis."""
    user_id: str
    behavior_score: float
    risk_level: str
    patterns: List[BehaviorPattern]
    anomalies: List[str]
    recommendations: List[str]


@dataclass
class CommitBehavior:
    """Represents commit behavior analysis."""
    commit_id: str
    behavior_score: float
    risk_level: str
    patterns: List[BehaviorPattern]
    suspicious_indicators: List[str]
    recommendations: List[str]


class BehaviorAnalyzer:
    """
    Advanced behavioral analysis system for security monitoring.
    
    Analyzes:
    - User behavior patterns
    - Commit patterns and timing
    - Code modification patterns
    - Access patterns
    - Communication patterns
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the behavior analyzer."""
        self.model_path = model_path or "models/behavior_analyzer.joblib"
        
        # Behavioral models
        self.user_clusterer = KMeans(n_clusters=5, random_state=42)
        self.commit_clusterer = DBSCAN(eps=0.5, min_samples=2)
        self.scaler = StandardScaler()
        
        # Behavioral baselines
        self.user_baselines = {}
        self.commit_baselines = {}
        self.code_baselines = {}
        
        # Pattern templates
        self.suspicious_patterns = {
            'mass_file_deletion': {
                'pattern': r'delete.*files?',
                'threshold': 10,
                'severity': 'HIGH'
            },
            'unusual_commit_time': {
                'pattern': r'commit.*time',
                'threshold': 0.1,
                'severity': 'MEDIUM'
            },
            'large_commit': {
                'pattern': r'large.*commit',
                'threshold': 1000,
                'severity': 'MEDIUM'
            },
            'sensitive_file_access': {
                'pattern': r'access.*sensitive',
                'threshold': 1,
                'severity': 'HIGH'
            },
            'unusual_branch_activity': {
                'pattern': r'branch.*activity',
                'threshold': 0.2,
                'severity': 'MEDIUM'
            }
        }
        
        # Behavioral indicators
        self.behavioral_indicators = {
            'insider_threat': [
                'unusual_access_patterns',
                'off_hours_activity',
                'mass_data_access',
                'privilege_escalation_attempts',
                'data_exfiltration_patterns'
            ],
            'malicious_actor': [
                'rapid_commit_patterns',
                'suspicious_file_modifications',
                'backdoor_indicators',
                'obfuscated_code',
                'unusual_dependencies'
            ],
            'accidental_risk': [
                'inconsistent_coding_style',
                'missing_security_checks',
                'hardcoded_credentials',
                'insecure_configurations',
                'poor_error_handling'
            ]
        }
        
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models if available."""
        try:
            if Path(self.model_path).exists():
                models = joblib.load(self.model_path)
                self.user_clusterer = models.get('user_clusterer', self.user_clusterer)
                self.commit_clusterer = models.get('commit_clusterer', self.commit_clusterer)
                self.scaler = models.get('scaler', self.scaler)
                self.user_baselines = models.get('user_baselines', {})
                self.commit_baselines = models.get('commit_baselines', {})
                self.code_baselines = models.get('code_baselines', {})
        except Exception as e:
            print(f"Warning: Could not load models: {e}")
    
    def _save_models(self):
        """Save trained models."""
        try:
            Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
            models = {
                'user_clusterer': self.user_clusterer,
                'commit_clusterer': self.commit_clusterer,
                'scaler': self.scaler,
                'user_baselines': self.user_baselines,
                'commit_baselines': self.commit_baselines,
                'code_baselines': self.code_baselines
            }
            joblib.dump(models, self.model_path)
        except Exception as e:
            print(f"Warning: Could not save models: {e}")
    
    def analyze_user_behavior(self, user_data: Dict[str, Any]) -> UserBehavior:
        """Analyze user behavior patterns."""
        user_id = user_data.get('user_id', 'unknown')
        
        # Extract behavioral features
        features = self._extract_user_features(user_data)
        
        # Detect patterns
        patterns = self._detect_user_patterns(user_data, features)
        
        # Calculate behavior score
        behavior_score = self._calculate_user_behavior_score(features, patterns)
        
        # Determine risk level
        risk_level = self._determine_risk_level(behavior_score)
        
        # Detect anomalies
        anomalies = self._detect_user_anomalies(user_data, features)
        
        # Generate recommendations
        recommendations = self._generate_user_recommendations(features, patterns, anomalies)
        
        return UserBehavior(
            user_id=user_id,
            behavior_score=behavior_score,
            risk_level=risk_level,
            patterns=patterns,
            anomalies=anomalies,
            recommendations=recommendations
        )
    
    def analyze_commit_behavior(self, commit_data: Dict[str, Any]) -> CommitBehavior:
        """Analyze commit behavior patterns."""
        commit_id = commit_data.get('commit_id', 'unknown')
        
        # Extract commit features
        features = self._extract_commit_features(commit_data)
        
        # Detect patterns
        patterns = self._detect_commit_patterns(commit_data, features)
        
        # Calculate behavior score
        behavior_score = self._calculate_commit_behavior_score(features, patterns)
        
        # Determine risk level
        risk_level = self._determine_risk_level(behavior_score)
        
        # Detect suspicious indicators
        suspicious_indicators = self._detect_suspicious_indicators(commit_data, features)
        
        # Generate recommendations
        recommendations = self._generate_commit_recommendations(features, patterns, suspicious_indicators)
        
        return CommitBehavior(
            commit_id=commit_id,
            behavior_score=behavior_score,
            risk_level=risk_level,
            patterns=patterns,
            suspicious_indicators=suspicious_indicators,
            recommendations=recommendations
        )
    
    def _extract_user_features(self, user_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract user behavioral features."""
        features = {}
        
        # Activity patterns
        commits = user_data.get('commits', [])
        features['total_commits'] = len(commits)
        features['avg_commits_per_day'] = self._calculate_avg_commits_per_day(commits)
        features['commit_frequency_variance'] = self._calculate_commit_frequency_variance(commits)
        
        # Time patterns
        features['off_hours_commits'] = self._calculate_off_hours_commits(commits)
        features['weekend_commits'] = self._calculate_weekend_commits(commits)
        features['unusual_time_commits'] = self._calculate_unusual_time_commits(commits)
        
        # File access patterns
        files_accessed = user_data.get('files_accessed', [])
        features['unique_files_accessed'] = len(set(files_accessed))
        features['sensitive_files_accessed'] = self._calculate_sensitive_files_accessed(files_accessed)
        features['file_access_diversity'] = self._calculate_file_access_diversity(files_accessed)
        
        # Code patterns
        code_changes = user_data.get('code_changes', [])
        features['avg_code_changes'] = np.mean([c.get('lines_changed', 0) for c in code_changes]) if code_changes else 0
        features['max_code_changes'] = np.max([c.get('lines_changed', 0) for c in code_changes]) if code_changes else 0
        features['deletion_ratio'] = self._calculate_deletion_ratio(code_changes)
        
        # Communication patterns
        communications = user_data.get('communications', [])
        features['communication_frequency'] = len(communications)
        features['unusual_communication_patterns'] = self._detect_unusual_communication_patterns(communications)
        
        return features
    
    def _extract_commit_features(self, commit_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract commit behavioral features."""
        features = {}
        
        # Basic commit metrics
        features['files_changed'] = len(commit_data.get('files_changed', []))
        features['lines_added'] = commit_data.get('lines_added', 0)
        features['lines_deleted'] = commit_data.get('lines_deleted', 0)
        features['lines_modified'] = commit_data.get('lines_modified', 0)
        
        # Commit message analysis
        message = commit_data.get('message', '')
        features['message_length'] = len(message)
        features['message_complexity'] = self._calculate_message_complexity(message)
        features['security_related_message'] = self._is_security_related(message)
        
        # File type analysis
        files_changed = commit_data.get('files_changed', [])
        features['config_files_changed'] = sum(1 for f in files_changed if self._is_config_file(f))
        features['sensitive_files_changed'] = sum(1 for f in files_changed if self._is_sensitive_file(f))
        features['binary_files_changed'] = sum(1 for f in files_changed if self._is_binary_file(f))
        
        # Timing analysis
        timestamp = commit_data.get('timestamp', 0)
        features['commit_hour'] = datetime.fromtimestamp(timestamp).hour
        features['commit_day_of_week'] = datetime.fromtimestamp(timestamp).weekday()
        features['is_off_hours'] = self._is_off_hours(timestamp)
        features['is_weekend'] = self._is_weekend(timestamp)
        
        # Author analysis
        author = commit_data.get('author', {})
        features['author_commit_count'] = author.get('total_commits', 0)
        features['author_experience_days'] = author.get('experience_days', 0)
        
        return features
    
    def _detect_user_patterns(self, user_data: Dict[str, Any], features: Dict[str, float]) -> List[BehaviorPattern]:
        """Detect user behavior patterns."""
        patterns = []
        
        # Mass file deletion pattern
        if features.get('deletion_ratio', 0) > 0.8:
            pattern = BehaviorPattern(
                pattern_id=f"mass_deletion_{user_data.get('user_id', 'unknown')}",
                pattern_type='mass_file_deletion',
                confidence=0.8,
                severity='HIGH',
                description='User has high file deletion ratio',
                entities=[user_data.get('user_id', 'unknown')],
                timeframe='recent',
                frequency=1,
                context={'deletion_ratio': features.get('deletion_ratio', 0)},
                risk_score=0.8
            )
            patterns.append(pattern)
        
        # Off-hours activity pattern
        if features.get('off_hours_commits', 0) > 0.3:
            pattern = BehaviorPattern(
                pattern_id=f"off_hours_{user_data.get('user_id', 'unknown')}",
                pattern_type='off_hours_activity',
                confidence=0.6,
                severity='MEDIUM',
                description='User has high off-hours activity',
                entities=[user_data.get('user_id', 'unknown')],
                timeframe='recent',
                frequency=1,
                context={'off_hours_ratio': features.get('off_hours_commits', 0)},
                risk_score=0.6
            )
            patterns.append(pattern)
        
        # Sensitive file access pattern
        if features.get('sensitive_files_accessed', 0) > 0:
            pattern = BehaviorPattern(
                pattern_id=f"sensitive_access_{user_data.get('user_id', 'unknown')}",
                pattern_type='sensitive_file_access',
                confidence=0.7,
                severity='HIGH',
                description='User accessed sensitive files',
                entities=[user_data.get('user_id', 'unknown')],
                timeframe='recent',
                frequency=features.get('sensitive_files_accessed', 0),
                context={'sensitive_files_count': features.get('sensitive_files_accessed', 0)},
                risk_score=0.7
            )
            patterns.append(pattern)
        
        return patterns
    
    def _detect_commit_patterns(self, commit_data: Dict[str, Any], features: Dict[str, float]) -> List[BehaviorPattern]:
        """Detect commit behavior patterns."""
        patterns = []
        
        # Large commit pattern
        if features.get('lines_added', 0) + features.get('lines_deleted', 0) > 1000:
            pattern = BehaviorPattern(
                pattern_id=f"large_commit_{commit_data.get('commit_id', 'unknown')}",
                pattern_type='large_commit',
                confidence=0.7,
                severity='MEDIUM',
                description='Large commit detected',
                entities=[commit_data.get('commit_id', 'unknown')],
                timeframe='single_commit',
                frequency=1,
                context={
                    'lines_added': features.get('lines_added', 0),
                    'lines_deleted': features.get('lines_deleted', 0)
                },
                risk_score=0.5
            )
            patterns.append(pattern)
        
        # Unusual commit time pattern
        if features.get('is_off_hours', 0) > 0 and features.get('is_weekend', 0) > 0:
            pattern = BehaviorPattern(
                pattern_id=f"unusual_time_{commit_data.get('commit_id', 'unknown')}",
                pattern_type='unusual_commit_time',
                confidence=0.6,
                severity='MEDIUM',
                description='Commit made during unusual hours',
                entities=[commit_data.get('commit_id', 'unknown')],
                timeframe='single_commit',
                frequency=1,
                context={
                    'commit_hour': features.get('commit_hour', 0),
                    'commit_day_of_week': features.get('commit_day_of_week', 0)
                },
                risk_score=0.4
            )
            patterns.append(pattern)
        
        # Sensitive file modification pattern
        if features.get('sensitive_files_changed', 0) > 0:
            pattern = BehaviorPattern(
                pattern_id=f"sensitive_modification_{commit_data.get('commit_id', 'unknown')}",
                pattern_type='sensitive_file_modification',
                confidence=0.8,
                severity='HIGH',
                description='Sensitive files modified in commit',
                entities=[commit_data.get('commit_id', 'unknown')],
                timeframe='single_commit',
                frequency=features.get('sensitive_files_changed', 0),
                context={'sensitive_files_count': features.get('sensitive_files_changed', 0)},
                risk_score=0.8
            )
            patterns.append(pattern)
        
        return patterns
    
    def _calculate_user_behavior_score(self, features: Dict[str, float], patterns: List[BehaviorPattern]) -> float:
        """Calculate overall user behavior score."""
        base_score = 0.0
        
        # Pattern-based scoring
        for pattern in patterns:
            base_score += pattern.risk_score * pattern.confidence
        
        # Feature-based scoring
        if features.get('off_hours_commits', 0) > 0.3:
            base_score += 0.2
        
        if features.get('sensitive_files_accessed', 0) > 0:
            base_score += 0.3
        
        if features.get('deletion_ratio', 0) > 0.8:
            base_score += 0.4
        
        if features.get('unusual_communication_patterns', 0) > 0:
            base_score += 0.2
        
        return min(1.0, base_score)
    
    def _calculate_commit_behavior_score(self, features: Dict[str, float], patterns: List[BehaviorPattern]) -> float:
        """Calculate overall commit behavior score."""
        base_score = 0.0
        
        # Pattern-based scoring
        for pattern in patterns:
            base_score += pattern.risk_score * pattern.confidence
        
        # Feature-based scoring
        if features.get('sensitive_files_changed', 0) > 0:
            base_score += 0.4
        
        if features.get('is_off_hours', 0) > 0 and features.get('is_weekend', 0) > 0:
            base_score += 0.2
        
        if features.get('lines_added', 0) + features.get('lines_deleted', 0) > 1000:
            base_score += 0.2
        
        if features.get('binary_files_changed', 0) > 0:
            base_score += 0.3
        
        return min(1.0, base_score)
    
    def _determine_risk_level(self, behavior_score: float) -> str:
        """Determine risk level from behavior score."""
        if behavior_score >= 0.8:
            return "CRITICAL"
        elif behavior_score >= 0.6:
            return "HIGH"
        elif behavior_score >= 0.4:
            return "MEDIUM"
        elif behavior_score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _detect_user_anomalies(self, user_data: Dict[str, Any], features: Dict[str, float]) -> List[str]:
        """Detect user behavioral anomalies."""
        anomalies = []
        
        # Compare with baseline
        user_id = user_data.get('user_id', 'unknown')
        baseline = self.user_baselines.get(user_id, {})
        
        if baseline:
            # Unusual commit frequency
            if features.get('avg_commits_per_day', 0) > baseline.get('avg_commits_per_day', 0) * 3:
                anomalies.append("Unusually high commit frequency")
            
            # Unusual file access patterns
            if features.get('unique_files_accessed', 0) > baseline.get('unique_files_accessed', 0) * 2:
                anomalies.append("Unusual file access patterns")
            
            # Unusual time patterns
            if features.get('off_hours_commits', 0) > baseline.get('off_hours_commits', 0) * 2:
                anomalies.append("Unusual off-hours activity")
        
        return anomalies
    
    def _detect_suspicious_indicators(self, commit_data: Dict[str, Any], features: Dict[str, float]) -> List[str]:
        """Detect suspicious indicators in commits."""
        indicators = []
        
        # Obfuscated code indicators
        message = commit_data.get('message', '')
        if len(message) < 10 or 'fix' in message.lower() and len(message) < 20:
            indicators.append("Minimal commit message")
        
        # Binary file modifications
        if features.get('binary_files_changed', 0) > 0:
            indicators.append("Binary file modifications")
        
        # Large deletions
        if features.get('lines_deleted', 0) > 500:
            indicators.append("Large code deletion")
        
        # Sensitive file modifications
        if features.get('sensitive_files_changed', 0) > 0:
            indicators.append("Sensitive file modifications")
        
        # Unusual timing
        if features.get('is_off_hours', 0) > 0 and features.get('is_weekend', 0) > 0:
            indicators.append("Unusual commit timing")
        
        return indicators
    
    def _generate_user_recommendations(self, features: Dict[str, float], patterns: List[BehaviorPattern], anomalies: List[str]) -> List[str]:
        """Generate user behavior recommendations."""
        recommendations = []
        
        if features.get('off_hours_commits', 0) > 0.3:
            recommendations.append("Review off-hours activity patterns")
        
        if features.get('sensitive_files_accessed', 0) > 0:
            recommendations.append("Audit sensitive file access permissions")
        
        if features.get('deletion_ratio', 0) > 0.8:
            recommendations.append("Investigate high file deletion ratio")
        
        if anomalies:
            recommendations.append("Review detected behavioral anomalies")
        
        if not recommendations:
            recommendations.append("Continue monitoring user behavior")
        
        return recommendations
    
    def _generate_commit_recommendations(self, features: Dict[str, float], patterns: List[BehaviorPattern], indicators: List[str]) -> List[str]:
        """Generate commit behavior recommendations."""
        recommendations = []
        
        if features.get('sensitive_files_changed', 0) > 0:
            recommendations.append("Review sensitive file modifications")
        
        if features.get('lines_added', 0) + features.get('lines_deleted', 0) > 1000:
            recommendations.append("Consider breaking large commits into smaller ones")
        
        if features.get('binary_files_changed', 0) > 0:
            recommendations.append("Review binary file modifications")
        
        if indicators:
            recommendations.append("Investigate suspicious commit indicators")
        
        if not recommendations:
            recommendations.append("Continue monitoring commit patterns")
        
        return recommendations
    
    # Helper methods
    def _calculate_avg_commits_per_day(self, commits: List[Dict]) -> float:
        """Calculate average commits per day."""
        if not commits:
            return 0.0
        
        timestamps = [c.get('timestamp', 0) for c in commits]
        if not timestamps:
            return 0.0
        
        min_time = min(timestamps)
        max_time = max(timestamps)
        days = (max_time - min_time) / (24 * 3600) + 1
        
        return len(commits) / days if days > 0 else 0.0
    
    def _calculate_commit_frequency_variance(self, commits: List[Dict]) -> float:
        """Calculate variance in commit frequency."""
        if len(commits) < 2:
            return 0.0
        
        timestamps = sorted([c.get('timestamp', 0) for c in commits])
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        return np.var(intervals) if intervals else 0.0
    
    def _calculate_off_hours_commits(self, commits: List[Dict]) -> float:
        """Calculate ratio of off-hours commits."""
        if not commits:
            return 0.0
        
        off_hours_count = sum(1 for c in commits if self._is_off_hours(c.get('timestamp', 0)))
        return off_hours_count / len(commits)
    
    def _calculate_weekend_commits(self, commits: List[Dict]) -> float:
        """Calculate ratio of weekend commits."""
        if not commits:
            return 0.0
        
        weekend_count = sum(1 for c in commits if self._is_weekend(c.get('timestamp', 0)))
        return weekend_count / len(commits)
    
    def _calculate_unusual_time_commits(self, commits: List[Dict]) -> float:
        """Calculate ratio of unusual time commits."""
        if not commits:
            return 0.0
        
        unusual_count = sum(1 for c in commits if self._is_unusual_time(c.get('timestamp', 0)))
        return unusual_count / len(commits)
    
    def _calculate_sensitive_files_accessed(self, files: List[str]) -> int:
        """Calculate number of sensitive files accessed."""
        sensitive_patterns = ['password', 'secret', 'key', 'token', 'config', 'env']
        return sum(1 for f in files if any(pattern in f.lower() for pattern in sensitive_patterns))
    
    def _calculate_file_access_diversity(self, files: List[str]) -> float:
        """Calculate file access diversity."""
        if not files:
            return 0.0
        
        unique_files = len(set(files))
        total_accesses = len(files)
        
        return unique_files / total_accesses if total_accesses > 0 else 0.0
    
    def _calculate_deletion_ratio(self, code_changes: List[Dict]) -> float:
        """Calculate ratio of deletions to total changes."""
        if not code_changes:
            return 0.0
        
        total_deletions = sum(c.get('lines_deleted', 0) for c in code_changes)
        total_changes = sum(c.get('lines_added', 0) + c.get('lines_deleted', 0) for c in code_changes)
        
        return total_deletions / total_changes if total_changes > 0 else 0.0
    
    def _detect_unusual_communication_patterns(self, communications: List[Dict]) -> int:
        """Detect unusual communication patterns."""
        if not communications:
            return 0
        
        unusual_count = 0
        for comm in communications:
            # Check for unusual patterns
            if comm.get('encrypted', False) and comm.get('size', 0) > 1000:
                unusual_count += 1
            if comm.get('frequency', 0) > 100:  # Very high frequency
                unusual_count += 1
        
        return unusual_count
    
    def _calculate_message_complexity(self, message: str) -> float:
        """Calculate commit message complexity."""
        if not message:
            return 0.0
        
        # Simple complexity based on length and word count
        words = message.split()
        return len(message) / 100.0 + len(words) / 10.0
    
    def _is_security_related(self, text: str) -> float:
        """Check if text is security-related."""
        security_keywords = ['security', 'vulnerability', 'exploit', 'attack', 'breach', 'auth', 'password', 'token']
        text_lower = text.lower()
        return sum(1 for keyword in security_keywords if keyword in text_lower) / len(security_keywords)
    
    def _is_config_file(self, file_path: str) -> bool:
        """Check if file is a configuration file."""
        config_extensions = ['.conf', '.config', '.ini', '.yaml', '.yml', '.json', '.xml', '.properties']
        return any(file_path.endswith(ext) for ext in config_extensions)
    
    def _is_sensitive_file(self, file_path: str) -> bool:
        """Check if file is sensitive."""
        sensitive_patterns = ['password', 'secret', 'key', 'token', 'config', 'env', 'credential']
        return any(pattern in file_path.lower() for pattern in sensitive_patterns)
    
    def _is_binary_file(self, file_path: str) -> bool:
        """Check if file is binary."""
        binary_extensions = ['.exe', '.dll', '.so', '.dylib', '.bin', '.img', '.iso']
        return any(file_path.endswith(ext) for ext in binary_extensions)
    
    def _is_off_hours(self, timestamp: float) -> bool:
        """Check if timestamp is during off-hours."""
        dt = datetime.fromtimestamp(timestamp)
        hour = dt.hour
        return hour < 6 or hour > 22
    
    def _is_weekend(self, timestamp: float) -> bool:
        """Check if timestamp is during weekend."""
        dt = datetime.fromtimestamp(timestamp)
        return dt.weekday() >= 5  # Saturday = 5, Sunday = 6
    
    def _is_unusual_time(self, timestamp: float) -> bool:
        """Check if timestamp is during unusual hours."""
        return self._is_off_hours(timestamp) and self._is_weekend(timestamp)
    
    def train_models(self, training_data: List[Dict[str, Any]]):
        """Train behavioral analysis models."""
        if not training_data:
            return
        
        # Extract user features
        user_features = []
        for data in training_data:
            features = self._extract_user_features(data)
            if features:
                user_features.append(list(features.values()))
        
        if user_features:
            X_user = np.array(user_features)
            X_user_scaled = self.scaler.fit_transform(X_user)
            self.user_clusterer.fit(X_user_scaled)
        
        # Extract commit features
        commit_features = []
        for data in training_data:
            commits = data.get('commits', [])
            for commit in commits:
                features = self._extract_commit_features(commit)
                if features:
                    commit_features.append(list(features.values()))
        
        if commit_features:
            X_commit = np.array(commit_features)
            X_commit_scaled = self.scaler.transform(X_commit)
            self.commit_clusterer.fit(X_commit_scaled)
        
        # Calculate baselines
        self._calculate_baselines(training_data)
        
        # Save models
        self._save_models()
    
    def _calculate_baselines(self, training_data: List[Dict[str, Any]]):
        """Calculate behavioral baselines."""
        for data in training_data:
            user_id = data.get('user_id', 'unknown')
            if user_id != 'unknown':
                features = self._extract_user_features(data)
                if features:
                    self.user_baselines[user_id] = features
