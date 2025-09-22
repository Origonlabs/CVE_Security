"""
Pattern Detection using Machine Learning.

This module implements ML-based pattern detection for security vulnerabilities,
code smells, and suspicious patterns in repositories.
"""

import re
import json
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib


@dataclass
class SecurityPattern:
    """Represents a detected security pattern."""
    pattern_id: str
    pattern_type: str
    confidence: float
    severity: str
    description: str
    code_snippet: str
    file_path: str
    line_number: int
    context: Dict[str, Any]
    remediation: str


class PatternDetector:
    """
    Machine Learning-based pattern detector for security vulnerabilities.
    
    Uses various ML techniques to identify patterns that might indicate
    security issues, code smells, or suspicious behavior.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the pattern detector."""
        self.model_path = model_path or "models/pattern_detector.joblib"
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 3)
        )
        self.clusterer = DBSCAN(eps=0.5, min_samples=2)
        self.anomaly_detector = IsolationForest(contamination=0.1)
        self.scaler = StandardScaler()
        
        # Security pattern templates
        self.security_patterns = {
            'sql_injection': {
                'patterns': [
                    r'SELECT.*\+.*WHERE',
                    r'INSERT.*\+.*VALUES',
                    r'UPDATE.*\+.*SET',
                    r'DELETE.*\+.*WHERE',
                    r'EXEC.*\+.*',
                    r'EXECUTE.*\+.*'
                ],
                'severity': 'HIGH',
                'description': 'Potential SQL injection vulnerability'
            },
            'xss': {
                'patterns': [
                    r'innerHTML\s*=',
                    r'document\.write\s*\(',
                    r'eval\s*\(',
                    r'setTimeout\s*\(.*eval',
                    r'setInterval\s*\(.*eval'
                ],
                'severity': 'HIGH',
                'description': 'Potential XSS vulnerability'
            },
            'path_traversal': {
                'patterns': [
                    r'\.\./',
                    r'\.\.\\',
                    r'%2e%2e%2f',
                    r'%2e%2e%5c',
                    r'\.\.%2f',
                    r'\.\.%5c'
                ],
                'severity': 'MEDIUM',
                'description': 'Potential path traversal vulnerability'
            },
            'hardcoded_secrets': {
                'patterns': [
                    r'password\s*=\s*["\'][^"\']+["\']',
                    r'api_key\s*=\s*["\'][^"\']+["\']',
                    r'secret\s*=\s*["\'][^"\']+["\']',
                    r'token\s*=\s*["\'][^"\']+["\']',
                    r'private_key\s*=\s*["\'][^"\']+["\']'
                ],
                'severity': 'CRITICAL',
                'description': 'Hardcoded secret detected'
            },
            'weak_crypto': {
                'patterns': [
                    r'MD5\s*\(',
                    r'SHA1\s*\(',
                    r'DES\s*\(',
                    r'RC4\s*\(',
                    r'random\s*\(\s*\)',
                    r'Math\.random\s*\('
                ],
                'severity': 'MEDIUM',
                'description': 'Weak cryptographic function detected'
            },
            'insecure_redirect': {
                'patterns': [
                    r'redirect\s*\(.*request\.',
                    r'response\.sendRedirect\s*\(.*request\.',
                    r'window\.location\s*=.*request\.',
                    r'location\.href\s*=.*request\.'
                ],
                'severity': 'MEDIUM',
                'description': 'Insecure redirect detected'
            }
        }
        
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models if available."""
        try:
            if Path(self.model_path).exists():
                models = joblib.load(self.model_path)
                self.vectorizer = models.get('vectorizer', self.vectorizer)
                self.clusterer = models.get('clusterer', self.clusterer)
                self.anomaly_detector = models.get('anomaly_detector', self.anomaly_detector)
                self.scaler = models.get('scaler', self.scaler)
        except Exception as e:
            print(f"Warning: Could not load models: {e}")
    
    def _save_models(self):
        """Save trained models."""
        try:
            Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
            models = {
                'vectorizer': self.vectorizer,
                'clusterer': self.clusterer,
                'anomaly_detector': self.anomaly_detector,
                'scaler': self.scaler
            }
            joblib.dump(models, self.model_path)
        except Exception as e:
            print(f"Warning: Could not save models: {e}")
    
    def extract_code_features(self, code_content: str) -> Dict[str, Any]:
        """Extract features from code content."""
        features = {}
        
        # Basic metrics
        features['lines_of_code'] = len(code_content.split('\n'))
        features['char_count'] = len(code_content)
        features['comment_ratio'] = self._calculate_comment_ratio(code_content)
        features['complexity'] = self._calculate_complexity(code_content)
        
        # Security-related features
        features['has_imports'] = bool(re.search(r'import\s+', code_content))
        features['has_functions'] = bool(re.search(r'def\s+\w+', code_content))
        features['has_classes'] = bool(re.search(r'class\s+\w+', code_content))
        features['has_try_catch'] = bool(re.search(r'try\s*:', code_content))
        features['has_async'] = bool(re.search(r'async\s+', code_content))
        
        # Security patterns
        for pattern_name, pattern_info in self.security_patterns.items():
            pattern_count = 0
            for pattern in pattern_info['patterns']:
                pattern_count += len(re.findall(pattern, code_content, re.IGNORECASE))
            features[f'{pattern_name}_count'] = pattern_count
        
        return features
    
    def _calculate_comment_ratio(self, code_content: str) -> float:
        """Calculate the ratio of comments to code."""
        lines = code_content.split('\n')
        comment_lines = sum(1 for line in lines if line.strip().startswith('#') or line.strip().startswith('//'))
        return comment_lines / len(lines) if lines else 0
    
    def _calculate_complexity(self, code_content: str) -> int:
        """Calculate cyclomatic complexity."""
        complexity_keywords = ['if', 'elif', 'else', 'for', 'while', 'try', 'except', 'with', 'and', 'or']
        complexity = 1  # Base complexity
        
        for keyword in complexity_keywords:
            complexity += len(re.findall(rf'\b{keyword}\b', code_content))
        
        return complexity
    
    def detect_patterns(self, file_path: str, code_content: str) -> List[SecurityPattern]:
        """Detect security patterns in code content."""
        patterns = []
        
        for pattern_name, pattern_info in self.security_patterns.items():
            for pattern in pattern_info['patterns']:
                matches = re.finditer(pattern, code_content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    # Calculate confidence based on context
                    confidence = self._calculate_confidence(match, code_content, pattern_name)
                    
                    if confidence > 0.3:  # Threshold for reporting
                        line_number = code_content[:match.start()].count('\n') + 1
                        
                        pattern_obj = SecurityPattern(
                            pattern_id=f"{pattern_name}_{match.start()}",
                            pattern_type=pattern_name,
                            confidence=confidence,
                            severity=pattern_info['severity'],
                            description=pattern_info['description'],
                            code_snippet=match.group(),
                            file_path=file_path,
                            line_number=line_number,
                            context=self._extract_context(match, code_content),
                            remediation=self._get_remediation(pattern_name)
                        )
                        patterns.append(pattern_obj)
        
        return patterns
    
    def _calculate_confidence(self, match, code_content: str, pattern_type: str) -> float:
        """Calculate confidence score for a pattern match."""
        confidence = 0.5  # Base confidence
        
        # Context-based adjustments
        context_start = max(0, match.start() - 100)
        context_end = min(len(code_content), match.end() + 100)
        context = code_content[context_start:context_end]
        
        # Positive indicators
        if 'password' in context.lower():
            confidence += 0.2
        if 'user' in context.lower():
            confidence += 0.1
        if 'input' in context.lower():
            confidence += 0.1
        if 'request' in context.lower():
            confidence += 0.1
        
        # Negative indicators
        if 'test' in context.lower():
            confidence -= 0.1
        if 'example' in context.lower():
            confidence -= 0.1
        if 'TODO' in context:
            confidence -= 0.1
        
        return max(0.0, min(1.0, confidence))
    
    def _extract_context(self, match, code_content: str) -> Dict[str, Any]:
        """Extract context around a pattern match."""
        context_start = max(0, match.start() - 200)
        context_end = min(len(code_content), match.end() + 200)
        context = code_content[context_start:context_end]
        
        return {
            'before': code_content[context_start:match.start()],
            'after': code_content[match.end():context_end],
            'full_context': context,
            'line_context': self._get_line_context(match, code_content)
        }
    
    def _get_line_context(self, match, code_content: str) -> List[str]:
        """Get the lines around a match."""
        lines = code_content.split('\n')
        match_line = code_content[:match.start()].count('\n')
        
        start_line = max(0, match_line - 3)
        end_line = min(len(lines), match_line + 4)
        
        return lines[start_line:end_line]
    
    def _get_remediation(self, pattern_type: str) -> str:
        """Get remediation advice for a pattern type."""
        remediations = {
            'sql_injection': 'Use parameterized queries or prepared statements',
            'xss': 'Sanitize user input and use proper output encoding',
            'path_traversal': 'Validate and sanitize file paths',
            'hardcoded_secrets': 'Use environment variables or secure secret management',
            'weak_crypto': 'Use strong cryptographic functions (SHA-256, AES-256)',
            'insecure_redirect': 'Validate redirect URLs against whitelist'
        }
        return remediations.get(pattern_type, 'Review and fix the identified security issue')
    
    def train_models(self, training_data: List[Dict[str, Any]]):
        """Train ML models on historical data."""
        if not training_data:
            return
        
        # Extract features
        features = []
        labels = []
        
        for item in training_data:
            code_features = self.extract_code_features(item.get('code', ''))
            features.append(list(code_features.values()))
            labels.append(item.get('is_vulnerable', 0))
        
        if not features:
            return
        
        # Train models
        X = np.array(features)
        y = np.array(labels)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train anomaly detector
        self.anomaly_detector.fit(X_scaled)
        
        # Train clusterer
        self.clusterer.fit(X_scaled)
        
        # Save models
        self._save_models()
    
    def predict_anomalies(self, code_content: str) -> Tuple[bool, float]:
        """Predict if code contains anomalies."""
        features = self.extract_code_features(code_content)
        X = np.array([list(features.values())])
        X_scaled = self.scaler.transform(X)
        
        prediction = self.anomaly_detector.predict(X_scaled)[0]
        score = self.anomaly_detector.score_samples(X_scaled)[0]
        
        is_anomaly = prediction == -1
        confidence = abs(score)
        
        return is_anomaly, confidence
    
    def cluster_similar_patterns(self, patterns: List[SecurityPattern]) -> Dict[int, List[SecurityPattern]]:
        """Cluster similar security patterns."""
        if not patterns:
            return {}
        
        # Extract features from patterns
        features = []
        for pattern in patterns:
            pattern_features = self.extract_code_features(pattern.code_snippet)
            features.append(list(pattern_features.values()))
        
        if not features:
            return {}
        
        # Cluster patterns
        X = np.array(features)
        X_scaled = self.scaler.transform(X)
        clusters = self.clusterer.fit_predict(X_scaled)
        
        # Group patterns by cluster
        clustered_patterns = {}
        for i, cluster_id in enumerate(clusters):
            if cluster_id not in clustered_patterns:
                clustered_patterns[cluster_id] = []
            clustered_patterns[cluster_id].append(patterns[i])
        
        return clustered_patterns
