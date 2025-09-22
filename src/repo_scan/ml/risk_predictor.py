"""
Risk Prediction using Machine Learning.

This module implements ML-based risk prediction models to forecast
potential security vulnerabilities and assess risk levels.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional, Union
from dataclasses import dataclass
from pathlib import Path
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.linear_model import LinearRegression, Ridge
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import mean_squared_error, r2_score, mean_absolute_error
import joblib
import json
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')


@dataclass
class RiskPrediction:
    """Represents a risk prediction result."""
    prediction_id: str
    risk_score: float
    confidence: float
    risk_level: str
    factors: Dict[str, float]
    recommendations: List[str]
    timeframe: str
    timestamp: datetime


@dataclass
class VulnerabilityForecast:
    """Represents a vulnerability forecast."""
    forecast_id: str
    vulnerability_type: str
    probability: float
    severity: str
    timeframe: str
    affected_components: List[str]
    mitigation_strategies: List[str]


class RiskPredictor:
    """
    Advanced risk prediction system using multiple ML algorithms.
    
    Predicts:
    - Overall security risk scores
    - Vulnerability probabilities
    - Attack surface evolution
    - Compliance risk levels
    - Incident likelihood
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the risk predictor."""
        self.model_path = model_path or "models/risk_predictor.joblib"
        
        # Multiple prediction models
        self.risk_models = {
            'random_forest': RandomForestRegressor(
                n_estimators=100,
                max_depth=10,
                random_state=42
            ),
            'gradient_boosting': GradientBoostingRegressor(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42
            ),
            'neural_network': MLPRegressor(
                hidden_layer_sizes=(100, 50),
                max_iter=500,
                random_state=42
            ),
            'linear_regression': Ridge(alpha=1.0)
        }
        
        # Preprocessing
        self.scaler = StandardScaler()
        self.label_encoders = {}
        
        # Feature importance tracking
        self.feature_importance = {}
        self.model_performance = {}
        
        # Historical data for trend analysis
        self.historical_data = []
        
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models if available."""
        try:
            if Path(self.model_path).exists():
                models = joblib.load(self.model_path)
                self.risk_models = models.get('risk_models', self.risk_models)
                self.scaler = models.get('scaler', self.scaler)
                self.label_encoders = models.get('label_encoders', {})
                self.feature_importance = models.get('feature_importance', {})
                self.model_performance = models.get('model_performance', {})
                self.historical_data = models.get('historical_data', [])
        except Exception as e:
            print(f"Warning: Could not load models: {e}")
    
    def _save_models(self):
        """Save trained models."""
        try:
            Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
            models = {
                'risk_models': self.risk_models,
                'scaler': self.scaler,
                'label_encoders': self.label_encoders,
                'feature_importance': self.feature_importance,
                'model_performance': self.model_performance,
                'historical_data': self.historical_data
            }
            joblib.dump(models, self.model_path)
        except Exception as e:
            print(f"Warning: Could not save models: {e}")
    
    def extract_risk_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features relevant for risk prediction."""
        features = {}
        
        # Code complexity features
        features.update(self._extract_complexity_features(repo_data))
        
        # Security features
        features.update(self._extract_security_features(repo_data))
        
        # Dependency features
        features.update(self._extract_dependency_features(repo_data))
        
        # Historical features
        features.update(self._extract_historical_features(repo_data))
        
        # External factors
        features.update(self._extract_external_features(repo_data))
        
        return features
    
    def _extract_complexity_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract code complexity features."""
        features = {}
        
        files = repo_data.get('files', [])
        if not files:
            return features
        
        # Cyclomatic complexity
        complexities = []
        for file_data in files:
            content = file_data.get('content', '')
            complexity = self._calculate_cyclomatic_complexity(content)
            complexities.append(complexity)
        
        features['avg_complexity'] = np.mean(complexities) if complexities else 0
        features['max_complexity'] = np.max(complexities) if complexities else 0
        features['high_complexity_files'] = sum(1 for c in complexities if c > 10)
        
        # Code size metrics
        total_lines = sum(f.get('lines', 0) for f in files)
        features['total_lines'] = total_lines
        features['avg_lines_per_file'] = total_lines / len(files) if files else 0
        features['large_files'] = sum(1 for f in files if f.get('lines', 0) > 1000)
        
        # Function/class density
        total_functions = sum(f.get('functions', 0) for f in files)
        total_classes = sum(f.get('classes', 0) for f in files)
        features['function_density'] = total_functions / total_lines if total_lines > 0 else 0
        features['class_density'] = total_classes / total_lines if total_lines > 0 else 0
        
        return features
    
    def _extract_security_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract security-related features."""
        features = {}
        
        # Vulnerability counts
        vulnerabilities = repo_data.get('vulnerabilities', [])
        features['total_vulnerabilities'] = len(vulnerabilities)
        features['critical_vulnerabilities'] = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL')
        features['high_vulnerabilities'] = sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH')
        features['medium_vulnerabilities'] = sum(1 for v in vulnerabilities if v.get('severity') == 'MEDIUM')
        features['low_vulnerabilities'] = sum(1 for v in vulnerabilities if v.get('severity') == 'LOW')
        
        # Security patterns
        security_patterns = repo_data.get('security_patterns', [])
        features['security_patterns'] = len(security_patterns)
        features['suspicious_patterns'] = sum(1 for p in security_patterns if p.get('suspicious', False))
        
        # Authentication/authorization
        auth_features = repo_data.get('authentication', {})
        features['has_authentication'] = 1 if auth_features.get('implemented', False) else 0
        features['weak_auth'] = 1 if auth_features.get('weak', False) else 0
        features['missing_auth'] = 1 if auth_features.get('missing', False) else 0
        
        # Encryption
        encryption_features = repo_data.get('encryption', {})
        features['has_encryption'] = 1 if encryption_features.get('implemented', False) else 0
        features['weak_encryption'] = 1 if encryption_features.get('weak', False) else 0
        features['missing_encryption'] = 1 if encryption_features.get('missing', False) else 0
        
        return features
    
    def _extract_dependency_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract dependency-related features."""
        features = {}
        
        dependencies = repo_data.get('dependencies', [])
        features['total_dependencies'] = len(dependencies)
        features['vulnerable_dependencies'] = sum(1 for d in dependencies if d.get('vulnerable', False))
        features['outdated_dependencies'] = sum(1 for d in dependencies if d.get('outdated', False))
        features['unmaintained_dependencies'] = sum(1 for d in dependencies if d.get('unmaintained', False))
        
        # Dependency depth
        max_depth = 0
        for dep in dependencies:
            depth = dep.get('depth', 0)
            max_depth = max(max_depth, depth)
        features['max_dependency_depth'] = max_depth
        
        # External dependencies ratio
        external_deps = sum(1 for d in dependencies if d.get('external', True))
        features['external_dependency_ratio'] = external_deps / len(dependencies) if dependencies else 0
        
        return features
    
    def _extract_historical_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract historical trend features."""
        features = {}
        
        # Commit history
        commits = repo_data.get('commits', [])
        if commits:
            # Recent activity
            recent_commits = [c for c in commits if self._is_recent(c.get('timestamp', 0))]
            features['recent_commits'] = len(recent_commits)
            features['commit_frequency'] = len(commits) / 30  # commits per day over 30 days
            
            # Author diversity
            authors = set(c.get('author', '') for c in commits)
            features['author_diversity'] = len(authors)
            
            # Security-related commits
            security_commits = sum(1 for c in commits if self._is_security_related(c.get('message', '')))
            features['security_commits'] = security_commits
            features['security_commit_ratio'] = security_commits / len(commits) if commits else 0
        
        # Issue history
        issues = repo_data.get('issues', [])
        if issues:
            security_issues = sum(1 for i in issues if self._is_security_related(i.get('title', '')))
            features['security_issues'] = security_issues
            features['open_security_issues'] = sum(1 for i in issues if i.get('state') == 'open' and self._is_security_related(i.get('title', '')))
        
        return features
    
    def _extract_external_features(self, repo_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract external environment features."""
        features = {}
        
        # Threat intelligence
        threat_data = repo_data.get('threat_intelligence', {})
        features['threat_level'] = threat_data.get('level', 0)
        features['active_threats'] = threat_data.get('active_threats', 0)
        features['emerging_threats'] = threat_data.get('emerging_threats', 0)
        
        # Compliance requirements
        compliance = repo_data.get('compliance', {})
        features['compliance_requirements'] = len(compliance.get('requirements', []))
        features['compliance_violations'] = len(compliance.get('violations', []))
        
        # External dependencies risk
        external_risk = repo_data.get('external_risk', {})
        features['supply_chain_risk'] = external_risk.get('supply_chain', 0)
        features['third_party_risk'] = external_risk.get('third_party', 0)
        
        return features
    
    def _calculate_cyclomatic_complexity(self, content: str) -> int:
        """Calculate cyclomatic complexity of code."""
        complexity_keywords = [
            'if', 'elif', 'else', 'for', 'while', 'try', 'except', 'with',
            'and', 'or', 'case', 'default', 'catch', 'finally'
        ]
        
        complexity = 1  # Base complexity
        for keyword in complexity_keywords:
            complexity += len(re.findall(rf'\b{keyword}\b', content))
        
        return complexity
    
    def _is_recent(self, timestamp: Union[int, float]) -> bool:
        """Check if timestamp is within last 30 days."""
        if isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(timestamp)
            return (datetime.now() - dt).days <= 30
        return False
    
    def _is_security_related(self, text: str) -> bool:
        """Check if text is security-related."""
        security_keywords = [
            'security', 'vulnerability', 'exploit', 'attack', 'breach',
            'auth', 'password', 'token', 'encrypt', 'decrypt', 'hash',
            'injection', 'xss', 'csrf', 'sql', 'buffer', 'overflow'
        ]
        
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in security_keywords)
    
    def predict_risk_score(self, repo_data: Dict[str, Any]) -> RiskPrediction:
        """Predict overall security risk score."""
        features = self.extract_risk_features(repo_data)
        if not features:
            return self._create_default_prediction()
        
        # Prepare features for prediction
        feature_values = list(features.values())
        X = np.array([feature_values])
        X_scaled = self.scaler.transform(X)
        
        # Get predictions from all models
        predictions = {}
        for model_name, model in self.risk_models.items():
            try:
                pred = model.predict(X_scaled)[0]
                predictions[model_name] = pred
            except Exception as e:
                print(f"Warning: {model_name} prediction failed: {e}")
                predictions[model_name] = 0.5  # Default value
        
        # Ensemble prediction (weighted average)
        weights = self._get_model_weights()
        ensemble_prediction = sum(predictions[model] * weights.get(model, 0.25) for model in predictions)
        
        # Calculate confidence based on model agreement
        prediction_std = np.std(list(predictions.values()))
        confidence = max(0.0, 1.0 - prediction_std)
        
        # Determine risk level
        risk_level = self._determine_risk_level(ensemble_prediction)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(features, ensemble_prediction)
        
        return RiskPrediction(
            prediction_id=f"risk_{datetime.now().timestamp()}",
            risk_score=ensemble_prediction,
            confidence=confidence,
            risk_level=risk_level,
            factors=self._get_top_factors(features),
            recommendations=recommendations,
            timeframe="30 days",
            timestamp=datetime.now()
        )
    
    def _create_default_prediction(self) -> RiskPrediction:
        """Create a default prediction when features are unavailable."""
        return RiskPrediction(
            prediction_id=f"risk_{datetime.now().timestamp()}",
            risk_score=0.5,
            confidence=0.0,
            risk_level="UNKNOWN",
            factors={},
            recommendations=["Unable to analyze - insufficient data"],
            timeframe="30 days",
            timestamp=datetime.now()
        )
    
    def _get_model_weights(self) -> Dict[str, float]:
        """Get model weights based on performance."""
        if not self.model_performance:
            return {model: 0.25 for model in self.risk_models.keys()}
        
        # Weight models by their R² score
        total_performance = sum(self.model_performance.values())
        if total_performance == 0:
            return {model: 0.25 for model in self.risk_models.keys()}
        
        weights = {}
        for model, performance in self.model_performance.items():
            weights[model] = performance / total_performance
        
        return weights
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level from score."""
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        elif risk_score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _generate_recommendations(self, features: Dict[str, float], risk_score: float) -> List[str]:
        """Generate risk mitigation recommendations."""
        recommendations = []
        
        # High complexity recommendations
        if features.get('avg_complexity', 0) > 10:
            recommendations.append("Reduce code complexity by refactoring complex functions")
        
        if features.get('high_complexity_files', 0) > 0:
            recommendations.append("Break down large, complex files into smaller modules")
        
        # Security recommendations
        if features.get('critical_vulnerabilities', 0) > 0:
            recommendations.append("Address critical vulnerabilities immediately")
        
        if features.get('missing_auth', 0) > 0:
            recommendations.append("Implement proper authentication mechanisms")
        
        if features.get('missing_encryption', 0) > 0:
            recommendations.append("Implement encryption for sensitive data")
        
        # Dependency recommendations
        if features.get('vulnerable_dependencies', 0) > 0:
            recommendations.append("Update vulnerable dependencies")
        
        if features.get('outdated_dependencies', 0) > 0:
            recommendations.append("Update outdated dependencies to latest versions")
        
        # General recommendations based on risk score
        if risk_score > 0.7:
            recommendations.append("Conduct comprehensive security audit")
            recommendations.append("Implement additional security monitoring")
        
        if risk_score > 0.5:
            recommendations.append("Increase security testing frequency")
            recommendations.append("Review and update security policies")
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def _get_top_factors(self, features: Dict[str, float]) -> Dict[str, float]:
        """Get top contributing factors to risk score."""
        # Sort features by absolute value (importance)
        sorted_features = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)
        
        # Return top 5 factors
        return dict(sorted_features[:5])
    
    def forecast_vulnerabilities(self, repo_data: Dict[str, Any], timeframe: str = "30 days") -> List[VulnerabilityForecast]:
        """Forecast potential vulnerabilities."""
        forecasts = []
        
        features = self.extract_risk_features(repo_data)
        if not features:
            return forecasts
        
        # Vulnerability type probabilities
        vuln_types = [
            'sql_injection', 'xss', 'csrf', 'path_traversal',
            'authentication_bypass', 'privilege_escalation',
            'data_exposure', 'insecure_deserialization'
        ]
        
        for vuln_type in vuln_types:
            # Calculate probability based on features
            probability = self._calculate_vulnerability_probability(vuln_type, features)
            
            if probability > 0.3:  # Only forecast if probability > 30%
                severity = self._determine_vulnerability_severity(vuln_type, probability)
                affected_components = self._identify_affected_components(vuln_type, repo_data)
                mitigation_strategies = self._get_mitigation_strategies(vuln_type)
                
                forecast = VulnerabilityForecast(
                    forecast_id=f"forecast_{vuln_type}_{datetime.now().timestamp()}",
                    vulnerability_type=vuln_type,
                    probability=probability,
                    severity=severity,
                    timeframe=timeframe,
                    affected_components=affected_components,
                    mitigation_strategies=mitigation_strategies
                )
                forecasts.append(forecast)
        
        return forecasts
    
    def _calculate_vulnerability_probability(self, vuln_type: str, features: Dict[str, float]) -> float:
        """Calculate probability of specific vulnerability type."""
        # Base probability
        base_probabilities = {
            'sql_injection': 0.1,
            'xss': 0.15,
            'csrf': 0.05,
            'path_traversal': 0.08,
            'authentication_bypass': 0.12,
            'privilege_escalation': 0.06,
            'data_exposure': 0.2,
            'insecure_deserialization': 0.03
        }
        
        base_prob = base_probabilities.get(vuln_type, 0.1)
        
        # Adjust based on features
        adjustments = 0.0
        
        # Complexity increases risk
        if features.get('avg_complexity', 0) > 10:
            adjustments += 0.1
        
        # Missing security controls
        if features.get('missing_auth', 0) > 0:
            adjustments += 0.15
        
        if features.get('missing_encryption', 0) > 0:
            adjustments += 0.1
        
        # Vulnerable dependencies
        if features.get('vulnerable_dependencies', 0) > 0:
            adjustments += 0.2
        
        # Recent security issues
        if features.get('open_security_issues', 0) > 0:
            adjustments += 0.1
        
        return min(1.0, base_prob + adjustments)
    
    def _determine_vulnerability_severity(self, vuln_type: str, probability: float) -> str:
        """Determine vulnerability severity."""
        if probability > 0.8:
            return "CRITICAL"
        elif probability > 0.6:
            return "HIGH"
        elif probability > 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _identify_affected_components(self, vuln_type: str, repo_data: Dict[str, Any]) -> List[str]:
        """Identify components likely to be affected by vulnerability type."""
        components = []
        
        files = repo_data.get('files', [])
        for file_data in files:
            file_path = file_data.get('path', '')
            content = file_data.get('content', '')
            
            # Check for vulnerability-specific patterns
            if vuln_type == 'sql_injection' and any(keyword in content.lower() for keyword in ['select', 'insert', 'update', 'delete']):
                components.append(file_path)
            elif vuln_type == 'xss' and any(keyword in content.lower() for keyword in ['innerhtml', 'document.write', 'eval']):
                components.append(file_path)
            elif vuln_type == 'authentication_bypass' and any(keyword in content.lower() for keyword in ['auth', 'login', 'password']):
                components.append(file_path)
        
        return components[:5]  # Limit to top 5 components
    
    def _get_mitigation_strategies(self, vuln_type: str) -> List[str]:
        """Get mitigation strategies for vulnerability type."""
        strategies = {
            'sql_injection': [
                "Use parameterized queries",
                "Implement input validation",
                "Use ORM with built-in protection"
            ],
            'xss': [
                "Sanitize user input",
                "Use proper output encoding",
                "Implement Content Security Policy"
            ],
            'csrf': [
                "Implement CSRF tokens",
                "Use SameSite cookies",
                "Validate referer headers"
            ],
            'path_traversal': [
                "Validate file paths",
                "Use whitelist of allowed paths",
                "Implement proper access controls"
            ],
            'authentication_bypass': [
                "Implement strong authentication",
                "Use multi-factor authentication",
                "Regular security audits"
            ],
            'privilege_escalation': [
                "Implement principle of least privilege",
                "Regular access reviews",
                "Monitor privilege changes"
            ],
            'data_exposure': [
                "Implement data encryption",
                "Use secure data storage",
                "Regular data access audits"
            ],
            'insecure_deserialization': [
                "Avoid deserializing untrusted data",
                "Use safe serialization formats",
                "Implement input validation"
            ]
        }
        
        return strategies.get(vuln_type, ["Implement general security best practices"])
    
    def train_models(self, training_data: List[Dict[str, Any]]):
        """Train risk prediction models on historical data."""
        if not training_data:
            return
        
        # Prepare training data
        X = []
        y = []
        
        for data in training_data:
            features = self.extract_risk_features(data)
            if features:
                X.append(list(features.values()))
                y.append(data.get('actual_risk_score', 0.5))  # Ground truth risk score
        
        if not X:
            return
        
        # Convert to numpy arrays
        X = np.array(X)
        y = np.array(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train models
        for model_name, model in self.risk_models.items():
            try:
                model.fit(X_train_scaled, y_train)
                
                # Evaluate model
                y_pred = model.predict(X_test_scaled)
                mse = mean_squared_error(y_test, y_pred)
                r2 = r2_score(y_test, y_pred)
                mae = mean_absolute_error(y_test, y_pred)
                
                self.model_performance[model_name] = r2
                
                # Feature importance (for tree-based models)
                if hasattr(model, 'feature_importances_'):
                    self.feature_importance[model_name] = model.feature_importances_.tolist()
                
                print(f"{model_name} - MSE: {mse:.4f}, R²: {r2:.4f}, MAE: {mae:.4f}")
                
            except Exception as e:
                print(f"Error training {model_name}: {e}")
        
        # Save models
        self._save_models()
    
    def update_models(self, new_data: Dict[str, Any]):
        """Update models with new data (online learning)."""
        features = self.extract_risk_features(new_data)
        if not features:
            return
        
        # Add to historical data
        self.historical_data.append({
            'features': features,
            'timestamp': datetime.now().timestamp(),
            'actual_risk_score': new_data.get('actual_risk_score', 0.5)
        })
        
        # Keep only recent data (last 1000 samples)
        if len(self.historical_data) > 1000:
            self.historical_data = self.historical_data[-1000:]
        
        # Retrain models periodically
        if len(self.historical_data) % 100 == 0:
            self.train_models(self.historical_data)
