"""
Dynamic Scoring System.

This module implements a dynamic scoring system that adapts to:
- Threat landscape changes
- Historical data patterns
- Contextual factors
- Risk evolution
- Business impact
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional, Callable
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict, deque
import json
import math
from datetime import datetime, timedelta
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error
import joblib


@dataclass
class ScoringContext:
    """Represents the context for scoring."""
    timestamp: datetime
    threat_level: str
    business_impact: str
    compliance_requirements: List[str]
    historical_data: Dict[str, Any]
    external_factors: Dict[str, Any]


@dataclass
class DynamicScore:
    """Represents a dynamic score."""
    score_id: str
    base_score: float
    adjusted_score: float
    confidence: float
    factors: Dict[str, float]
    context: ScoringContext
    timestamp: datetime
    explanation: str


@dataclass
class ScoringRule:
    """Represents a scoring rule."""
    rule_id: str
    name: str
    condition: Callable[[Dict[str, Any]], bool]
    adjustment: Callable[[float, Dict[str, Any]], float]
    weight: float
    description: str


class DynamicScorer:
    """
    Advanced dynamic scoring system.
    
    Features:
    - Adaptive scoring based on threat landscape
    - Historical pattern analysis
    - Contextual adjustments
    - Machine learning-based predictions
    - Real-time score updates
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the dynamic scorer."""
        self.model_path = model_path or "models/dynamic_scorer.joblib"
        self.scoring_rules = []
        self.historical_scores = deque(maxlen=1000)
        self.threat_landscape_data = {}
        self.business_context = {}
        
        # ML models for prediction
        self.score_predictor = LinearRegression()
        self.scaler = StandardScaler()
        
        # Scoring weights
        self.base_weights = {
            'severity': 0.4,
            'exploitability': 0.3,
            'impact': 0.2,
            'context': 0.1
        }
        
        # Dynamic adjustment factors
        self.adjustment_factors = {
            'threat_level': {'HIGH': 1.2, 'MEDIUM': 1.0, 'LOW': 0.8},
            'business_impact': {'CRITICAL': 1.3, 'HIGH': 1.1, 'MEDIUM': 1.0, 'LOW': 0.9},
            'compliance': {'REQUIRED': 1.2, 'RECOMMENDED': 1.0, 'OPTIONAL': 0.8},
            'time_factor': {'recent': 1.1, 'moderate': 1.0, 'old': 0.9}
        }
        
        self._load_models()
        self._initialize_scoring_rules()
    
    def _load_models(self):
        """Load pre-trained models."""
        try:
            if Path(self.model_path).exists():
                models = joblib.load(self.model_path)
                self.score_predictor = models.get('score_predictor', self.score_predictor)
                self.scaler = models.get('scaler', self.scaler)
                self.historical_scores = models.get('historical_scores', self.historical_scores)
                self.threat_landscape_data = models.get('threat_landscape_data', {})
                self.business_context = models.get('business_context', {})
        except Exception as e:
            print(f"Warning: Could not load models: {e}")
    
    def _save_models(self):
        """Save trained models."""
        try:
            Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
            models = {
                'score_predictor': self.score_predictor,
                'scaler': self.scaler,
                'historical_scores': self.historical_scores,
                'threat_landscape_data': self.threat_landscape_data,
                'business_context': self.business_context
            }
            joblib.dump(models, self.model_path)
        except Exception as e:
            print(f"Warning: Could not save models: {e}")
    
    def _initialize_scoring_rules(self):
        """Initialize scoring rules."""
        # Threat level adjustment rule
        threat_rule = ScoringRule(
            rule_id='threat_level_adjustment',
            name='Threat Level Adjustment',
            condition=lambda data: data.get('threat_level') in ['HIGH', 'CRITICAL'],
            adjustment=lambda score, data: score * self.adjustment_factors['threat_level'].get(data.get('threat_level', 'MEDIUM'), 1.0),
            weight=0.3,
            description='Adjust score based on current threat level'
        )
        self.scoring_rules.append(threat_rule)
        
        # Business impact adjustment rule
        business_rule = ScoringRule(
            rule_id='business_impact_adjustment',
            name='Business Impact Adjustment',
            condition=lambda data: data.get('business_impact') in ['CRITICAL', 'HIGH'],
            adjustment=lambda score, data: score * self.adjustment_factors['business_impact'].get(data.get('business_impact', 'MEDIUM'), 1.0),
            weight=0.25,
            description='Adjust score based on business impact'
        )
        self.scoring_rules.append(business_rule)
        
        # Compliance requirement rule
        compliance_rule = ScoringRule(
            rule_id='compliance_adjustment',
            name='Compliance Adjustment',
            condition=lambda data: 'REQUIRED' in data.get('compliance_requirements', []),
            adjustment=lambda score, data: score * 1.2 if 'REQUIRED' in data.get('compliance_requirements', []) else score,
            weight=0.2,
            description='Adjust score based on compliance requirements'
        )
        self.scoring_rules.append(compliance_rule)
        
        # Time factor rule
        time_rule = ScoringRule(
            rule_id='time_factor_adjustment',
            name='Time Factor Adjustment',
            condition=lambda data: data.get('age_factor') == 'recent',
            adjustment=lambda score, data: score * self.adjustment_factors['time_factor'].get(data.get('age_factor', 'moderate'), 1.0),
            weight=0.15,
            description='Adjust score based on time factors'
        )
        self.scoring_rules.append(time_rule)
        
        # Historical pattern rule
        historical_rule = ScoringRule(
            rule_id='historical_pattern_adjustment',
            name='Historical Pattern Adjustment',
            condition=lambda data: data.get('historical_risk') > 0.7,
            adjustment=lambda score, data: score * (1 + data.get('historical_risk', 0) * 0.2),
            weight=0.1,
            description='Adjust score based on historical patterns'
        )
        self.scoring_rules.append(historical_rule)
    
    def calculate_dynamic_score(self, finding: Dict[str, Any], context: ScoringContext) -> DynamicScore:
        """Calculate dynamic score for a finding."""
        # Calculate base score
        base_score = self._calculate_base_score(finding)
        
        # Apply dynamic adjustments
        adjusted_score, factors = self._apply_dynamic_adjustments(base_score, finding, context)
        
        # Calculate confidence
        confidence = self._calculate_confidence(finding, context)
        
        # Generate explanation
        explanation = self._generate_explanation(base_score, adjusted_score, factors, context)
        
        # Create dynamic score
        dynamic_score = DynamicScore(
            score_id=f"dynamic_{finding.get('id', 'unknown')}_{datetime.now().timestamp()}",
            base_score=base_score,
            adjusted_score=adjusted_score,
            confidence=confidence,
            factors=factors,
            context=context,
            timestamp=datetime.now(),
            explanation=explanation
        )
        
        # Store in historical data
        self.historical_scores.append({
            'timestamp': datetime.now().timestamp(),
            'base_score': base_score,
            'adjusted_score': adjusted_score,
            'finding_type': finding.get('type', 'unknown'),
            'severity': finding.get('severity', 'MEDIUM'),
            'context': context
        })
        
        return dynamic_score
    
    def _calculate_base_score(self, finding: Dict[str, Any]) -> float:
        """Calculate base score for a finding."""
        # Extract severity
        severity = finding.get('severity', 'MEDIUM')
        severity_scores = {'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25}
        severity_score = severity_scores.get(severity, 50)
        
        # Extract exploitability
        exploitability = finding.get('exploitability', 'MEDIUM')
        exploitability_scores = {'HIGH': 1.0, 'MEDIUM': 0.6, 'LOW': 0.3}
        exploitability_factor = exploitability_scores.get(exploitability, 0.6)
        
        # Extract impact
        impact = finding.get('impact', 'MEDIUM')
        impact_scores = {'HIGH': 1.0, 'MEDIUM': 0.6, 'LOW': 0.3}
        impact_factor = impact_scores.get(impact, 0.6)
        
        # Calculate base score
        base_score = severity_score * exploitability_factor * impact_factor
        
        return min(100.0, base_score)
    
    def _apply_dynamic_adjustments(self, base_score: float, finding: Dict[str, Any], context: ScoringContext) -> Tuple[float, Dict[str, float]]:
        """Apply dynamic adjustments to base score."""
        adjusted_score = base_score
        factors = {}
        
        # Apply scoring rules
        for rule in self.scoring_rules:
            if rule.condition(finding):
                old_score = adjusted_score
                adjusted_score = rule.adjustment(adjusted_score, finding)
                factor_change = (adjusted_score - old_score) / old_score if old_score > 0 else 0
                factors[rule.rule_id] = factor_change
        
        # Apply ML-based adjustments
        ml_adjustment = self._apply_ml_adjustment(finding, context)
        if ml_adjustment != 1.0:
            old_score = adjusted_score
            adjusted_score *= ml_adjustment
            factors['ml_adjustment'] = (adjusted_score - old_score) / old_score if old_score > 0 else 0
        
        # Apply threat landscape adjustments
        threat_adjustment = self._apply_threat_landscape_adjustment(finding, context)
        if threat_adjustment != 1.0:
            old_score = adjusted_score
            adjusted_score *= threat_adjustment
            factors['threat_landscape'] = (adjusted_score - old_score) / old_score if old_score > 0 else 0
        
        # Apply business context adjustments
        business_adjustment = self._apply_business_context_adjustment(finding, context)
        if business_adjustment != 1.0:
            old_score = adjusted_score
            adjusted_score *= business_adjustment
            factors['business_context'] = (adjusted_score - old_score) / old_score if old_score > 0 else 0
        
        # Ensure score is within bounds
        adjusted_score = max(0.0, min(100.0, adjusted_score))
        
        return adjusted_score, factors
    
    def _apply_ml_adjustment(self, finding: Dict[str, Any], context: ScoringContext) -> float:
        """Apply ML-based adjustment."""
        try:
            # Prepare features for ML model
            features = self._extract_ml_features(finding, context)
            
            if not features:
                return 1.0
            
            # Scale features
            features_scaled = self.scaler.transform([list(features.values())])
            
            # Predict adjustment
            adjustment = self.score_predictor.predict(features_scaled)[0]
            
            # Normalize adjustment
            return max(0.5, min(2.0, adjustment))
            
        except Exception as e:
            print(f"Warning: ML adjustment failed: {e}")
            return 1.0
    
    def _apply_threat_landscape_adjustment(self, finding: Dict[str, Any], context: ScoringContext) -> float:
        """Apply threat landscape adjustment."""
        threat_level = context.threat_level
        finding_type = finding.get('type', 'unknown')
        
        # Get threat landscape data for finding type
        threat_data = self.threat_landscape_data.get(finding_type, {})
        
        if not threat_data:
            return 1.0
        
        # Calculate adjustment based on threat level and landscape
        base_adjustment = threat_data.get('base_adjustment', 1.0)
        threat_multiplier = self.adjustment_factors['threat_level'].get(threat_level, 1.0)
        
        return base_adjustment * threat_multiplier
    
    def _apply_business_context_adjustment(self, finding: Dict[str, Any], context: ScoringContext) -> float:
        """Apply business context adjustment."""
        business_impact = context.business_impact
        compliance_requirements = context.compliance_requirements
        
        # Base business impact adjustment
        business_adjustment = self.adjustment_factors['business_impact'].get(business_impact, 1.0)
        
        # Compliance adjustment
        compliance_adjustment = 1.0
        if 'REQUIRED' in compliance_requirements:
            compliance_adjustment = 1.2
        elif 'RECOMMENDED' in compliance_requirements:
            compliance_adjustment = 1.1
        
        return business_adjustment * compliance_adjustment
    
    def _extract_ml_features(self, finding: Dict[str, Any], context: ScoringContext) -> Dict[str, float]:
        """Extract features for ML model."""
        features = {}
        
        # Finding features
        features['severity_numeric'] = self._severity_to_numeric(finding.get('severity', 'MEDIUM'))
        features['exploitability_numeric'] = self._exploitability_to_numeric(finding.get('exploitability', 'MEDIUM'))
        features['impact_numeric'] = self._impact_to_numeric(finding.get('impact', 'MEDIUM'))
        
        # Context features
        features['threat_level_numeric'] = self._threat_level_to_numeric(context.threat_level)
        features['business_impact_numeric'] = self._business_impact_to_numeric(context.business_impact)
        features['compliance_count'] = len(context.compliance_requirements)
        
        # Historical features
        historical_data = context.historical_data
        features['historical_risk'] = historical_data.get('risk_score', 0.5)
        features['historical_frequency'] = historical_data.get('frequency', 0.0)
        
        # Time features
        features['age_factor'] = self._calculate_age_factor(finding.get('timestamp', datetime.now()))
        
        return features
    
    def _calculate_confidence(self, finding: Dict[str, Any], context: ScoringContext) -> float:
        """Calculate confidence in the score."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on data quality
        if finding.get('severity') and finding.get('exploitability') and finding.get('impact'):
            confidence += 0.2
        
        # Increase confidence based on historical data
        if context.historical_data:
            confidence += 0.1
        
        # Increase confidence based on threat landscape data
        if self.threat_landscape_data.get(finding.get('type', 'unknown')):
            confidence += 0.1
        
        # Decrease confidence for new or unknown finding types
        if finding.get('type', 'unknown') == 'unknown':
            confidence -= 0.2
        
        return max(0.0, min(1.0, confidence))
    
    def _generate_explanation(self, base_score: float, adjusted_score: float, factors: Dict[str, float], context: ScoringContext) -> str:
        """Generate explanation for the score."""
        explanation_parts = []
        
        explanation_parts.append(f"Base score: {base_score:.1f}")
        
        if factors:
            explanation_parts.append("Adjustments applied:")
            for factor, change in factors.items():
                if abs(change) > 0.01:  # Only include significant changes
                    direction = "increased" if change > 0 else "decreased"
                    explanation_parts.append(f"  - {factor}: {direction} by {abs(change)*100:.1f}%")
        
        explanation_parts.append(f"Final score: {adjusted_score:.1f}")
        
        # Add context information
        if context.threat_level != 'MEDIUM':
            explanation_parts.append(f"Threat level: {context.threat_level}")
        
        if context.business_impact != 'MEDIUM':
            explanation_parts.append(f"Business impact: {context.business_impact}")
        
        if context.compliance_requirements:
            explanation_parts.append(f"Compliance requirements: {', '.join(context.compliance_requirements)}")
        
        return "; ".join(explanation_parts)
    
    def train_models(self, training_data: List[Dict[str, Any]]):
        """Train ML models on historical data."""
        if not training_data:
            return
        
        # Prepare training data
        X = []
        y = []
        
        for data in training_data:
            features = self._extract_ml_features(data.get('finding', {}), data.get('context', ScoringContext(
                timestamp=datetime.now(),
                threat_level='MEDIUM',
                business_impact='MEDIUM',
                compliance_requirements=[],
                historical_data={},
                external_factors={}
            )))
            
            if features:
                X.append(list(features.values()))
                y.append(data.get('actual_score', 0.5))
        
        if not X:
            return
        
        # Convert to numpy arrays
        X = np.array(X)
        y = np.array(y)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.score_predictor.fit(X_scaled, y)
        
        # Save models
        self._save_models()
    
    def update_threat_landscape(self, threat_data: Dict[str, Any]):
        """Update threat landscape data."""
        self.threat_landscape_data.update(threat_data)
        self._save_models()
    
    def update_business_context(self, business_data: Dict[str, Any]):
        """Update business context data."""
        self.business_context.update(business_data)
        self._save_models()
    
    def get_score_trends(self, timeframe: str = '30d') -> Dict[str, Any]:
        """Get score trends over time."""
        if not self.historical_scores:
            return {}
        
        # Filter by timeframe
        cutoff_time = datetime.now() - timedelta(days=int(timeframe[:-1]))
        recent_scores = [score for score in self.historical_scores 
                        if datetime.fromtimestamp(score['timestamp']) > cutoff_time]
        
        if not recent_scores:
            return {}
        
        # Calculate trends
        scores = [score['adjusted_score'] for score in recent_scores]
        timestamps = [score['timestamp'] for score in recent_scores]
        
        # Calculate trend
        if len(scores) > 1:
            trend = np.polyfit(timestamps, scores, 1)[0]
        else:
            trend = 0
        
        # Calculate statistics
        stats = {
            'average_score': np.mean(scores),
            'median_score': np.median(scores),
            'std_score': np.std(scores),
            'min_score': np.min(scores),
            'max_score': np.max(scores),
            'trend': trend,
            'sample_count': len(scores)
        }
        
        return stats
    
    # Helper methods
    def _severity_to_numeric(self, severity: str) -> float:
        """Convert severity to numeric value."""
        severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'MINIMAL': 0}
        return severity_map.get(severity, 2)
    
    def _exploitability_to_numeric(self, exploitability: str) -> float:
        """Convert exploitability to numeric value."""
        exploitability_map = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return exploitability_map.get(exploitability, 2)
    
    def _impact_to_numeric(self, impact: str) -> float:
        """Convert impact to numeric value."""
        impact_map = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return impact_map.get(impact, 2)
    
    def _threat_level_to_numeric(self, threat_level: str) -> float:
        """Convert threat level to numeric value."""
        threat_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return threat_map.get(threat_level, 2)
    
    def _business_impact_to_numeric(self, business_impact: str) -> float:
        """Convert business impact to numeric value."""
        business_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return business_map.get(business_impact, 2)
    
    def _calculate_age_factor(self, timestamp: datetime) -> str:
        """Calculate age factor for a timestamp."""
        age_days = (datetime.now() - timestamp).days
        
        if age_days < 7:
            return 'recent'
        elif age_days < 30:
            return 'moderate'
        else:
            return 'old'
