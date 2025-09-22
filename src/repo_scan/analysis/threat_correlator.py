"""
Threat Correlation System.

This module implements advanced threat correlation capabilities including:
- Multi-source threat intelligence correlation
- Attack pattern recognition
- Threat actor attribution
- Campaign analysis
- Risk aggregation
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional, Set
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict, Counter
import json
import requests
from datetime import datetime, timedelta
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from sklearn.metrics.pairwise import cosine_similarity
import networkx as nx


@dataclass
class ThreatIndicator:
    """Represents a threat indicator."""
    indicator_id: str
    indicator_type: str
    value: str
    confidence: float
    severity: str
    source: str
    timestamp: datetime
    metadata: Dict[str, Any]


@dataclass
class ThreatActor:
    """Represents a threat actor."""
    actor_id: str
    name: str
    aliases: List[str]
    techniques: List[str]
    targets: List[str]
    confidence: float
    metadata: Dict[str, Any]


@dataclass
class AttackCampaign:
    """Represents an attack campaign."""
    campaign_id: str
    name: str
    threat_actors: List[str]
    techniques: List[str]
    targets: List[str]
    timeline: List[datetime]
    confidence: float
    description: str


@dataclass
class ThreatCorrelation:
    """Represents a threat correlation result."""
    correlation_id: str
    correlation_type: str
    confidence: float
    severity: str
    indicators: List[ThreatIndicator]
    threat_actors: List[ThreatActor]
    campaigns: List[AttackCampaign]
    description: str
    recommendations: List[str]


class ThreatCorrelator:
    """
    Advanced threat correlation system.
    
    Features:
    - Multi-source threat intelligence correlation
    - Attack pattern recognition
    - Threat actor attribution
    - Campaign analysis
    - Risk aggregation and scoring
    """
    
    def __init__(self, threat_intel_path: Optional[str] = None):
        """Initialize the threat correlator."""
        self.threat_intel_path = threat_intel_path or "data/threat_intelligence.json"
        self.threat_indicators = []
        self.threat_actors = []
        self.attack_campaigns = []
        self.correlation_rules = []
        
        # Threat intelligence sources
        self.threat_sources = {
            'mitre_attack': 'https://attack.mitre.org',
            'nvd': 'https://services.nvd.nist.gov',
            'cve': 'https://cve.mitre.org',
            'virustotal': 'https://www.virustotal.com',
            'threatcrowd': 'https://www.threatcrowd.org',
            'otx': 'https://otx.alienvault.com'
        }
        
        # Attack pattern templates
        self.attack_patterns = {
            'apt_campaign': {
                'indicators': ['spear_phishing', 'zero_day', 'persistence', 'lateral_movement'],
                'confidence_threshold': 0.7
            },
            'ransomware': {
                'indicators': ['file_encryption', 'ransom_note', 'bitcoin_payment'],
                'confidence_threshold': 0.8
            },
            'supply_chain_attack': {
                'indicators': ['dependency_compromise', 'build_system_compromise', 'update_mechanism_abuse'],
                'confidence_threshold': 0.6
            },
            'insider_threat': {
                'indicators': ['unusual_access_patterns', 'data_exfiltration', 'privilege_abuse'],
                'confidence_threshold': 0.5
            }
        }
        
        self._load_threat_intelligence()
    
    def _load_threat_intelligence(self):
        """Load threat intelligence data."""
        try:
            if Path(self.threat_intel_path).exists():
                with open(self.threat_intel_path, 'r') as f:
                    data = json.load(f)
                    self.threat_indicators = data.get('indicators', [])
                    self.threat_actors = data.get('actors', [])
                    self.attack_campaigns = data.get('campaigns', [])
                    self.correlation_rules = data.get('rules', [])
        except Exception as e:
            print(f"Warning: Could not load threat intelligence: {e}")
    
    def _save_threat_intelligence(self):
        """Save threat intelligence data."""
        try:
            Path(self.threat_intel_path).parent.mkdir(parents=True, exist_ok=True)
            data = {
                'indicators': self.threat_indicators,
                'actors': self.threat_actors,
                'campaigns': self.attack_campaigns,
                'rules': self.correlation_rules
            }
            with open(self.threat_intel_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save threat intelligence: {e}")
    
    def correlate_threats(self, repo_data: Dict[str, Any]) -> List[ThreatCorrelation]:
        """Perform threat correlation analysis."""
        correlations = []
        
        # Extract threat indicators from repository
        indicators = self._extract_threat_indicators(repo_data)
        
        # Correlate with known threat intelligence
        for indicator in indicators:
            correlation = self._correlate_indicator(indicator)
            if correlation:
                correlations.append(correlation)
        
        # Detect attack patterns
        pattern_correlations = self._detect_attack_patterns(indicators)
        correlations.extend(pattern_correlations)
        
        # Correlate with threat actors
        actor_correlations = self._correlate_threat_actors(indicators)
        correlations.extend(actor_correlations)
        
        # Correlate with campaigns
        campaign_correlations = self._correlate_campaigns(indicators)
        correlations.extend(campaign_correlations)
        
        # Aggregate correlations
        aggregated_correlations = self._aggregate_correlations(correlations)
        
        return aggregated_correlations
    
    def _extract_threat_indicators(self, repo_data: Dict[str, Any]) -> List[ThreatIndicator]:
        """Extract threat indicators from repository data."""
        indicators = []
        
        # Extract from vulnerabilities
        vulnerabilities = repo_data.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            indicator = ThreatIndicator(
                indicator_id=f"vuln_{vuln.get('id', 'unknown')}",
                indicator_type='vulnerability',
                value=vuln.get('id', ''),
                confidence=0.8,
                severity=vuln.get('severity', 'MEDIUM'),
                source='repository_scan',
                timestamp=datetime.now(),
                metadata=vuln
            )
            indicators.append(indicator)
        
        # Extract from security findings
        security_findings = repo_data.get('security_findings', [])
        for finding in security_findings:
            indicator = ThreatIndicator(
                indicator_id=f"finding_{finding.get('id', 'unknown')}",
                indicator_type='security_finding',
                value=finding.get('type', ''),
                confidence=finding.get('confidence', 0.5),
                severity=finding.get('severity', 'MEDIUM'),
                source='security_scanner',
                timestamp=datetime.now(),
                metadata=finding
            )
            indicators.append(indicator)
        
        # Extract from dependencies
        dependencies = repo_data.get('dependencies', [])
        for dep in dependencies:
            if dep.get('vulnerable', False):
                indicator = ThreatIndicator(
                    indicator_id=f"dep_{dep.get('name', 'unknown')}",
                    indicator_type='vulnerable_dependency',
                    value=dep.get('name', ''),
                    confidence=0.7,
                    severity=dep.get('severity', 'MEDIUM'),
                    source='dependency_scan',
                    timestamp=datetime.now(),
                    metadata=dep
                )
                indicators.append(indicator)
        
        # Extract from code patterns
        code_patterns = repo_data.get('code_patterns', [])
        for pattern in code_patterns:
            if pattern.get('suspicious', False):
                indicator = ThreatIndicator(
                    indicator_id=f"pattern_{pattern.get('id', 'unknown')}",
                    indicator_type='suspicious_pattern',
                    value=pattern.get('pattern', ''),
                    confidence=pattern.get('confidence', 0.5),
                    severity=pattern.get('severity', 'MEDIUM'),
                    source='pattern_analysis',
                    timestamp=datetime.now(),
                    metadata=pattern
                )
                indicators.append(indicator)
        
        return indicators
    
    def _correlate_indicator(self, indicator: ThreatIndicator) -> Optional[ThreatCorrelation]:
        """Correlate a single indicator with threat intelligence."""
        correlations = []
        
        # Check against known indicators
        for known_indicator in self.threat_indicators:
            similarity = self._calculate_indicator_similarity(indicator, known_indicator)
            if similarity > 0.7:
                correlations.append(known_indicator)
        
        if correlations:
            return ThreatCorrelation(
                correlation_id=f"corr_{indicator.indicator_id}",
                correlation_type='indicator_correlation',
                confidence=max(corr.get('confidence', 0.5) for corr in correlations),
                severity=indicator.severity,
                indicators=[indicator],
                threat_actors=[],
                campaigns=[],
                description=f"Indicator {indicator.value} correlated with {len(correlations)} known threats",
                recommendations=self._generate_indicator_recommendations(indicator, correlations)
            )
        
        return None
    
    def _detect_attack_patterns(self, indicators: List[ThreatIndicator]) -> List[ThreatCorrelation]:
        """Detect attack patterns from indicators."""
        pattern_correlations = []
        
        for pattern_name, pattern_info in self.attack_patterns.items():
            matching_indicators = []
            
            for indicator in indicators:
                if self._indicator_matches_pattern(indicator, pattern_info):
                    matching_indicators.append(indicator)
            
            if len(matching_indicators) >= len(pattern_info['indicators']) * 0.5:
                confidence = len(matching_indicators) / len(pattern_info['indicators'])
                
                if confidence >= pattern_info['confidence_threshold']:
                    correlation = ThreatCorrelation(
                        correlation_id=f"pattern_{pattern_name}_{datetime.now().timestamp()}",
                        correlation_type='attack_pattern',
                        confidence=confidence,
                        severity=self._determine_pattern_severity(pattern_name, confidence),
                        indicators=matching_indicators,
                        threat_actors=[],
                        campaigns=[],
                        description=f"Detected {pattern_name} attack pattern",
                        recommendations=self._generate_pattern_recommendations(pattern_name, matching_indicators)
                    )
                    pattern_correlations.append(correlation)
        
        return pattern_correlations
    
    def _correlate_threat_actors(self, indicators: List[ThreatIndicator]) -> List[ThreatCorrelation]:
        """Correlate indicators with threat actors."""
        actor_correlations = []
        
        for actor in self.threat_actors:
            matching_indicators = []
            
            for indicator in indicators:
                if self._indicator_matches_actor(indicator, actor):
                    matching_indicators.append(indicator)
            
            if matching_indicators:
                confidence = len(matching_indicators) / len(actor.get('techniques', []))
                
                if confidence > 0.3:
                    correlation = ThreatCorrelation(
                        correlation_id=f"actor_{actor.get('id', 'unknown')}_{datetime.now().timestamp()}",
                        correlation_type='threat_actor',
                        confidence=confidence,
                        severity='HIGH',
                        indicators=matching_indicators,
                        threat_actors=[actor],
                        campaigns=[],
                        description=f"Indicators correlate with threat actor {actor.get('name', 'Unknown')}",
                        recommendations=self._generate_actor_recommendations(actor, matching_indicators)
                    )
                    actor_correlations.append(correlation)
        
        return actor_correlations
    
    def _correlate_campaigns(self, indicators: List[ThreatIndicator]) -> List[ThreatCorrelation]:
        """Correlate indicators with attack campaigns."""
        campaign_correlations = []
        
        for campaign in self.attack_campaigns:
            matching_indicators = []
            
            for indicator in indicators:
                if self._indicator_matches_campaign(indicator, campaign):
                    matching_indicators.append(indicator)
            
            if matching_indicators:
                confidence = len(matching_indicators) / len(campaign.get('techniques', []))
                
                if confidence > 0.4:
                    correlation = ThreatCorrelation(
                        correlation_id=f"campaign_{campaign.get('id', 'unknown')}_{datetime.now().timestamp()}",
                        correlation_type='attack_campaign',
                        confidence=confidence,
                        severity='CRITICAL',
                        indicators=matching_indicators,
                        threat_actors=[],
                        campaigns=[campaign],
                        description=f"Indicators correlate with campaign {campaign.get('name', 'Unknown')}",
                        recommendations=self._generate_campaign_recommendations(campaign, matching_indicators)
                    )
                    campaign_correlations.append(correlation)
        
        return campaign_correlations
    
    def _aggregate_correlations(self, correlations: List[ThreatCorrelation]) -> List[ThreatCorrelation]:
        """Aggregate similar correlations."""
        if not correlations:
            return []
        
        # Group correlations by type
        grouped_correlations = defaultdict(list)
        for correlation in correlations:
            grouped_correlations[correlation.correlation_type].append(correlation)
        
        aggregated = []
        
        for correlation_type, type_correlations in grouped_correlations.items():
            if len(type_correlations) == 1:
                aggregated.append(type_correlations[0])
            else:
                # Aggregate multiple correlations of the same type
                aggregated_correlation = self._merge_correlations(type_correlations)
                aggregated.append(aggregated_correlation)
        
        # Sort by confidence and severity
        aggregated.sort(key=lambda x: (x.confidence, self._severity_to_numeric(x.severity)), reverse=True)
        
        return aggregated
    
    def _merge_correlations(self, correlations: List[ThreatCorrelation]) -> ThreatCorrelation:
        """Merge multiple correlations into one."""
        if not correlations:
            return None
        
        # Merge indicators
        all_indicators = []
        for correlation in correlations:
            all_indicators.extend(correlation.indicators)
        
        # Remove duplicates
        unique_indicators = []
        seen_ids = set()
        for indicator in all_indicators:
            if indicator.indicator_id not in seen_ids:
                unique_indicators.append(indicator)
                seen_ids.add(indicator.indicator_id)
        
        # Merge threat actors
        all_actors = []
        for correlation in correlations:
            all_actors.extend(correlation.threat_actors)
        
        # Remove duplicates
        unique_actors = []
        seen_ids = set()
        for actor in all_actors:
            actor_id = actor.get('id', '') if isinstance(actor, dict) else actor.actor_id
            if actor_id not in seen_ids:
                unique_actors.append(actor)
                seen_ids.add(actor_id)
        
        # Merge campaigns
        all_campaigns = []
        for correlation in correlations:
            all_campaigns.extend(correlation.campaigns)
        
        # Remove duplicates
        unique_campaigns = []
        seen_ids = set()
        for campaign in all_campaigns:
            campaign_id = campaign.get('id', '') if isinstance(campaign, dict) else campaign.campaign_id
            if campaign_id not in seen_ids:
                unique_campaigns.append(campaign)
                seen_ids.add(campaign_id)
        
        # Calculate aggregated confidence
        avg_confidence = sum(correlation.confidence for correlation in correlations) / len(correlations)
        
        # Determine highest severity
        severities = [correlation.severity for correlation in correlations]
        highest_severity = max(severities, key=lambda x: self._severity_to_numeric(x))
        
        # Merge recommendations
        all_recommendations = []
        for correlation in correlations:
            all_recommendations.extend(correlation.recommendations)
        
        # Remove duplicates
        unique_recommendations = list(set(all_recommendations))
        
        return ThreatCorrelation(
            correlation_id=f"aggregated_{correlations[0].correlation_type}_{datetime.now().timestamp()}",
            correlation_type=correlations[0].correlation_type,
            confidence=avg_confidence,
            severity=highest_severity,
            indicators=unique_indicators,
            threat_actors=unique_actors,
            campaigns=unique_campaigns,
            description=f"Aggregated {len(correlations)} {correlations[0].correlation_type} correlations",
            recommendations=unique_recommendations
        )
    
    def _calculate_indicator_similarity(self, indicator1: ThreatIndicator, indicator2: Dict[str, Any]) -> float:
        """Calculate similarity between two indicators."""
        # Simple similarity based on type and value
        if indicator1.indicator_type != indicator2.get('type', ''):
            return 0.0
        
        # Value similarity
        value1 = indicator1.value.lower()
        value2 = indicator2.get('value', '').lower()
        
        if value1 == value2:
            return 1.0
        
        # Partial match
        if value1 in value2 or value2 in value1:
            return 0.7
        
        # Fuzzy matching (simplified)
        return self._fuzzy_match(value1, value2)
    
    def _fuzzy_match(self, str1: str, str2: str) -> float:
        """Simple fuzzy string matching."""
        if not str1 or not str2:
            return 0.0
        
        # Calculate Jaccard similarity
        set1 = set(str1.split())
        set2 = set(str2.split())
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def _indicator_matches_pattern(self, indicator: ThreatIndicator, pattern_info: Dict[str, Any]) -> bool:
        """Check if indicator matches attack pattern."""
        pattern_indicators = pattern_info.get('indicators', [])
        
        for pattern_indicator in pattern_indicators:
            if pattern_indicator.lower() in indicator.value.lower():
                return True
        
        return False
    
    def _indicator_matches_actor(self, indicator: ThreatIndicator, actor: Dict[str, Any]) -> bool:
        """Check if indicator matches threat actor."""
        actor_techniques = actor.get('techniques', [])
        
        for technique in actor_techniques:
            if technique.lower() in indicator.value.lower():
                return True
        
        return False
    
    def _indicator_matches_campaign(self, indicator: ThreatIndicator, campaign: Dict[str, Any]) -> bool:
        """Check if indicator matches attack campaign."""
        campaign_techniques = campaign.get('techniques', [])
        
        for technique in campaign_techniques:
            if technique.lower() in indicator.value.lower():
                return True
        
        return False
    
    def _determine_pattern_severity(self, pattern_name: str, confidence: float) -> str:
        """Determine severity based on attack pattern."""
        if pattern_name in ['apt_campaign', 'supply_chain_attack']:
            return 'CRITICAL'
        elif pattern_name == 'ransomware':
            return 'HIGH'
        elif pattern_name == 'insider_threat':
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _severity_to_numeric(self, severity: str) -> int:
        """Convert severity to numeric value for sorting."""
        severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'MINIMAL': 0}
        return severity_map.get(severity, 0)
    
    def _generate_indicator_recommendations(self, indicator: ThreatIndicator, correlations: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations for indicator correlation."""
        recommendations = []
        
        recommendations.append(f"Investigate indicator {indicator.value} immediately")
        recommendations.append("Review related threat intelligence")
        recommendations.append("Implement additional monitoring")
        
        if indicator.severity in ['CRITICAL', 'HIGH']:
            recommendations.append("Consider incident response activation")
        
        return recommendations
    
    def _generate_pattern_recommendations(self, pattern_name: str, indicators: List[ThreatIndicator]) -> List[str]:
        """Generate recommendations for attack pattern detection."""
        recommendations = []
        
        recommendations.append(f"Investigate {pattern_name} attack pattern")
        recommendations.append("Review all related indicators")
        recommendations.append("Implement pattern-specific defenses")
        
        if pattern_name == 'apt_campaign':
            recommendations.append("Activate advanced threat hunting")
            recommendations.append("Review network segmentation")
        elif pattern_name == 'ransomware':
            recommendations.append("Check backup systems")
            recommendations.append("Review file access controls")
        elif pattern_name == 'supply_chain_attack':
            recommendations.append("Audit all dependencies")
            recommendations.append("Review build processes")
        
        return recommendations
    
    def _generate_actor_recommendations(self, actor: Dict[str, Any], indicators: List[ThreatIndicator]) -> List[str]:
        """Generate recommendations for threat actor correlation."""
        recommendations = []
        
        actor_name = actor.get('name', 'Unknown')
        recommendations.append(f"Investigate potential {actor_name} activity")
        recommendations.append("Review actor-specific techniques")
        recommendations.append("Implement actor-specific defenses")
        
        return recommendations
    
    def _generate_campaign_recommendations(self, campaign: Dict[str, Any], indicators: List[ThreatIndicator]) -> List[str]:
        """Generate recommendations for campaign correlation."""
        recommendations = []
        
        campaign_name = campaign.get('name', 'Unknown')
        recommendations.append(f"Investigate {campaign_name} campaign")
        recommendations.append("Review campaign timeline")
        recommendations.append("Implement campaign-specific defenses")
        recommendations.append("Consider threat hunting activities")
        
        return recommendations
    
    def fetch_threat_intelligence(self, source: str = 'all') -> bool:
        """Fetch threat intelligence from external sources."""
        success = True
        
        if source == 'all' or source == 'mitre_attack':
            success &= self._fetch_mitre_attack_data()
        
        if source == 'all' or source == 'nvd':
            success &= self._fetch_nvd_data()
        
        if source == 'all' or source == 'cve':
            success &= self._fetch_cve_data()
        
        if success:
            self._save_threat_intelligence()
        
        return success
    
    def _fetch_mitre_attack_data(self) -> bool:
        """Fetch MITRE ATT&CK data."""
        try:
            # This is a simplified implementation
            # In practice, you would use the MITRE ATT&CK API
            print("Fetching MITRE ATT&CK data...")
            # Implementation would go here
            return True
        except Exception as e:
            print(f"Error fetching MITRE ATT&CK data: {e}")
            return False
    
    def _fetch_nvd_data(self) -> bool:
        """Fetch NVD data."""
        try:
            print("Fetching NVD data...")
            # Implementation would go here
            return True
        except Exception as e:
            print(f"Error fetching NVD data: {e}")
            return False
    
    def _fetch_cve_data(self) -> bool:
        """Fetch CVE data."""
        try:
            print("Fetching CVE data...")
            # Implementation would go here
            return True
        except Exception as e:
            print(f"Error fetching CVE data: {e}")
            return False
