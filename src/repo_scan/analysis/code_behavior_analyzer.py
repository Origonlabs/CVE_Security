"""
Code Behavior Analysis.

This module implements advanced code behavior analysis including:
- Code evolution analysis
- Complexity trend analysis
- Security pattern evolution
- Code quality metrics
- Technical debt analysis
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional, Set
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict, Counter
import json
import re
from datetime import datetime, timedelta
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import networkx as nx


@dataclass
class CodeMetric:
    """Represents a code metric."""
    metric_id: str
    metric_type: str
    value: float
    timestamp: datetime
    file_path: str
    context: Dict[str, Any]


@dataclass
class CodeEvolution:
    """Represents code evolution analysis."""
    file_path: str
    evolution_type: str
    trend: str
    confidence: float
    metrics: List[CodeMetric]
    description: str


@dataclass
class ComplexityAnalysis:
    """Represents complexity analysis results."""
    file_path: str
    cyclomatic_complexity: float
    cognitive_complexity: float
    maintainability_index: float
    technical_debt: float
    recommendations: List[str]


@dataclass
class CodeBehaviorAnalysis:
    """Represents complete code behavior analysis."""
    total_files: int
    analyzed_files: int
    code_evolutions: List[CodeEvolution]
    complexity_analysis: List[ComplexityAnalysis]
    quality_metrics: Dict[str, float]
    technical_debt: float
    recommendations: List[str]


class CodeBehaviorAnalyzer:
    """
    Advanced code behavior analyzer.
    
    Features:
    - Code evolution tracking
    - Complexity trend analysis
    - Security pattern evolution
    - Code quality metrics
    - Technical debt analysis
    - Maintainability assessment
    """
    
    def __init__(self, analysis_history_path: Optional[str] = None):
        """Initialize the code behavior analyzer."""
        self.analysis_history_path = analysis_history_path or "data/code_analysis_history.json"
        self.analysis_history = []
        self.complexity_thresholds = {
            'cyclomatic': {'low': 10, 'medium': 20, 'high': 50},
            'cognitive': {'low': 15, 'medium': 25, 'high': 50},
            'maintainability': {'low': 20, 'medium': 10, 'high': 0}
        }
        
        # Code quality patterns
        self.quality_patterns = {
            'code_smells': [
                'long_method', 'large_class', 'duplicate_code',
                'dead_code', 'complex_conditional', 'magic_numbers'
            ],
            'security_patterns': [
                'hardcoded_secrets', 'sql_injection', 'xss',
                'path_traversal', 'weak_crypto', 'insecure_redirect'
            ],
            'maintainability_patterns': [
                'poor_naming', 'deep_nesting', 'high_coupling',
                'low_cohesion', 'missing_documentation'
            ]
        }
        
        self._load_analysis_history()
    
    def _load_analysis_history(self):
        """Load analysis history."""
        try:
            if Path(self.analysis_history_path).exists():
                with open(self.analysis_history_path, 'r') as f:
                    self.analysis_history = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load analysis history: {e}")
            self.analysis_history = []
    
    def _save_analysis_history(self):
        """Save analysis history."""
        try:
            Path(self.analysis_history_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.analysis_history_path, 'w') as f:
                json.dump(self.analysis_history, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save analysis history: {e}")
    
    def analyze_code_behavior(self, repo_data: Dict[str, Any]) -> CodeBehaviorAnalysis:
        """Perform comprehensive code behavior analysis."""
        # Extract code files
        files = repo_data.get('files', [])
        
        # Analyze code evolution
        code_evolutions = self._analyze_code_evolution(files)
        
        # Analyze complexity
        complexity_analysis = self._analyze_complexity(files)
        
        # Calculate quality metrics
        quality_metrics = self._calculate_quality_metrics(files)
        
        # Calculate technical debt
        technical_debt = self._calculate_technical_debt(files, complexity_analysis)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(code_evolutions, complexity_analysis, quality_metrics)
        
        # Save analysis to history
        analysis_result = {
            'timestamp': datetime.now().isoformat(),
            'files_analyzed': len(files),
            'code_evolutions': len(code_evolutions),
            'complexity_analysis': len(complexity_analysis),
            'quality_metrics': quality_metrics,
            'technical_debt': technical_debt
        }
        self.analysis_history.append(analysis_result)
        self._save_analysis_history()
        
        return CodeBehaviorAnalysis(
            total_files=len(files),
            analyzed_files=len([f for f in files if f.get('content')]),
            code_evolutions=code_evolutions,
            complexity_analysis=complexity_analysis,
            quality_metrics=quality_metrics,
            technical_debt=technical_debt,
            recommendations=recommendations
        )
    
    def _analyze_code_evolution(self, files: List[Dict[str, Any]]) -> List[CodeEvolution]:
        """Analyze code evolution patterns."""
        evolutions = []
        
        for file_data in files:
            file_path = file_data.get('path', '')
            content = file_data.get('content', '')
            
            if not content:
                continue
            
            # Analyze evolution patterns
            evolution_patterns = self._detect_evolution_patterns(file_path, content)
            evolutions.extend(evolution_patterns)
        
        return evolutions
    
    def _detect_evolution_patterns(self, file_path: str, content: str) -> List[CodeEvolution]:
        """Detect evolution patterns in a file."""
        evolutions = []
        
        # Analyze complexity evolution
        complexity_evolution = self._analyze_complexity_evolution(file_path, content)
        if complexity_evolution:
            evolutions.append(complexity_evolution)
        
        # Analyze security pattern evolution
        security_evolution = self._analyze_security_evolution(file_path, content)
        if security_evolution:
            evolutions.append(security_evolution)
        
        # Analyze quality evolution
        quality_evolution = self._analyze_quality_evolution(file_path, content)
        if quality_evolution:
            evolutions.append(quality_evolution)
        
        return evolutions
    
    def _analyze_complexity_evolution(self, file_path: str, content: str) -> Optional[CodeEvolution]:
        """Analyze complexity evolution."""
        current_complexity = self._calculate_cyclomatic_complexity(content)
        
        # Get historical complexity
        historical_complexity = self._get_historical_complexity(file_path)
        
        if historical_complexity:
            # Calculate trend
            trend = self._calculate_complexity_trend(current_complexity, historical_complexity)
            
            if trend != 'stable':
                return CodeEvolution(
                    file_path=file_path,
                    evolution_type='complexity',
                    trend=trend,
                    confidence=0.8,
                    metrics=[CodeMetric(
                        metric_id=f"complexity_{file_path}",
                        metric_type='cyclomatic_complexity',
                        value=current_complexity,
                        timestamp=datetime.now(),
                        file_path=file_path,
                        context={'historical': historical_complexity}
                    )],
                    description=f"Complexity {trend} from {historical_complexity} to {current_complexity}"
                )
        
        return None
    
    def _analyze_security_evolution(self, file_path: str, content: str) -> Optional[CodeEvolution]:
        """Analyze security pattern evolution."""
        current_security_patterns = self._detect_security_patterns(content)
        
        # Get historical security patterns
        historical_patterns = self._get_historical_security_patterns(file_path)
        
        if historical_patterns:
            # Calculate evolution
            pattern_changes = self._calculate_pattern_changes(current_security_patterns, historical_patterns)
            
            if pattern_changes:
                return CodeEvolution(
                    file_path=file_path,
                    evolution_type='security',
                    trend='changed',
                    confidence=0.7,
                    metrics=[CodeMetric(
                        metric_id=f"security_{file_path}",
                        metric_type='security_patterns',
                        value=len(current_security_patterns),
                        timestamp=datetime.now(),
                        file_path=file_path,
                        context={'patterns': current_security_patterns, 'changes': pattern_changes}
                    )],
                    description=f"Security patterns changed: {pattern_changes}"
                )
        
        return None
    
    def _analyze_quality_evolution(self, file_path: str, content: str) -> Optional[CodeEvolution]:
        """Analyze code quality evolution."""
        current_quality = self._calculate_code_quality(content)
        
        # Get historical quality
        historical_quality = self._get_historical_quality(file_path)
        
        if historical_quality:
            # Calculate trend
            trend = self._calculate_quality_trend(current_quality, historical_quality)
            
            if trend != 'stable':
                return CodeEvolution(
                    file_path=file_path,
                    evolution_type='quality',
                    trend=trend,
                    confidence=0.6,
                    metrics=[CodeMetric(
                        metric_id=f"quality_{file_path}",
                        metric_type='code_quality',
                        value=current_quality,
                        timestamp=datetime.now(),
                        file_path=file_path,
                        context={'historical': historical_quality}
                    )],
                    description=f"Code quality {trend} from {historical_quality} to {current_quality}"
                )
        
        return None
    
    def _analyze_complexity(self, files: List[Dict[str, Any]]) -> List[ComplexityAnalysis]:
        """Analyze code complexity."""
        complexity_analyses = []
        
        for file_data in files:
            file_path = file_data.get('path', '')
            content = file_data.get('content', '')
            
            if not content:
                continue
            
            # Calculate complexity metrics
            cyclomatic_complexity = self._calculate_cyclomatic_complexity(content)
            cognitive_complexity = self._calculate_cognitive_complexity(content)
            maintainability_index = self._calculate_maintainability_index(content)
            technical_debt = self._calculate_file_technical_debt(content)
            
            # Generate recommendations
            recommendations = self._generate_complexity_recommendations(
                cyclomatic_complexity, cognitive_complexity, maintainability_index
            )
            
            complexity_analysis = ComplexityAnalysis(
                file_path=file_path,
                cyclomatic_complexity=cyclomatic_complexity,
                cognitive_complexity=cognitive_complexity,
                maintainability_index=maintainability_index,
                technical_debt=technical_debt,
                recommendations=recommendations
            )
            
            complexity_analyses.append(complexity_analysis)
        
        return complexity_analyses
    
    def _calculate_cyclomatic_complexity(self, content: str) -> float:
        """Calculate cyclomatic complexity."""
        complexity_keywords = [
            'if', 'elif', 'else', 'for', 'while', 'try', 'except', 'with',
            'and', 'or', 'case', 'default', 'catch', 'finally'
        ]
        
        complexity = 1  # Base complexity
        for keyword in complexity_keywords:
            complexity += len(re.findall(rf'\b{keyword}\b', content))
        
        return complexity
    
    def _calculate_cognitive_complexity(self, content: str) -> float:
        """Calculate cognitive complexity."""
        # Simplified cognitive complexity calculation
        cognitive_complexity = 0
        
        # Nested structures increase cognitive complexity
        lines = content.split('\n')
        nesting_level = 0
        
        for line in lines:
            line = line.strip()
            
            # Increase nesting
            if any(keyword in line for keyword in ['if', 'for', 'while', 'try', 'with']):
                nesting_level += 1
                cognitive_complexity += nesting_level
            
            # Decrease nesting
            elif any(keyword in line for keyword in ['else', 'elif', 'except', 'finally']):
                nesting_level = max(0, nesting_level - 1)
            
            # Logical operators
            if 'and' in line or 'or' in line:
                cognitive_complexity += 1
        
        return cognitive_complexity
    
    def _calculate_maintainability_index(self, content: str) -> float:
        """Calculate maintainability index."""
        # Simplified maintainability index calculation
        lines = content.split('\n')
        total_lines = len(lines)
        
        if total_lines == 0:
            return 100.0
        
        # Calculate various factors
        comment_ratio = self._calculate_comment_ratio(content)
        function_count = len(re.findall(r'def\s+\w+', content))
        class_count = len(re.findall(r'class\s+\w+', content))
        
        # Calculate maintainability score
        maintainability = 100.0
        
        # Penalize for long files
        if total_lines > 500:
            maintainability -= 20
        elif total_lines > 200:
            maintainability -= 10
        
        # Reward for comments
        maintainability += comment_ratio * 10
        
        # Penalize for too many functions in one file
        if function_count > 20:
            maintainability -= 15
        elif function_count > 10:
            maintainability -= 5
        
        # Penalize for too many classes in one file
        if class_count > 5:
            maintainability -= 10
        elif class_count > 2:
            maintainability -= 5
        
        return max(0.0, min(100.0, maintainability))
    
    def _calculate_comment_ratio(self, content: str) -> float:
        """Calculate comment ratio."""
        lines = content.split('\n')
        if not lines:
            return 0.0
        
        comment_lines = sum(1 for line in lines if line.strip().startswith('#') or line.strip().startswith('//'))
        return comment_lines / len(lines)
    
    def _calculate_file_technical_debt(self, content: str) -> float:
        """Calculate technical debt for a file."""
        technical_debt = 0.0
        
        # Code smells
        code_smells = self._detect_code_smells(content)
        technical_debt += len(code_smells) * 0.1
        
        # Complexity
        complexity = self._calculate_cyclomatic_complexity(content)
        if complexity > 20:
            technical_debt += (complexity - 20) * 0.05
        
        # Duplicate code
        duplicate_ratio = self._calculate_duplicate_ratio(content)
        technical_debt += duplicate_ratio * 0.2
        
        # Missing documentation
        doc_ratio = self._calculate_documentation_ratio(content)
        if doc_ratio < 0.1:
            technical_debt += 0.3
        
        return min(1.0, technical_debt)
    
    def _detect_code_smells(self, content: str) -> List[str]:
        """Detect code smells."""
        smells = []
        
        # Long method
        if len(content.split('\n')) > 50:
            smells.append('long_method')
        
        # Magic numbers
        magic_numbers = re.findall(r'\b\d{3,}\b', content)
        if len(magic_numbers) > 5:
            smells.append('magic_numbers')
        
        # Deep nesting
        max_nesting = self._calculate_max_nesting(content)
        if max_nesting > 4:
            smells.append('deep_nesting')
        
        # Duplicate code (simplified)
        duplicate_ratio = self._calculate_duplicate_ratio(content)
        if duplicate_ratio > 0.3:
            smells.append('duplicate_code')
        
        return smells
    
    def _calculate_max_nesting(self, content: str) -> int:
        """Calculate maximum nesting level."""
        lines = content.split('\n')
        max_nesting = 0
        current_nesting = 0
        
        for line in lines:
            line = line.strip()
            
            # Increase nesting
            if any(keyword in line for keyword in ['if', 'for', 'while', 'try', 'with']):
                current_nesting += 1
                max_nesting = max(max_nesting, current_nesting)
            
            # Decrease nesting
            elif any(keyword in line for keyword in ['else', 'elif', 'except', 'finally']):
                current_nesting = max(0, current_nesting - 1)
        
        return max_nesting
    
    def _calculate_duplicate_ratio(self, content: str) -> float:
        """Calculate duplicate code ratio."""
        lines = content.split('\n')
        if len(lines) < 2:
            return 0.0
        
        # Simple duplicate detection
        line_counts = Counter(lines)
        duplicate_lines = sum(count - 1 for count in line_counts.values() if count > 1)
        
        return duplicate_lines / len(lines)
    
    def _calculate_documentation_ratio(self, content: str) -> float:
        """Calculate documentation ratio."""
        lines = content.split('\n')
        if not lines:
            return 0.0
        
        doc_lines = sum(1 for line in lines if line.strip().startswith('#') or line.strip().startswith('//'))
        return doc_lines / len(lines)
    
    def _calculate_quality_metrics(self, files: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate overall quality metrics."""
        metrics = {
            'total_lines': 0,
            'total_functions': 0,
            'total_classes': 0,
            'comment_ratio': 0.0,
            'complexity_avg': 0.0,
            'maintainability_avg': 0.0,
            'technical_debt_avg': 0.0
        }
        
        if not files:
            return metrics
        
        total_complexity = 0.0
        total_maintainability = 0.0
        total_technical_debt = 0.0
        total_comment_ratio = 0.0
        
        for file_data in files:
            content = file_data.get('content', '')
            if not content:
                continue
            
            lines = content.split('\n')
            metrics['total_lines'] += len(lines)
            metrics['total_functions'] += len(re.findall(r'def\s+\w+', content))
            metrics['total_classes'] += len(re.findall(r'class\s+\w+', content))
            
            # Calculate metrics
            complexity = self._calculate_cyclomatic_complexity(content)
            maintainability = self._calculate_maintainability_index(content)
            technical_debt = self._calculate_file_technical_debt(content)
            comment_ratio = self._calculate_comment_ratio(content)
            
            total_complexity += complexity
            total_maintainability += maintainability
            total_technical_debt += technical_debt
            total_comment_ratio += comment_ratio
        
        # Calculate averages
        file_count = len([f for f in files if f.get('content')])
        if file_count > 0:
            metrics['complexity_avg'] = total_complexity / file_count
            metrics['maintainability_avg'] = total_maintainability / file_count
            metrics['technical_debt_avg'] = total_technical_debt / file_count
            metrics['comment_ratio'] = total_comment_ratio / file_count
        
        return metrics
    
    def _calculate_technical_debt(self, files: List[Dict[str, Any]], complexity_analyses: List[ComplexityAnalysis]) -> float:
        """Calculate overall technical debt."""
        if not complexity_analyses:
            return 0.0
        
        total_debt = sum(analysis.technical_debt for analysis in complexity_analyses)
        return total_debt / len(complexity_analyses)
    
    def _generate_recommendations(self, code_evolutions: List[CodeEvolution], 
                                complexity_analyses: List[ComplexityAnalysis], 
                                quality_metrics: Dict[str, float]) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        # Complexity recommendations
        high_complexity_files = [analysis for analysis in complexity_analyses 
                               if analysis.cyclomatic_complexity > 20]
        if high_complexity_files:
            recommendations.append(f"Refactor {len(high_complexity_files)} files with high complexity")
        
        # Maintainability recommendations
        low_maintainability_files = [analysis for analysis in complexity_analyses 
                                   if analysis.maintainability_index < 20]
        if low_maintainability_files:
            recommendations.append(f"Improve maintainability of {len(low_maintainability_files)} files")
        
        # Technical debt recommendations
        if quality_metrics.get('technical_debt_avg', 0) > 0.5:
            recommendations.append("Address high technical debt across the codebase")
        
        # Evolution recommendations
        for evolution in code_evolutions:
            if evolution.trend == 'increasing' and evolution.evolution_type == 'complexity':
                recommendations.append(f"Monitor complexity increase in {evolution.file_path}")
        
        # Quality recommendations
        if quality_metrics.get('comment_ratio', 0) < 0.1:
            recommendations.append("Improve code documentation")
        
        if quality_metrics.get('complexity_avg', 0) > 15:
            recommendations.append("Reduce overall code complexity")
        
        return recommendations
    
    def _generate_complexity_recommendations(self, cyclomatic: float, cognitive: float, maintainability: float) -> List[str]:
        """Generate recommendations for complexity issues."""
        recommendations = []
        
        if cyclomatic > 20:
            recommendations.append("Break down complex functions into smaller ones")
        
        if cognitive > 25:
            recommendations.append("Simplify conditional logic and reduce nesting")
        
        if maintainability < 20:
            recommendations.append("Improve code structure and add documentation")
        
        return recommendations
    
    # Helper methods for historical analysis
    def _get_historical_complexity(self, file_path: str) -> Optional[float]:
        """Get historical complexity for a file."""
        # This would typically query a database or file system
        # For now, return None to indicate no historical data
        return None
    
    def _get_historical_security_patterns(self, file_path: str) -> Optional[List[str]]:
        """Get historical security patterns for a file."""
        # This would typically query a database or file system
        # For now, return None to indicate no historical data
        return None
    
    def _get_historical_quality(self, file_path: str) -> Optional[float]:
        """Get historical quality for a file."""
        # This would typically query a database or file system
        # For now, return None to indicate no historical data
        return None
    
    def _detect_security_patterns(self, content: str) -> List[str]:
        """Detect security patterns in content."""
        patterns = []
        
        security_patterns = {
            'hardcoded_secrets': r'password\s*=\s*["\'][^"\']+["\']',
            'sql_injection': r'SELECT.*\+.*WHERE',
            'xss': r'innerHTML\s*=',
            'path_traversal': r'\.\./',
            'weak_crypto': r'MD5\s*\(',
            'insecure_redirect': r'redirect\s*\(.*request\.'
        }
        
        for pattern_name, pattern in security_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                patterns.append(pattern_name)
        
        return patterns
    
    def _calculate_complexity_trend(self, current: float, historical: float) -> str:
        """Calculate complexity trend."""
        if current > historical * 1.2:
            return 'increasing'
        elif current < historical * 0.8:
            return 'decreasing'
        else:
            return 'stable'
    
    def _calculate_quality_trend(self, current: float, historical: float) -> str:
        """Calculate quality trend."""
        if current > historical * 1.1:
            return 'improving'
        elif current < historical * 0.9:
            return 'degrading'
        else:
            return 'stable'
    
    def _calculate_pattern_changes(self, current: List[str], historical: List[str]) -> List[str]:
        """Calculate pattern changes."""
        current_set = set(current)
        historical_set = set(historical)
        
        added = list(current_set - historical_set)
        removed = list(historical_set - current_set)
        
        changes = []
        if added:
            changes.append(f"Added: {', '.join(added)}")
        if removed:
            changes.append(f"Removed: {', '.join(removed)}")
        
        return changes
