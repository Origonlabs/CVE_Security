"""
Dependency Analysis with Vulnerability Graph.

This module implements advanced dependency analysis including:
- Vulnerability graph construction
- Attack path analysis
- Dependency risk assessment
- Supply chain analysis
- Transitive vulnerability detection
"""

import networkx as nx
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


@dataclass
class DependencyNode:
    """Represents a dependency in the graph."""
    name: str
    version: str
    package_type: str
    vulnerabilities: List[Dict[str, Any]]
    risk_score: float
    metadata: Dict[str, Any]


@dataclass
class VulnerabilityEdge:
    """Represents a vulnerability relationship between dependencies."""
    source: str
    target: str
    vulnerability_type: str
    severity: str
    exploitability: float
    impact: float
    metadata: Dict[str, Any]


@dataclass
class AttackPath:
    """Represents an attack path through dependencies."""
    path_id: str
    nodes: List[str]
    vulnerabilities: List[str]
    total_risk: float
    exploitability: float
    impact: float
    description: str


@dataclass
class DependencyAnalysis:
    """Represents complete dependency analysis results."""
    total_dependencies: int
    vulnerable_dependencies: int
    critical_paths: List[AttackPath]
    risk_distribution: Dict[str, int]
    recommendations: List[str]
    graph_metrics: Dict[str, float]


class DependencyAnalyzer:
    """
    Advanced dependency analyzer with vulnerability graph construction.
    
    Features:
    - Builds dependency graphs with vulnerability relationships
    - Identifies attack paths and critical vulnerabilities
    - Analyzes supply chain risks
    - Detects transitive vulnerabilities
    - Provides risk-based recommendations
    """
    
    def __init__(self, vulnerability_db_path: Optional[str] = None):
        """Initialize the dependency analyzer."""
        self.vulnerability_db_path = vulnerability_db_path or "data/vulnerability_db.json"
        self.graph = nx.DiGraph()
        self.vulnerability_db = {}
        self.package_registries = {
            'npm': 'https://registry.npmjs.org',
            'pypi': 'https://pypi.org',
            'maven': 'https://repo1.maven.org/maven2',
            'nuget': 'https://api.nuget.org/v3',
            'cargo': 'https://crates.io',
            'composer': 'https://packagist.org'
        }
        
        # Risk scoring weights
        self.risk_weights = {
            'severity': {'CRITICAL': 1.0, 'HIGH': 0.8, 'MEDIUM': 0.6, 'LOW': 0.4},
            'exploitability': {'HIGH': 1.0, 'MEDIUM': 0.6, 'LOW': 0.3},
            'impact': {'HIGH': 1.0, 'MEDIUM': 0.6, 'LOW': 0.3},
            'age': {'recent': 1.0, 'moderate': 0.7, 'old': 0.4},
            'popularity': {'high': 0.3, 'medium': 0.6, 'low': 1.0}
        }
        
        self._load_vulnerability_db()
    
    def _load_vulnerability_db(self):
        """Load vulnerability database."""
        try:
            if Path(self.vulnerability_db_path).exists():
                with open(self.vulnerability_db_path, 'r') as f:
                    self.vulnerability_db = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load vulnerability database: {e}")
            self.vulnerability_db = {}
    
    def _save_vulnerability_db(self):
        """Save vulnerability database."""
        try:
            Path(self.vulnerability_db_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.vulnerability_db_path, 'w') as f:
                json.dump(self.vulnerability_db, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save vulnerability database: {e}")
    
    def analyze_dependencies(self, repo_data: Dict[str, Any]) -> DependencyAnalysis:
        """Perform comprehensive dependency analysis."""
        # Extract dependencies from repository
        dependencies = self._extract_dependencies(repo_data)
        
        # Build dependency graph
        self._build_dependency_graph(dependencies)
        
        # Identify vulnerabilities
        self._identify_vulnerabilities(dependencies)
        
        # Find attack paths
        attack_paths = self._find_attack_paths()
        
        # Calculate risk distribution
        risk_distribution = self._calculate_risk_distribution()
        
        # Generate recommendations
        recommendations = self._generate_recommendations(attack_paths, risk_distribution)
        
        # Calculate graph metrics
        graph_metrics = self._calculate_graph_metrics()
        
        return DependencyAnalysis(
            total_dependencies=len(dependencies),
            vulnerable_dependencies=len([d for d in dependencies if d.get('vulnerabilities')]),
            critical_paths=attack_paths,
            risk_distribution=risk_distribution,
            recommendations=recommendations,
            graph_metrics=graph_metrics
        )
    
    def _extract_dependencies(self, repo_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract dependencies from repository data."""
        dependencies = []
        
        # Extract from different package managers
        package_managers = ['npm', 'pip', 'maven', 'gradle', 'cargo', 'composer', 'nuget']
        
        for pm in package_managers:
            pm_deps = repo_data.get(f'{pm}_dependencies', [])
            for dep in pm_deps:
                dep_data = {
                    'name': dep.get('name', ''),
                    'version': dep.get('version', ''),
                    'package_type': pm,
                    'source': dep.get('source', ''),
                    'dependencies': dep.get('dependencies', []),
                    'metadata': dep.get('metadata', {})
                }
                dependencies.append(dep_data)
        
        # Extract from lock files
        lock_files = ['package-lock.json', 'yarn.lock', 'Pipfile.lock', 'poetry.lock', 'Cargo.lock']
        for lock_file in lock_files:
            lock_data = repo_data.get(lock_file, {})
            if lock_data:
                deps = self._parse_lock_file(lock_file, lock_data)
                dependencies.extend(deps)
        
        return dependencies
    
    def _parse_lock_file(self, lock_file: str, lock_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse lock file to extract dependencies."""
        dependencies = []
        
        if lock_file.endswith('package-lock.json'):
            # NPM lock file
            deps = lock_data.get('dependencies', {})
            for name, dep_info in deps.items():
                dependencies.append({
                    'name': name,
                    'version': dep_info.get('version', ''),
                    'package_type': 'npm',
                    'source': 'package-lock.json',
                    'dependencies': list(dep_info.get('dependencies', {}).keys()),
                    'metadata': dep_info
                })
        
        elif lock_file.endswith('Pipfile.lock'):
            # Pipenv lock file
            deps = lock_data.get('default', {})
            for name, dep_info in deps.items():
                dependencies.append({
                    'name': name,
                    'version': dep_info.get('version', ''),
                    'package_type': 'pip',
                    'source': 'Pipfile.lock',
                    'dependencies': [],
                    'metadata': dep_info
                })
        
        elif lock_file.endswith('Cargo.lock'):
            # Cargo lock file
            packages = lock_data.get('package', [])
            for package in packages:
                dependencies.append({
                    'name': package.get('name', ''),
                    'version': package.get('version', ''),
                    'package_type': 'cargo',
                    'source': 'Cargo.lock',
                    'dependencies': [dep.get('name', '') for dep in package.get('dependencies', [])],
                    'metadata': package
                })
        
        return dependencies
    
    def _build_dependency_graph(self, dependencies: List[Dict[str, Any]]):
        """Build dependency graph with relationships."""
        self.graph.clear()
        
        # Add nodes
        for dep in dependencies:
            node_id = f"{dep['name']}@{dep['version']}"
            self.graph.add_node(node_id, **dep)
        
        # Add edges (dependency relationships)
        for dep in dependencies:
            source_id = f"{dep['name']}@{dep['version']}"
            for sub_dep in dep.get('dependencies', []):
                target_id = f"{sub_dep}@{dep.get('version', 'latest')}"
                if self.graph.has_node(target_id):
                    self.graph.add_edge(source_id, target_id, relationship='depends_on')
    
    def _identify_vulnerabilities(self, dependencies: List[Dict[str, Any]]):
        """Identify vulnerabilities in dependencies."""
        for dep in dependencies:
            node_id = f"{dep['name']}@{dep['version']}"
            if self.graph.has_node(node_id):
                vulnerabilities = self._get_vulnerabilities(dep['name'], dep['version'], dep['package_type'])
                self.graph.nodes[node_id]['vulnerabilities'] = vulnerabilities
                self.graph.nodes[node_id]['risk_score'] = self._calculate_dependency_risk_score(vulnerabilities)
    
    def _get_vulnerabilities(self, package_name: str, version: str, package_type: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a specific package."""
        # Check local database first
        key = f"{package_type}:{package_name}:{version}"
        if key in self.vulnerability_db:
            return self.vulnerability_db[key]
        
        # Fetch from external sources
        vulnerabilities = []
        
        # NVD API
        nvd_vulns = self._fetch_nvd_vulnerabilities(package_name, package_type)
        vulnerabilities.extend(nvd_vulns)
        
        # Package-specific vulnerability databases
        if package_type == 'npm':
            npm_vulns = self._fetch_npm_vulnerabilities(package_name, version)
            vulnerabilities.extend(npm_vulns)
        elif package_type == 'pip':
            pip_vulns = self._fetch_pip_vulnerabilities(package_name, version)
            vulnerabilities.extend(pip_vulns)
        
        # Cache results
        self.vulnerability_db[key] = vulnerabilities
        self._save_vulnerability_db()
        
        return vulnerabilities
    
    def _fetch_nvd_vulnerabilities(self, package_name: str, package_type: str) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from NVD."""
        vulnerabilities = []
        
        try:
            # NVD API endpoint
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': package_name,
                'resultsPerPage': 100
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for cve in data.get('vulnerabilities', []):
                    vuln_data = cve.get('cve', {})
                    vulnerabilities.append({
                        'id': vuln_data.get('id', ''),
                        'severity': self._extract_severity(vuln_data),
                        'description': vuln_data.get('descriptions', [{}])[0].get('value', ''),
                        'published': vuln_data.get('published', ''),
                        'source': 'NVD'
                    })
        except Exception as e:
            print(f"Warning: Could not fetch NVD vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _fetch_npm_vulnerabilities(self, package_name: str, version: str) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from npm audit."""
        vulnerabilities = []
        
        try:
            # Use npm audit API
            url = f"https://registry.npmjs.org/-/npm/v1/security/audits"
            payload = {
                'name': package_name,
                'version': version
            }
            
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    vulnerabilities.append({
                        'id': vuln.get('id', ''),
                        'severity': vuln.get('severity', 'MEDIUM'),
                        'description': vuln.get('description', ''),
                        'published': vuln.get('published', ''),
                        'source': 'npm'
                    })
        except Exception as e:
            print(f"Warning: Could not fetch npm vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _fetch_pip_vulnerabilities(self, package_name: str, version: str) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from PyPI security."""
        vulnerabilities = []
        
        try:
            # Use safety-db or similar
            url = f"https://pypi.org/pypi/{package_name}/{version}/json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                # Check for known vulnerabilities
                # This is a simplified implementation
                if 'vulnerabilities' in data:
                    for vuln in data['vulnerabilities']:
                        vulnerabilities.append({
                            'id': vuln.get('id', ''),
                            'severity': vuln.get('severity', 'MEDIUM'),
                            'description': vuln.get('description', ''),
                            'published': vuln.get('published', ''),
                            'source': 'PyPI'
                        })
        except Exception as e:
            print(f"Warning: Could not fetch pip vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _extract_severity(self, cve_data: Dict[str, Any]) -> str:
        """Extract severity from CVE data."""
        metrics = cve_data.get('metrics', {})
        
        # Check CVSS v3.1
        if 'cvssMetricV31' in metrics:
            cvss = metrics['cvssMetricV31'][0].get('cvssData', {})
            base_score = cvss.get('baseScore', 0)
            if base_score >= 9.0:
                return 'CRITICAL'
            elif base_score >= 7.0:
                return 'HIGH'
            elif base_score >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        
        # Check CVSS v3.0
        elif 'cvssMetricV30' in metrics:
            cvss = metrics['cvssMetricV30'][0].get('cvssData', {})
            base_score = cvss.get('baseScore', 0)
            if base_score >= 9.0:
                return 'CRITICAL'
            elif base_score >= 7.0:
                return 'HIGH'
            elif base_score >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        
        # Check CVSS v2
        elif 'cvssMetricV2' in metrics:
            cvss = metrics['cvssMetricV2'][0].get('cvssData', {})
            base_score = cvss.get('baseScore', 0)
            if base_score >= 7.0:
                return 'HIGH'
            elif base_score >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        
        return 'UNKNOWN'
    
    def _calculate_dependency_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate risk score for a dependency."""
        if not vulnerabilities:
            return 0.0
        
        total_score = 0.0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            severity_weight = self.risk_weights['severity'].get(severity, 0.5)
            
            # Age factor
            published = vuln.get('published', '')
            age_factor = self._calculate_age_factor(published)
            
            # Exploitability factor (simplified)
            exploitability = self._estimate_exploitability(vuln)
            
            # Impact factor (simplified)
            impact = self._estimate_impact(vuln)
            
            vuln_score = severity_weight * age_factor * exploitability * impact
            total_score += vuln_score
        
        return min(1.0, total_score / len(vulnerabilities))
    
    def _calculate_age_factor(self, published: str) -> float:
        """Calculate age factor for vulnerability."""
        if not published:
            return 0.5
        
        try:
            pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
            age_days = (datetime.now() - pub_date.replace(tzinfo=None)).days
            
            if age_days < 30:
                return 1.0  # Recent
            elif age_days < 365:
                return 0.7  # Moderate
            else:
                return 0.4  # Old
        except:
            return 0.5
    
    def _estimate_exploitability(self, vuln: Dict[str, Any]) -> float:
        """Estimate exploitability of vulnerability."""
        description = vuln.get('description', '').lower()
        
        # High exploitability indicators
        if any(keyword in description for keyword in ['remote', 'unauthenticated', 'buffer overflow', 'injection']):
            return 1.0
        
        # Medium exploitability indicators
        elif any(keyword in description for keyword in ['authenticated', 'local', 'privilege']):
            return 0.6
        
        # Low exploitability indicators
        else:
            return 0.3
    
    def _estimate_impact(self, vuln: Dict[str, Any]) -> float:
        """Estimate impact of vulnerability."""
        description = vuln.get('description', '').lower()
        
        # High impact indicators
        if any(keyword in description for keyword in ['code execution', 'arbitrary', 'complete', 'total']):
            return 1.0
        
        # Medium impact indicators
        elif any(keyword in description for keyword in ['information disclosure', 'denial of service', 'elevation']):
            return 0.6
        
        # Low impact indicators
        else:
            return 0.3
    
    def _find_attack_paths(self) -> List[AttackPath]:
        """Find critical attack paths through dependency graph."""
        attack_paths = []
        
        # Find all paths from vulnerable dependencies to critical nodes
        vulnerable_nodes = [node for node, data in self.graph.nodes(data=True) 
                          if data.get('vulnerabilities') and data.get('risk_score', 0) > 0.5]
        
        critical_nodes = [node for node, data in self.graph.nodes(data=True) 
                         if data.get('risk_score', 0) > 0.8]
        
        for vuln_node in vulnerable_nodes:
            for critical_node in critical_nodes:
                if vuln_node != critical_node:
                    try:
                        paths = list(nx.all_simple_paths(self.graph, vuln_node, critical_node, cutoff=5))
                        for path in paths:
                            attack_path = self._create_attack_path(path)
                            if attack_path:
                                attack_paths.append(attack_path)
                    except nx.NetworkXNoPath:
                        continue
        
        # Sort by total risk
        attack_paths.sort(key=lambda x: x.total_risk, reverse=True)
        
        return attack_paths[:10]  # Return top 10 attack paths
    
    def _create_attack_path(self, path: List[str]) -> Optional[AttackPath]:
        """Create attack path from node path."""
        if len(path) < 2:
            return None
        
        vulnerabilities = []
        total_risk = 0.0
        exploitability = 0.0
        impact = 0.0
        
        for node in path:
            node_data = self.graph.nodes[node]
            node_vulns = node_data.get('vulnerabilities', [])
            vulnerabilities.extend([v.get('id', '') for v in node_vulns])
            total_risk += node_data.get('risk_score', 0)
            exploitability += self._estimate_exploitability(node_vulns[0]) if node_vulns else 0
            impact += self._estimate_impact(node_vulns[0]) if node_vulns else 0
        
        return AttackPath(
            path_id=f"path_{len(path)}_{hash(tuple(path))}",
            nodes=path,
            vulnerabilities=vulnerabilities,
            total_risk=total_risk / len(path),
            exploitability=exploitability / len(path),
            impact=impact / len(path),
            description=f"Attack path through {len(path)} dependencies"
        )
    
    def _calculate_risk_distribution(self) -> Dict[str, int]:
        """Calculate risk distribution across dependencies."""
        distribution = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NONE': 0}
        
        for node, data in self.graph.nodes(data=True):
            risk_score = data.get('risk_score', 0)
            if risk_score >= 0.8:
                distribution['CRITICAL'] += 1
            elif risk_score >= 0.6:
                distribution['HIGH'] += 1
            elif risk_score >= 0.4:
                distribution['MEDIUM'] += 1
            elif risk_score > 0:
                distribution['LOW'] += 1
            else:
                distribution['NONE'] += 1
        
        return distribution
    
    def _generate_recommendations(self, attack_paths: List[AttackPath], risk_distribution: Dict[str, int]) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        # Critical vulnerabilities
        if risk_distribution.get('CRITICAL', 0) > 0:
            recommendations.append("Address critical vulnerabilities immediately")
        
        # High-risk attack paths
        if attack_paths and attack_paths[0].total_risk > 0.8:
            recommendations.append("Break critical attack paths by updating vulnerable dependencies")
        
        # Supply chain risks
        if len(attack_paths) > 5:
            recommendations.append("Reduce supply chain complexity by minimizing dependencies")
        
        # Outdated dependencies
        outdated_count = sum(1 for node, data in self.graph.nodes(data=True) 
                           if data.get('metadata', {}).get('outdated', False))
        if outdated_count > 0:
            recommendations.append(f"Update {outdated_count} outdated dependencies")
        
        # Transitive vulnerabilities
        transitive_vulns = self._count_transitive_vulnerabilities()
        if transitive_vulns > 0:
            recommendations.append(f"Address {transitive_vulns} transitive vulnerabilities")
        
        return recommendations
    
    def _count_transitive_vulnerabilities(self) -> int:
        """Count transitive vulnerabilities."""
        count = 0
        for node, data in self.graph.nodes(data=True):
            if data.get('vulnerabilities') and len(list(self.graph.predecessors(node))) > 0:
                count += 1
        return count
    
    def _calculate_graph_metrics(self) -> Dict[str, float]:
        """Calculate graph metrics."""
        if not self.graph.nodes():
            return {}
        
        metrics = {
            'total_nodes': len(self.graph.nodes()),
            'total_edges': len(self.graph.edges()),
            'density': nx.density(self.graph),
            'average_clustering': nx.average_clustering(self.graph.to_undirected()),
            'diameter': nx.diameter(self.graph.to_undirected()) if nx.is_connected(self.graph.to_undirected()) else 0,
            'average_path_length': nx.average_shortest_path_length(self.graph.to_undirected()) if nx.is_connected(self.graph.to_undirected()) else 0
        }
        
        return metrics
    
    def get_dependency_graph(self) -> nx.DiGraph:
        """Get the dependency graph."""
        return self.graph
    
    def export_graph(self, format: str = 'json') -> str:
        """Export dependency graph in specified format."""
        if format == 'json':
            return json.dumps(nx.node_link_data(self.graph), indent=2)
        elif format == 'graphml':
            return '\n'.join(nx.generate_graphml(self.graph))
        elif format == 'gexf':
            return '\n'.join(nx.generate_gexf(self.graph))
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def visualize_graph(self, output_path: str = "dependency_graph.png"):
        """Visualize dependency graph."""
        try:
            import matplotlib.pyplot as plt
            import matplotlib.patches as mpatches
            
            plt.figure(figsize=(20, 16))
            pos = nx.spring_layout(self.graph, k=3, iterations=50)
            
            # Color nodes by risk score
            node_colors = []
            for node, data in self.graph.nodes(data=True):
                risk_score = data.get('risk_score', 0)
                if risk_score >= 0.8:
                    node_colors.append('red')
                elif risk_score >= 0.6:
                    node_colors.append('orange')
                elif risk_score >= 0.4:
                    node_colors.append('yellow')
                else:
                    node_colors.append('green')
            
            # Draw nodes
            nx.draw_networkx_nodes(self.graph, pos, node_color=node_colors, 
                                 node_size=500, alpha=0.7)
            
            # Draw edges
            nx.draw_networkx_edges(self.graph, pos, alpha=0.5, edge_color='gray')
            
            # Draw labels
            labels = {node: node.split('@')[0] for node in self.graph.nodes()}
            nx.draw_networkx_labels(self.graph, pos, labels, font_size=8)
            
            # Add legend
            legend_elements = [
                mpatches.Patch(color='red', label='Critical Risk'),
                mpatches.Patch(color='orange', label='High Risk'),
                mpatches.Patch(color='yellow', label='Medium Risk'),
                mpatches.Patch(color='green', label='Low Risk')
            ]
            plt.legend(handles=legend_elements, loc='upper right')
            
            plt.title('Dependency Vulnerability Graph')
            plt.axis('off')
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
        except ImportError:
            print("Warning: matplotlib not available for graph visualization")
        except Exception as e:
            print(f"Warning: Could not create graph visualization: {e}")
