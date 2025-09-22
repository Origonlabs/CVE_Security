"""
Main orchestrator for coordinating security scans.
"""

import asyncio
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import git
from git import Repo

from .core.config import Config
from .core.exceptions import RepoScanError, ScannerError
from .core.models import (
    Finding,
    FindingType,
    Repository,
    ScanConfig,
    ScanResult,
    Severity,
    TechStack,
)
from .detectors.base import BaseDetector
from .detectors.registry import DetectorRegistry
from .scoring import RiskScorer
from .utils import (
    detect_tech_stack,
    generate_scan_id,
    get_repository_info,
    is_git_repository,
    normalize_path,
)


class ScanOrchestrator:
    """
    Main orchestrator for coordinating security scans across multiple detectors.
    """
    
    def __init__(self, config: Config) -> None:
        """Initialize the scan orchestrator."""
        self.config = config
        self.detector_registry = DetectorRegistry()
        self.risk_scorer = RiskScorer(config)
        self._workspace_dir = Path(config.workspace_dir)
        self._workspace_dir.mkdir(parents=True, exist_ok=True)
    
    def scan_repository(
        self,
        repo_path: Optional[str] = None,
        repo_url: Optional[str] = None,
        branch: Optional[str] = None,
        scanners: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
        timeout: int = 3600,
        parallel: bool = True,
    ) -> ScanResult:
        """
        Scan a repository for security vulnerabilities.
        
        Args:
            repo_path: Path to local repository
            repo_url: URL of remote repository to clone
            branch: Branch to scan
            scanners: List of specific scanners to run
            exclude_patterns: Patterns to exclude from scanning
            include_patterns: Patterns to include in scanning
            timeout: Scan timeout in seconds
            parallel: Whether to run scanners in parallel
            
        Returns:
            ScanResult containing all findings and metadata
        """
        scan_id = generate_scan_id()
        start_time = datetime.utcnow()
        
        try:
            # Prepare repository
            if repo_url:
                repo_path = self._clone_repository(repo_url, branch, scan_id)
            elif repo_path:
                repo_path = normalize_path(repo_path)
            else:
                raise RepoScanError("Either repo_path or repo_url must be provided")
            
            # Get repository information
            repo_info = get_repository_info(repo_path)
            tech_stack_data = detect_tech_stack(repo_path)
            
            repository = Repository(
                path=repo_path,
                url=repo_info.get("url"),
                branch=repo_info.get("branch") or branch,
                commit_hash=repo_info.get("commit_hash"),
                tech_stack=TechStack(**tech_stack_data),
                size_bytes=repo_info.get("size_bytes"),
                file_count=repo_info.get("file_count"),
                last_modified=repo_info.get("last_modified"),
                gpg_verified=False,  # TODO: Implement GPG verification
            )
            
            # Create scan configuration
            scan_config = ScanConfig(
                repository=repository,
                enabled_scanners=scanners or self._get_enabled_scanners(),
                exclude_patterns=exclude_patterns or [],
                include_patterns=include_patterns or [],
                timeout=timeout,
                parallel_scans=parallel,
            )
            
            # Run scanners
            if parallel:
                findings = self._run_scanners_parallel(scan_config)
            else:
                findings = self._run_scanners_sequential(scan_config)
            
            # Calculate risk score
            risk_score = self.risk_scorer.calculate_repository_risk_score(findings)
            risk_level = self._determine_risk_level(risk_score)
            
            # Create scan result
            end_time = datetime.utcnow()
            scan_duration = (end_time - start_time).total_seconds()
            
            result = ScanResult(
                scan_id=scan_id,
                repository=repository,
                config=scan_config,
                findings=findings,
                risk_score=risk_score,
                risk_level=risk_level,
                scan_duration=scan_duration,
                started_at=start_time,
                completed_at=end_time,
                success=True,
            )
            
            return result
            
        except Exception as e:
            end_time = datetime.utcnow()
            scan_duration = (end_time - start_time).total_seconds()
            
            # Create failed result
            result = ScanResult(
                scan_id=scan_id,
                repository=Repository(path=repo_path or repo_url or "unknown"),
                config=ScanConfig(repository=Repository(path=repo_path or repo_url or "unknown")),
                findings=[],
                risk_score=0.0,
                risk_level="UNKNOWN",
                scan_duration=scan_duration,
                started_at=start_time,
                completed_at=end_time,
                success=False,
                error_message=str(e),
            )
            
            raise RepoScanError(f"Scan failed: {e}") from e
        
        finally:
            # Cleanup temporary repository if cloned
            if repo_url and repo_path and Path(repo_path).exists():
                try:
                    shutil.rmtree(repo_path)
                except Exception:
                    pass  # Ignore cleanup errors
    
    def _clone_repository(self, repo_url: str, branch: Optional[str], scan_id: str) -> str:
        """Clone a remote repository."""
        try:
            # Create temporary directory for this scan
            temp_dir = self._workspace_dir / scan_id
            temp_dir.mkdir(parents=True, exist_ok=True)
            
            # Clone repository
            clone_kwargs = {
                "url": repo_url,
                "to_path": temp_dir,
                "depth": 1,  # Shallow clone for faster download
            }
            
            if branch:
                clone_kwargs["branch"] = branch
            
            repo = Repo.clone_from(**clone_kwargs)
            
            return str(temp_dir)
            
        except git.GitError as e:
            raise RepoScanError(f"Failed to clone repository {repo_url}: {e}") from e
    
    def _get_enabled_scanners(self) -> List[str]:
        """Get list of enabled scanners based on configuration."""
        enabled_scanners = []
        
        for scanner_name in self.detector_registry.list_detectors():
            if self.config.is_scanner_enabled(scanner_name):
                enabled_scanners.append(scanner_name)
        
        return enabled_scanners
    
    def _run_scanners_parallel(self, scan_config: ScanConfig) -> List[Finding]:
        """Run scanners in parallel."""
        findings = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all scanner tasks
            future_to_scanner = {}
            
            for scanner_name in scan_config.enabled_scanners:
                detector = self.detector_registry.get_detector(scanner_name)
                if detector:
                    future = executor.submit(
                        self._run_single_scanner,
                        detector,
                        scan_config
                    )
                    future_to_scanner[future] = scanner_name
            
            # Collect results as they complete
            for future in as_completed(future_to_scanner):
                scanner_name = future_to_scanner[future]
                try:
                    scanner_findings = future.result()
                    findings.extend(scanner_findings)
                except Exception as e:
                    # Log error but continue with other scanners
                    print(f"Scanner {scanner_name} failed: {e}")
                    continue
        
        return findings
    
    def _run_scanners_sequential(self, scan_config: ScanConfig) -> List[Finding]:
        """Run scanners sequentially."""
        findings = []
        
        for scanner_name in scan_config.enabled_scanners:
            detector = self.detector_registry.get_detector(scanner_name)
            if detector:
                try:
                    scanner_findings = self._run_single_scanner(detector, scan_config)
                    findings.extend(scanner_findings)
                except Exception as e:
                    # Log error but continue with other scanners
                    print(f"Scanner {scanner_name} failed: {e}")
                    continue
        
        return findings
    
    def _run_single_scanner(
        self, detector: BaseDetector, scan_config: ScanConfig
    ) -> List[Finding]:
        """Run a single scanner against the repository."""
        try:
            # Check if scanner is available
            if not detector.is_available():
                raise ScannerError(
                    detector.name,
                    f"Scanner {detector.name} is not available on this system"
                )
            
            # Run the scanner
            findings = detector.scan(scan_config)
            
            # Post-process findings
            processed_findings = []
            for finding in findings:
                # Calculate risk score for this finding
                finding.risk_score = self.risk_scorer.calculate_finding_risk_score(finding)
                processed_findings.append(finding)
            
            return processed_findings
            
        except Exception as e:
            raise ScannerError(detector.name, str(e)) from e
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score."""
        if risk_score >= 75:
            return "CRITICAL"
        elif risk_score >= 50:
            return "HIGH"
        elif risk_score >= 25:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_available_scanners(self) -> List[Dict[str, Any]]:
        """Get list of available scanners with metadata."""
        scanners = []
        
        for detector in self.detector_registry.list_detector_objects():
            scanners.append({
                "name": detector.name,
                "scanner_type": detector.scanner_type,
                "description": detector.description,
                "available": detector.is_available(),
                "enabled": self.config.is_scanner_enabled(detector.name),
            })
        
        return scanners

    def list_detectors(self) -> List[str]:
        """Return the registered detector names."""
        return self.detector_registry.list_detectors()

    def get_detector_info(self, detector_name: str) -> Optional[Dict[str, Any]]:
        """Expose detector metadata via the orchestrator."""
        detector = self.detector_registry.get_detector(detector_name)
        if not detector:
            return None
        return {
            "name": detector.name,
            "scanner_type": detector.scanner_type.value,
            "description": detector.description,
            "available": detector.is_available(),
            "enabled": self.config.is_scanner_enabled(detector.name),
            "required_dependencies": detector.get_required_dependencies(),
            "optional_dependencies": detector.get_optional_dependencies(),
        }
    
    def validate_scanner_configuration(self) -> Dict[str, List[str]]:
        """Validate scanner configuration and return issues."""
        issues = {
            "missing_dependencies": [],
            "configuration_errors": [],
            "permission_issues": [],
        }
        
        for detector in self.detector_registry.list_detector_objects():
            if not detector.is_available():
                issues["missing_dependencies"].append(detector.name)
            
            # Check configuration
            try:
                detector.validate_configuration()
            except Exception as e:
                issues["configuration_errors"].append(f"{detector.name}: {e}")
        
        return issues
    
    def get_scanner_statistics(self) -> Dict[str, Any]:
        """Get statistics about available scanners."""
        total_scanners = len(self.detector_registry.list_detectors())
        available_scanners = sum(
            1 for d in self.detector_registry.list_detector_objects()
            if d.is_available()
        )
        enabled_scanners = sum(
            1 for name in self.detector_registry.list_detectors()
            if self.config.is_scanner_enabled(name)
        )
        
        return {
            "total_scanners": total_scanners,
            "available_scanners": available_scanners,
            "enabled_scanners": enabled_scanners,
            "availability_rate": available_scanners / total_scanners if total_scanners > 0 else 0,
        }
