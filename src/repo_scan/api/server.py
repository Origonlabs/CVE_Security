"""FastAPI server implementation for repo-scan."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..core.config import Config, get_config
from ..core.models import ScanResult
from ..orchestrator import ScanOrchestrator
from ..report import ReportGenerator
from ..utils import generate_scan_id


class ScanRequest(BaseModel):
    """Payload accepted by the API to start a scan."""

    repo_path: Optional[str] = Field(None, description="Path to local repository")
    repo_url: Optional[str] = Field(None, description="Remote repository URL")
    branch: Optional[str] = Field(None, description="Branch to checkout when cloning a remote repository")
    scanners: Optional[List[str]] = Field(None, description="Explicit list of scanners to run")
    exclude_patterns: Optional[List[str]] = Field(None, description="Glob patterns to exclude")
    include_patterns: Optional[List[str]] = Field(None, description="Glob patterns to include")
    timeout: int = Field(3600, ge=60, description="Maximum scan duration in seconds")
    parallel: bool = Field(True, description="Run scanners in parallel")

    def resolve_scanners(self, orchestrator: ScanOrchestrator, config: Config) -> List[str]:
        available = {meta["name"] for meta in orchestrator.get_available_scanners()}
        if self.scanners:
            invalid = sorted(set(self.scanners) - available)
            if invalid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unknown scanners requested: {', '.join(invalid)}",
                )
            return self.scanners
        enabled = [name for name in available if config.is_scanner_enabled(name)]
        return enabled or list(available)


class ScanStatusResponse(BaseModel):
    """Status payload for a scan."""

    scan_id: str
    status: str
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    progress: int = 0
    error: Optional[str] = None


class ScanListResponse(BaseModel):
    """List response for scans."""

    scans: List[ScanStatusResponse]


class ScanResultResponse(BaseModel):
    """Complete scan result payload."""

    status: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class ScanJob:
    """Internal representation of an asynchronous scan."""

    def __init__(self, scan_id: str, request: ScanRequest) -> None:
        self.scan_id = scan_id
        self.request = request
        self.status = "queued"
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.finished_at: Optional[datetime] = None
        self.progress = 0
        self.result: Optional[ScanResult] = None
        self.error: Optional[str] = None
        self.future: Optional[asyncio.Future] = None

    def to_status(self) -> ScanStatusResponse:
        return ScanStatusResponse(
            scan_id=self.scan_id,
            status=self.status,
            created_at=self.created_at,
            started_at=self.started_at,
            finished_at=self.finished_at,
            progress=self.progress,
            error=self.error,
        )


class ScanManager:
    """Coordinates execution of scans on worker threads."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._orchestrator = ScanOrchestrator(config)
        self._executor = ThreadPoolExecutor(max_workers=max(4, config.max_workers))
        self._jobs: Dict[str, ScanJob] = {}
        self._jobs_lock = threading.Lock()
        self._report_generator = ReportGenerator()

    def list_jobs(self) -> List[ScanStatusResponse]:
        with self._jobs_lock:
            return [job.to_status() for job in self._jobs.values()]

    def list_available_scanners(self) -> List[Dict[str, Any]]:
        return self._orchestrator.get_available_scanners()

    def get_job(self, scan_id: str) -> ScanJob:
        with self._jobs_lock:
            job = self._jobs.get(scan_id)
            if not job:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
            return job

    async def submit(self, request: ScanRequest) -> ScanJob:
        scan_id = generate_scan_id()
        job = ScanJob(scan_id, request)
        with self._jobs_lock:
            self._jobs[scan_id] = job

        resolved_scanners = request.resolve_scanners(self._orchestrator, self._config)

        loop = asyncio.get_running_loop()
        job.status = "running"
        job.started_at = datetime.utcnow()
        job.progress = 10

        def _run() -> None:
            try:
                result = self._orchestrator.scan_repository(
                    repo_path=request.repo_path,
                    repo_url=request.repo_url,
                    branch=request.branch,
                    scanners=resolved_scanners,
                    exclude_patterns=request.exclude_patterns,
                    include_patterns=request.include_patterns,
                    timeout=request.timeout,
                    parallel=request.parallel,
                )
                job.progress = 95
                job.result = result
                job.status = "completed" if result.success else "failed"
                if not result.success:
                    job.error = result.error_message or "Scan reported failure"
            except Exception as exc:  # pylint: disable=broad-except
                job.status = "failed"
                job.error = str(exc)
            finally:
                if job.status in {"completed", "failed"}:
                    job.progress = 100
                job.finished_at = datetime.utcnow()

        job.future = loop.run_in_executor(self._executor, _run)
        return job

    def serialize_result(self, job: ScanJob) -> Dict[str, Any]:
        if not job.result:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Result not ready")
        return self._scan_result_to_dict(job.result)

    async def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _scan_result_to_dict(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Serialize ScanResult using the report generator helpers."""
        serialized = {
            "scan_id": scan_result.scan_id,
            "repository": {
                "path": scan_result.repository.path,
                "url": scan_result.repository.url,
                "branch": scan_result.repository.branch,
                "commit_hash": scan_result.repository.commit_hash,
                "tech_stack": {
                    "languages": scan_result.repository.tech_stack.languages,
                    "frameworks": scan_result.repository.tech_stack.frameworks,
                    "package_managers": scan_result.repository.tech_stack.package_managers,
                    "containers": scan_result.repository.tech_stack.containers,
                    "infrastructure": scan_result.repository.tech_stack.infrastructure,
                },
            },
            "config": {
                "enabled_scanners": scan_result.config.enabled_scanners,
                "exclude_patterns": scan_result.config.exclude_patterns,
                "include_patterns": scan_result.config.include_patterns,
                "timeout": scan_result.config.timeout,
                "parallel_scans": scan_result.config.parallel_scans,
            },
            "summary": self._report_generator.generate_summary_report(scan_result),
            "findings": [
                {
                    "id": finding.id,
                    "scanner": finding.scanner,
                    "finding_type": finding.finding_type.value,
                    "severity": finding.severity.value,
                    "title": finding.title,
                    "description": finding.description,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "column_number": finding.column_number,
                    "risk_score": finding.risk_score,
                    "tags": finding.tags,
                    "metadata": finding.metadata,
                }
                for finding in scan_result.findings
            ],
            "risk_score": scan_result.risk_score,
            "risk_level": scan_result.risk_level,
            "scan_duration": scan_result.scan_duration,
            "started_at": scan_result.started_at.isoformat(),
            "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
            "success": scan_result.success,
            "error_message": scan_result.error_message,
        }
        return serialized


def create_app(config: Optional[Config] = None) -> FastAPI:
    """Create and configure a FastAPI application instance."""

    config = config or get_config()
    manager = ScanManager(config)

    app = FastAPI(
        title="Repo-Scan API",
        description="Advanced repository security scanning service",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    @app.get("/api/v1/health", response_model=Dict[str, Any])
    async def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "timestamp": datetime.utcnow(),
            "workspace": config.workspace_dir,
            "max_workers": config.max_workers,
        }

    @app.get("/api/v1/scanners")
    async def list_scanners() -> JSONResponse:
        scanners = manager.list_available_scanners()
        return JSONResponse({"scanners": scanners})

    @app.post("/api/v1/scans", response_model=ScanStatusResponse, status_code=status.HTTP_202_ACCEPTED)
    async def start_scan(request: ScanRequest) -> ScanStatusResponse:
        if not request.repo_path and not request.repo_url:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="repo_path or repo_url must be provided")
        job = await manager.submit(request)
        return job.to_status()

    @app.get("/api/v1/scans", response_model=ScanListResponse)
    async def list_scans() -> ScanListResponse:
        return ScanListResponse(scans=manager.list_jobs())

    @app.get("/api/v1/scans/{scan_id}", response_model=ScanStatusResponse)
    async def get_scan(scan_id: str) -> ScanStatusResponse:
        job = manager.get_job(scan_id)
        return job.to_status()

    @app.get("/api/v1/scans/{scan_id}/result", response_model=ScanResultResponse)
    async def get_scan_result(scan_id: str) -> ScanResultResponse:
        job = manager.get_job(scan_id)
        if job.status in {"queued", "running"}:
            return ScanResultResponse(status=job.status)
        payload = manager.serialize_result(job)
        return ScanResultResponse(status=job.status, result=payload, error=job.error)

    @app.on_event("shutdown")
    async def on_shutdown() -> None:
        await manager.shutdown()

    return app
