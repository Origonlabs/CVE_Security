"""
Web-based interface for repo-scan using FastAPI and modern web technologies.
"""

import asyncio
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from fastapi import FastAPI, Request, Form, File, UploadFile, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import uvicorn

from ..core.config import Config
from ..core.models import ScanResult
from ..orchestrator import ScanOrchestrator
from ..report import ReportGenerator
from ..notifications import NotificationManager


class WebInterface:
    """
    Web-based interface for repo-scan using FastAPI.
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8000):
        """Initialize the web interface."""
        self.host = host
        self.port = port
        self.app = FastAPI(
            title="Repo-Scan Web Interface",
            description="Advanced repository security scanning tool",
            version="1.0.0"
        )
        
        # Initialize components
        self.config = Config()
        self.orchestrator = ScanOrchestrator(self.config)
        self.report_generator = ReportGenerator()
        self.notification_manager = NotificationManager()
        
        # Setup templates and static files
        self.setup_templates()
        self.setup_routes()
        self.setup_websockets()
        
        # Active scans tracking
        self.active_scans: Dict[str, Dict[str, Any]] = {}
    
    def setup_templates(self):
        """Setup Jinja2 templates and static files."""
        # Create templates directory if it doesn't exist
        templates_dir = Path(__file__).parent / "templates"
        templates_dir.mkdir(exist_ok=True)
        
        # Create static directory if it doesn't exist
        static_dir = Path(__file__).parent / "static"
        static_dir.mkdir(exist_ok=True)
        
        self.templates = Jinja2Templates(directory=str(templates_dir))
        
        # Mount static files
        self.app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    def setup_routes(self):
        """Setup all web routes."""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def index(request: Request):
            """Main dashboard page."""
            return self.templates.TemplateResponse("index.html", {
                "request": request,
                "title": "Repo-Scan Dashboard",
                "config": self.config,
                "orchestrator": self.orchestrator,
                "datetime": datetime,
            })

        @self.app.get("/scan", response_class=HTMLResponse)
        async def scan_page(request: Request):
            """Scan configuration page."""
            scanners = self.orchestrator.get_available_scanners()
            return self.templates.TemplateResponse("scan.html", {
                "request": request,
                "title": "Start Security Scan",
                "scanners": scanners,
                "config": self.config,
            })
        
        @self.app.post("/api/scan/start")
        async def start_scan(
            repo_path: Optional[str] = Form(None),
            repo_url: Optional[str] = Form(None),
            scanners: Optional[List[str]] = Form(None),
            timeout: int = Form(1800),
            parallel: bool = Form(True),
            output_format: str = Form("all")
        ):
            """Start a new security scan."""
            if not repo_path and not repo_url:
                raise HTTPException(status_code=400, detail="Repository path or URL required")
            
            available_scanners = [
                meta["name"] for meta in self.orchestrator.get_available_scanners()
            ]
            if scanners:
                invalid = sorted(set(scanners) - set(available_scanners))
                if invalid:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Unknown scanners requested: {', '.join(invalid)}",
                    )
                enabled_scanners = scanners
            else:
                enabled_scanners = [
                    name for name in available_scanners if self.config.is_scanner_enabled(name)
                ]
                if not enabled_scanners:
                    enabled_scanners = available_scanners

            # Generate scan ID
            scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Store scan configuration
            self.active_scans[scan_id] = {
                "id": scan_id,
                "repo_path": repo_path,
                "repo_url": repo_url,
                "scanners": enabled_scanners,
                "timeout": timeout,
                "parallel": parallel,
                "output_format": output_format,
                "status": "starting",
                "progress": 0,
                "started_at": datetime.now(),
                "result": None,
                "exclude_patterns": None,
                "include_patterns": None,
            }
            
            # Start scan in background
            asyncio.create_task(self.run_scan_async(scan_id))
            
            return JSONResponse({
                "scan_id": scan_id,
                "status": "started",
                "message": "Scan started successfully"
            })
        
        @self.app.get("/api/scan/{scan_id}/status")
        async def get_scan_status(scan_id: str):
            """Get scan status and progress."""
            if scan_id not in self.active_scans:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            scan_info = self.active_scans[scan_id]
            return JSONResponse({
                "scan_id": scan_id,
                "status": scan_info["status"],
                "progress": scan_info["progress"],
                "started_at": scan_info["started_at"].isoformat(),
                "result": scan_info["result"]
            })
        
        @self.app.get("/api/scan/{scan_id}/result")
        async def get_scan_result(scan_id: str):
            """Get complete scan result."""
            if scan_id not in self.active_scans:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            scan_info = self.active_scans[scan_id]
            if not scan_info["result"]:
                raise HTTPException(status_code=404, detail="Scan result not available")
            
            return JSONResponse(scan_info["result"])
        
        @self.app.get("/api/scans")
        async def list_scans():
            """List all scans."""
            scans = []
            for scan_id, scan_info in self.active_scans.items():
                scans.append({
                    "scan_id": scan_id,
                    "status": scan_info["status"],
                    "progress": scan_info["progress"],
                    "started_at": scan_info["started_at"].isoformat(),
                    "repo_path": scan_info["repo_path"],
                    "repo_url": scan_info["repo_url"]
                })
            
            return JSONResponse({"scans": scans})
        
        @self.app.get("/api/scanners")
        async def list_scanners():
            """List available scanners."""
            scanners = self.orchestrator.get_available_scanners()
            return JSONResponse({"scanners": scanners})
        
        @self.app.get("/reports/{scan_id}")
        async def get_report(scan_id: str, format: str = "html"):
            """Get scan report."""
            if scan_id not in self.active_scans:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            scan_info = self.active_scans[scan_id]
            if not scan_info["result"]:
                raise HTTPException(status_code=404, detail="Scan result not available")
            
            reports_dir = Path("reports")
            if format == "html":
                report_path = reports_dir / f"scan_{scan_id}.html"
                if report_path.exists():
                    return FileResponse(report_path)
            elif format == "json":
                report_path = reports_dir / f"scan_{scan_id}.json"
                if report_path.exists():
                    return FileResponse(report_path)
            elif format == "junit":
                report_path = reports_dir / f"scan_{scan_id}.xml"
                if report_path.exists():
                    return FileResponse(report_path)
            
            raise HTTPException(status_code=404, detail="Report not found")
        
        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard(request: Request):
            """Dashboard page with scan history."""
            return self.templates.TemplateResponse("dashboard.html", {
                "request": request,
                "title": "Scan Dashboard"
            })
        
        @self.app.get("/settings", response_class=HTMLResponse)
        async def settings_page(request: Request):
            """Settings configuration page."""
            return self.templates.TemplateResponse("settings.html", {
                "request": request,
                "title": "Settings",
                "config": self.config,
                "orchestrator": self.orchestrator,
                "datetime": datetime,
            })
        
        @self.app.get("/api/config")
        async def get_config():
            """Get current configuration."""
            scanner_data = {}
            for name in self.orchestrator.list_detectors():
                config = self.config.get_scanner_config(name)
                info = self.orchestrator.get_detector_info(name) or {"description": "Unknown"}
                scanner_data[name] = {
                    "enabled": config.enabled,
                    "timeout": config.timeout,
                    "available": info.get("available", False),
                    "description": info.get("description", ""),
                    "required_dependencies": info.get("required_dependencies", []),
                }

            return JSONResponse({
                "workspace_dir": self.config.workspace_dir,
                "max_workers": self.config.max_workers,
                "scan_timeout": self.config.scan_timeout,
                "scanners": scanner_data,
            })
        
        @self.app.post("/api/config")
        async def update_config(config_data: dict):
            """Update configuration."""
            # Update configuration based on provided data
            if "max_workers" in config_data:
                self.config.max_workers = config_data["max_workers"]
            if "scan_timeout" in config_data:
                self.config.scan_timeout = config_data["scan_timeout"]
            
            return JSONResponse({"status": "updated"})
    
    def setup_websockets(self):
        """Setup WebSocket connections for real-time updates."""
        
        @self.app.websocket("/ws/{scan_id}")
        async def websocket_endpoint(websocket: WebSocket, scan_id: str):
            """WebSocket endpoint for real-time scan updates."""
            await websocket.accept()
            
            try:
                while True:
                    # Send scan status updates
                    if scan_id in self.active_scans:
                        scan_info = self.active_scans[scan_id]
                        await websocket.send_json({
                            "type": "status_update",
                            "scan_id": scan_id,
                            "status": scan_info["status"],
                            "progress": scan_info["progress"],
                            "message": self.get_progress_message(scan_info["progress"])
                        })
                    
                    await asyncio.sleep(1)
                    
            except WebSocketDisconnect:
                pass
    
    async def run_scan_async(self, scan_id: str):
        """Run scan asynchronously."""
        scan_info = self.active_scans[scan_id]
        
        try:
            # Update status
            scan_info["status"] = "running"
            scan_info["progress"] = 10
            
            # Run the scan
            result = await asyncio.to_thread(
                self.orchestrator.scan_repository,
                scan_info["repo_path"],
                scan_info["repo_url"],
                None,
                scan_info["scanners"],
                scan_info.get("exclude_patterns"),
                scan_info.get("include_patterns"),
                scan_info["timeout"],
                scan_info["parallel"],
            )
            
            # Update progress
            scan_info["progress"] = 90
            
            # Generate reports
            output_dir = Path("reports")
            output_dir.mkdir(exist_ok=True)
            
            format_type = scan_info["output_format"]
            if format_type in ["json", "all"]:
                json_path = output_dir / f"scan_{result.scan_id}.json"
                self.report_generator.generate_json_report(result, json_path)
            
            if format_type in ["html", "all"]:
                html_path = output_dir / f"scan_{result.scan_id}.html"
                self.report_generator.generate_html_report(result, html_path)
            
            if format_type in ["junit", "all"]:
                junit_path = output_dir / f"scan_{result.scan_id}.xml"
                self.report_generator.generate_junit_report(result, junit_path)
            
            # Store result
            scan_info["result"] = {
                "scan_id": result.scan_id,
                "risk_score": result.risk_score,
                "risk_level": result.risk_level,
                "total_findings": len(result.findings),
                "scan_duration": result.scan_duration,
                "success": result.success,
                "findings": [
                    {
                        "id": f.id,
                        "scanner": f.scanner,
                        "severity": f.severity.value,
                        "title": f.title,
                        "description": f.description,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "risk_score": f.risk_score,
                        "tags": f.tags
                    }
                    for f in result.findings
                ]
            }
            
            # Update final status
            scan_info["status"] = "completed"
            scan_info["progress"] = 100
            
        except Exception as e:
            scan_info["status"] = "failed"
            scan_info["error"] = str(e)
    
    def get_progress_message(self, progress: int) -> str:
        """Get progress message based on progress percentage."""
        if progress < 20:
            return "Initializing scan..."
        elif progress < 40:
            return "Running security scanners..."
        elif progress < 60:
            return "Analyzing results..."
        elif progress < 80:
            return "Calculating risk scores..."
        elif progress < 100:
            return "Generating reports..."
        else:
            return "Scan completed!"
    
    def run(self):
        """Run the web interface."""
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )


# Pydantic models for API
class ScanRequest(BaseModel):
    repo_path: Optional[str] = None
    repo_url: Optional[str] = None
    scanners: List[str]
    timeout: int = 1800
    parallel: bool = True
    output_format: str = "all"


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


def main():
    """Main function to run the web interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Repo-Scan Web Interface")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    
    args = parser.parse_args()
    
    web_interface = WebInterface(host=args.host, port=args.port)
    web_interface.run()


if __name__ == "__main__":
    main()
