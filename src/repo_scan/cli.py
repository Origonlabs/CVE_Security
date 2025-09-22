"""
Command-line interface for repo-scan.
"""

import json
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text

from .core.config import Config, get_config
from .core.models import ScanResult, ScanSummary, Severity
from .core.exceptions import RepoScanError
from .orchestrator import ScanOrchestrator
from .report import ReportGenerator
from .utils import generate_scan_id

app = typer.Typer(
    name="repo-scan",
    help="Advanced repository security scanning tool",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


@app.command()
def scan(
    repo_path: Optional[str] = typer.Option(
        None, "--path", "-p", help="Path to local repository"
    ),
    repo_url: Optional[str] = typer.Option(
        None, "--url", "-u", help="URL of remote repository to clone"
    ),
    branch: Optional[str] = typer.Option(
        None, "--branch", "-b", help="Branch to scan (default: current/main)"
    ),
    output_dir: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output directory for reports"
    ),
    format: str = typer.Option(
        "json", "--format", "-f", help="Output format: json, html, junit, all"
    ),
    scanners: Optional[List[str]] = typer.Option(
        None, "--scanner", "-s", help="Specific scanners to run (can be used multiple times)"
    ),
    exclude: Optional[List[str]] = typer.Option(
        None, "--exclude", "-e", help="Patterns to exclude (can be used multiple times)"
    ),
    include: Optional[List[str]] = typer.Option(
        None, "--include", "-i", help="Patterns to include (can be used multiple times)"
    ),
    timeout: int = typer.Option(
        3600, "--timeout", "-t", help="Scan timeout in seconds"
    ),
    parallel: bool = typer.Option(
        True, "--parallel/--no-parallel", help="Run scanners in parallel"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose output"
    ),
    debug: bool = typer.Option(
        False, "--debug", "-d", help="Debug mode"
    ),
) -> None:
    """
    Scan a repository for security vulnerabilities.
    
    Examples:
        repo-scan --path /path/to/repo
        repo-scan --url https://github.com/user/repo.git
        repo-scan --path /path/to/repo --scanner semgrep --scanner gitleaks
        repo-scan --url https://github.com/user/repo.git --format html --output ./reports
    """
    try:
        # Validate inputs
        if not repo_path and not repo_url:
            console.print("[red]Error: Either --path or --url must be specified[/red]")
            raise typer.Exit(1)
        
        if repo_path and repo_url:
            console.print("[red]Error: Cannot specify both --path and --url[/red]")
            raise typer.Exit(1)
        
        # Load configuration
        config = get_config()
        if debug:
            config.debug = True
        if verbose:
            config.verbose = True
        
        # Create orchestrator
        orchestrator = ScanOrchestrator(config)
        
        # Prepare scan configuration
        if repo_path:
            repo_path = Path(repo_path).resolve()
            if not repo_path.exists():
                console.print(f"[red]Error: Repository path does not exist: {repo_path}[/red]")
                raise typer.Exit(1)
        
        # Run scan with progress indicator
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning repository...", total=None)
            
            try:
                result = orchestrator.scan_repository(
                    repo_path=repo_path,
                    repo_url=repo_url,
                    branch=branch,
                    scanners=scanners,
                    exclude_patterns=exclude,
                    include_patterns=include,
                    timeout=timeout,
                    parallel=parallel,
                )
                
                progress.update(task, description="Scan completed")
                
            except Exception as e:
                progress.update(task, description="Scan failed")
                console.print(f"[red]Scan failed: {e}[/red]")
                if debug:
                    console.print_exception()
                raise typer.Exit(1)
        
        # Display results
        _display_scan_results(result, verbose)
        
        # Generate reports
        if output_dir or format != "json":
            output_path = Path(output_dir) if output_dir else Path.cwd() / "reports"
            output_path.mkdir(parents=True, exist_ok=True)
            
            report_generator = ReportGenerator()
            
            if format in ["json", "all"]:
                json_path = output_path / f"scan_{result.scan_id}.json"
                report_generator.generate_json_report(result, json_path)
                console.print(f"[green]JSON report saved to: {json_path}[/green]")
            
            if format in ["html", "all"]:
                html_path = output_path / f"scan_{result.scan_id}.html"
                report_generator.generate_html_report(result, html_path)
                console.print(f"[green]HTML report saved to: {html_path}[/green]")
            
            if format in ["junit", "all"]:
                junit_path = output_path / f"scan_{result.scan_id}.xml"
                report_generator.generate_junit_report(result, junit_path)
                console.print(f"[green]JUnit report saved to: {junit_path}[/green]")
        
        # Exit with appropriate code
        if result.risk_score >= 75:  # HIGH or CRITICAL
            raise typer.Exit(2)
        elif result.risk_score >= 40:  # MEDIUM
            raise typer.Exit(1)
        else:
            raise typer.Exit(0)
            
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        if debug:
            console.print_exception()
        raise typer.Exit(1)


@app.command()
def list_scanners() -> None:
    """List available security scanners."""
    try:
        config = get_config()
        orchestrator = ScanOrchestrator(config)
        scanners = orchestrator.get_available_scanners()
        
        table = Table(title="Available Security Scanners")
        table.add_column("Scanner", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Description", style="white")
        table.add_column("Enabled", style="green")
        
        for scanner in scanners:
            enabled = "✓" if config.is_scanner_enabled(scanner.name) else "✗"
            table.add_row(
                scanner.name,
                scanner.scanner_type,
                scanner.description,
                enabled
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error listing scanners: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def config(
    show: bool = typer.Option(False, "--show", "-s", help="Show current configuration"),
    edit: bool = typer.Option(False, "--edit", "-e", help="Edit configuration"),
    config_file: Optional[str] = typer.Option(
        None, "--config", "-c", help="Configuration file path"
    ),
) -> None:
    """Manage repo-scan configuration."""
    try:
        if show:
            config = get_config()
            config_json = config.json(indent=2)
            console.print(Panel(config_json, title="Current Configuration"))
        
        elif edit:
            config_path = Path(config_file) if config_file else Path.home() / ".repo-scan" / "config.yaml"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            if not config_path.exists():
                # Create default config
                config = Config()
                config.save_to_file(config_path)
                console.print(f"[green]Created default configuration at: {config_path}[/green]")
            else:
                console.print(f"[yellow]Configuration file: {config_path}[/yellow]")
                console.print("Edit the file manually and restart repo-scan to apply changes.")
        
        else:
            console.print("Use --show to display current configuration or --edit to edit it.")
            
    except Exception as e:
        console.print(f"[red]Error managing configuration: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="API server host"),
    port: int = typer.Option(8000, "--port", help="API server port"),
    workers: int = typer.Option(1, "--workers", help="Number of worker processes"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload for development"),
) -> None:
    """Start the repo-scan API server."""
    try:
        import uvicorn
        from .api.server import create_app
        
        app_instance = create_app()
        
        console.print(f"[green]Starting repo-scan API server on {host}:{port}[/green]")
        
        uvicorn.run(
            app_instance,
            host=host,
            port=port,
            workers=workers if not reload else 1,
            reload=reload,
            log_level="info",
        )
        
    except ImportError:
        console.print("[red]Error: API dependencies not installed. Install with: pip install repo-scan[api][/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error starting API server: {e}[/red]")
        raise typer.Exit(1)


def _display_scan_results(result: ScanResult, verbose: bool = False) -> None:
    """Display scan results in a formatted table."""
    
    # Summary panel
    summary = ScanSummary.from_scan_result(result)
    
    summary_text = f"""
[bold]Repository:[/bold] {result.repository.path}
[bold]Risk Score:[/bold] {result.risk_score:.1f}/100 ({result.risk_level})
[bold]Total Findings:[/bold] {summary.total_findings}
[bold]Scan Duration:[/bold] {result.scan_duration:.1f}s
[bold]Status:[/bold] {'✓ Success' if result.success else '✗ Failed'}
"""
    
    console.print(Panel(summary_text, title="Scan Summary", border_style="blue"))
    
    # Findings by severity
    if summary.findings_by_severity:
        severity_table = Table(title="Findings by Severity")
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="right")
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = summary.findings_by_severity.get(severity, 0)
            if count > 0:
                color = {
                    Severity.CRITICAL: "red",
                    Severity.HIGH: "orange3",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "green"
                }[severity]
                severity_table.add_row(f"[{color}]{severity.value}[/{color}]", str(count))
        
        console.print(severity_table)
    
    # Top findings
    if result.findings:
        top_findings = result.get_top_findings(5)
        
        findings_table = Table(title="Top Findings")
        findings_table.add_column("Scanner", style="cyan")
        findings_table.add_column("Severity", style="bold")
        findings_table.add_column("Title", style="white")
        findings_table.add_column("File", style="dim")
        findings_table.add_column("Score", justify="right")
        
        for finding in top_findings:
            severity_color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "orange3",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "green"
            }[finding.severity]
            
            file_info = finding.file_path or "N/A"
            if finding.line_number:
                file_info += f":{finding.line_number}"
            
            findings_table.add_row(
                finding.scanner,
                f"[{severity_color}]{finding.severity.value}[/{severity_color}]",
                finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
                file_info,
                f"{finding.risk_score:.1f}"
            )
        
        console.print(findings_table)
    
    # Verbose output
    if verbose and result.findings:
        console.print("\n[bold]All Findings:[/bold]")
        for i, finding in enumerate(result.findings, 1):
            console.print(f"\n[bold]{i}. {finding.title}[/bold]")
            console.print(f"   Scanner: {finding.scanner}")
            console.print(f"   Severity: {finding.severity.value}")
            console.print(f"   File: {finding.file_path or 'N/A'}")
            if finding.line_number:
                console.print(f"   Line: {finding.line_number}")
            console.print(f"   Description: {finding.description}")
            if finding.remediation:
                console.print(f"   Remediation: {finding.remediation.description}")


if __name__ == "__main__":
    app()
