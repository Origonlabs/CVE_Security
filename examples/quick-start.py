#!/usr/bin/env python3
"""
Quick start example for repo-scan.
This script demonstrates basic usage of repo-scan programmatically.
"""

import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from repo_scan.core.config import Config
from repo_scan.orchestrator import ScanOrchestrator
from repo_scan.report import ReportGenerator


def main():
    """Main function demonstrating repo-scan usage."""
    
    print("🔒 Repo-Scan Quick Start Example")
    print("=" * 50)
    
    # 1. Load configuration
    print("\n1. Loading configuration...")
    config = Config()
    print(f"   Workspace: {config.workspace_dir}")
    print(f"   Max workers: {config.max_workers}")
    print(f"   Scan timeout: {config.scan_timeout}s")
    
    # 2. Create orchestrator
    print("\n2. Creating scan orchestrator...")
    orchestrator = ScanOrchestrator(config)
    
    # 3. List available scanners
    print("\n3. Available scanners:")
    scanners = orchestrator.get_available_scanners()
    for scanner in scanners:
        status = "✅" if scanner["available"] else "❌"
        enabled = "🟢" if scanner["enabled"] else "🔴"
        print(f"   {status} {enabled} {scanner['name']}: {scanner['description']}")
    
    # 4. Run a scan (example with current directory)
    print("\n4. Running security scan...")
    try:
        # Scan current directory
        current_dir = Path.cwd()
        print(f"   Scanning: {current_dir}")
        
        result = orchestrator.scan_repository(
            repo_path=str(current_dir),
            scanners=["semgrep", "gitleaks"],  # Use available scanners
            timeout=300,  # 5 minutes
            parallel=True
        )
        
        print(f"   ✅ Scan completed successfully!")
        print(f"   📊 Risk Score: {result.risk_score:.1f}/100 ({result.risk_level})")
        print(f"   🔍 Total Findings: {len(result.findings)}")
        print(f"   ⏱️  Duration: {result.scan_duration:.1f}s")
        
        # 5. Show findings summary
        if result.findings:
            print("\n5. Findings Summary:")
            severity_counts = {}
            for finding in result.findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "✅"}[severity]
                    print(f"   {emoji} {severity}: {count} findings")
            
            # Show top 3 findings
            print("\n6. Top Findings:")
            top_findings = sorted(result.findings, key=lambda f: f.risk_score, reverse=True)[:3]
            for i, finding in enumerate(top_findings, 1):
                emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "✅"}[finding.severity.value]
                print(f"   {i}. {emoji} {finding.title}")
                print(f"      Scanner: {finding.scanner}")
                print(f"      Risk Score: {finding.risk_score:.1f}")
                print(f"      File: {finding.file_path or 'N/A'}")
                if finding.line_number:
                    print(f"      Line: {finding.line_number}")
                print()
        
        # 6. Generate reports
        print("7. Generating reports...")
        report_generator = ReportGenerator()
        
        # Create reports directory
        reports_dir = Path("example-reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Generate JSON report
        json_path = reports_dir / f"scan_{result.scan_id}.json"
        report_generator.generate_json_report(result, json_path)
        print(f"   📄 JSON report: {json_path}")
        
        # Generate HTML report
        html_path = reports_dir / f"scan_{result.scan_id}.html"
        report_generator.generate_html_report(result, html_path)
        print(f"   🌐 HTML report: {html_path}")
        
        # Generate JUnit report
        junit_path = reports_dir / f"scan_{result.scan_id}.xml"
        report_generator.generate_junit_report(result, junit_path)
        print(f"   🧪 JUnit report: {junit_path}")
        
        print(f"\n✅ All reports generated in: {reports_dir}")
        
    except Exception as e:
        print(f"   ❌ Scan failed: {e}")
        return 1
    
    print("\n🎉 Quick start example completed successfully!")
    print("\nNext steps:")
    print("1. Check the generated reports in the 'example-reports' directory")
    print("2. Try scanning a different repository: repo-scan --path /path/to/repo")
    print("3. Use the CLI for more options: repo-scan --help")
    print("4. Configure notifications and CI/CD integration")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
