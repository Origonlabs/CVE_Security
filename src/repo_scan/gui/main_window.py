"""
Main GUI window for repo-scan using Tkinter.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import json
import webbrowser
from pathlib import Path
from typing import Optional, Dict, Any

from ..core.config import Config
from ..core.models import ScanResult
from ..orchestrator import ScanOrchestrator
from ..report import ReportGenerator


class RepoScanGUI:
    """
    Main GUI application for repo-scan using Tkinter.
    """
    
    def __init__(self):
        """Initialize the GUI application."""
        self.root = tk.Tk()
        self.root.title("Repo-Scan - Advanced Repository Security Scanner")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Configure style
        self.setup_styles()
        
        # Initialize components
        self.config = Config()
        self.orchestrator = ScanOrchestrator(self.config)
        self.report_generator = ReportGenerator()
        self.current_scan_result: Optional[ScanResult] = None
        
        # Create GUI elements
        self.create_widgets()
        self.setup_layout()
        
        # Center window
        self.center_window()
    
    def setup_styles(self):
        """Setup custom styles for the GUI."""
        style = ttk.Style()
        
        # Configure colors
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Heading.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Success.TLabel', foreground='green')
        style.configure('Warning.TLabel', foreground='orange')
        style.configure('Error.TLabel', foreground='red')
        
        # Configure buttons
        style.configure('Primary.TButton', font=('Arial', 10, 'bold'))
        style.configure('Success.TButton', foreground='green')
        style.configure('Danger.TButton', foreground='red')
    
    def create_widgets(self):
        """Create all GUI widgets."""
        # Main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        
        # Title
        self.title_label = ttk.Label(
            self.main_frame, 
            text="🔒 Repo-Scan Security Scanner",
            style='Title.TLabel'
        )
        
        # Repository selection frame
        self.repo_frame = ttk.LabelFrame(self.main_frame, text="Repository Selection", padding="10")
        
        # Repository path
        self.repo_path_var = tk.StringVar()
        self.repo_path_entry = ttk.Entry(
            self.repo_frame, 
            textvariable=self.repo_path_var,
            width=60
        )
        self.browse_button = ttk.Button(
            self.repo_frame,
            text="Browse...",
            command=self.browse_repository
        )
        
        # Repository URL
        self.repo_url_var = tk.StringVar()
        self.repo_url_entry = ttk.Entry(
            self.repo_frame,
            textvariable=self.repo_url_var,
            width=60
        )
        self.url_label = ttk.Label(self.repo_frame, text="Or enter Git URL:")
        
        # Scanner selection frame
        self.scanner_frame = ttk.LabelFrame(self.main_frame, text="Scanner Configuration", padding="10")
        
        # Scanner checkboxes
        self.scanner_vars = {}
        scanners = self.orchestrator.get_available_scanners()
        
        for i, scanner in enumerate(scanners):
            var = tk.BooleanVar(value=scanner["enabled"])
            self.scanner_vars[scanner["name"]] = var
            
            checkbox = ttk.Checkbutton(
                self.scanner_frame,
                text=f"{scanner['name']}: {scanner['description']}",
                variable=var
            )
            checkbox.grid(row=i//2, column=i%2, sticky="w", padx=5, pady=2)
        
        # Scan options frame
        self.options_frame = ttk.LabelFrame(self.main_frame, text="Scan Options", padding="10")
        
        # Parallel scans
        self.parallel_var = tk.BooleanVar(value=True)
        self.parallel_check = ttk.Checkbutton(
            self.options_frame,
            text="Run scanners in parallel",
            variable=self.parallel_var
        )
        
        # Timeout
        self.timeout_var = tk.IntVar(value=1800)
        self.timeout_label = ttk.Label(self.options_frame, text="Timeout (seconds):")
        self.timeout_spinbox = ttk.Spinbox(
            self.options_frame,
            from_=60,
            to=7200,
            textvariable=self.timeout_var,
            width=10
        )
        
        # Output format
        self.format_var = tk.StringVar(value="all")
        self.format_label = ttk.Label(self.options_frame, text="Output format:")
        self.format_combo = ttk.Combobox(
            self.options_frame,
            textvariable=self.format_var,
            values=["json", "html", "junit", "all"],
            state="readonly",
            width=10
        )
        
        # Control buttons
        self.button_frame = ttk.Frame(self.main_frame)
        
        self.scan_button = ttk.Button(
            self.button_frame,
            text="🔍 Start Scan",
            command=self.start_scan,
            style='Primary.TButton'
        )
        
        self.stop_button = ttk.Button(
            self.button_frame,
            text="⏹️ Stop Scan",
            command=self.stop_scan,
            state="disabled"
        )
        
        self.open_reports_button = ttk.Button(
            self.button_frame,
            text="📁 Open Reports",
            command=self.open_reports_folder,
            state="disabled"
        )
        
        # Progress frame
        self.progress_frame = ttk.LabelFrame(self.main_frame, text="Scan Progress", padding="10")
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            variable=self.progress_var,
            maximum=100
        )
        
        self.status_var = tk.StringVar(value="Ready to scan")
        self.status_label = ttk.Label(self.progress_frame, textvariable=self.status_var)
        
        # Results frame
        self.results_frame = ttk.LabelFrame(self.main_frame, text="Scan Results", padding="10")
        
        # Results summary
        self.results_summary = ttk.Frame(self.results_frame)
        
        self.risk_score_var = tk.StringVar(value="N/A")
        self.risk_level_var = tk.StringVar(value="N/A")
        self.total_findings_var = tk.StringVar(value="N/A")
        self.scan_duration_var = tk.StringVar(value="N/A")
        
        # Risk score display
        self.risk_score_label = ttk.Label(
            self.results_summary,
            text="Risk Score:",
            style='Heading.TLabel'
        )
        self.risk_score_value = ttk.Label(
            self.results_summary,
            textvariable=self.risk_score_var,
            style='Title.TLabel'
        )
        
        # Risk level display
        self.risk_level_label = ttk.Label(
            self.results_summary,
            text="Risk Level:",
            style='Heading.TLabel'
        )
        self.risk_level_value = ttk.Label(
            self.results_summary,
            textvariable=self.risk_level_var,
            style='Title.TLabel'
        )
        
        # Total findings display
        self.total_findings_label = ttk.Label(
            self.results_summary,
            text="Total Findings:",
            style='Heading.TLabel'
        )
        self.total_findings_value = ttk.Label(
            self.results_summary,
            textvariable=self.total_findings_var,
            style='Title.TLabel'
        )
        
        # Scan duration display
        self.scan_duration_label = ttk.Label(
            self.results_summary,
            text="Duration:",
            style='Heading.TLabel'
        )
        self.scan_duration_value = ttk.Label(
            self.results_summary,
            textvariable=self.scan_duration_var,
            style='Title.TLabel'
        )
        
        # Findings list
        self.findings_frame = ttk.Frame(self.results_frame)
        
        # Treeview for findings
        columns = ("Scanner", "Severity", "Title", "File", "Risk Score")
        self.findings_tree = ttk.Treeview(
            self.findings_frame,
            columns=columns,
            show="headings",
            height=10
        )
        
        # Configure columns
        for col in columns:
            self.findings_tree.heading(col, text=col)
            self.findings_tree.column(col, width=120)
        
        # Scrollbar for findings
        self.findings_scrollbar = ttk.Scrollbar(
            self.findings_frame,
            orient="vertical",
            command=self.findings_tree.yview
        )
        self.findings_tree.configure(yscrollcommand=self.findings_scrollbar.set)
        
        # Details frame
        self.details_frame = ttk.LabelFrame(self.results_frame, text="Finding Details", padding="10")
        
        self.details_text = scrolledtext.ScrolledText(
            self.details_frame,
            height=8,
            width=80,
            wrap=tk.WORD
        )
        
        # Bind selection event
        self.findings_tree.bind("<<TreeviewSelect>>", self.on_finding_select)
        
        # Menu bar
        self.create_menu_bar()
    
    def create_menu_bar(self):
        """Create the menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Repository...", command=self.browse_repository)
        file_menu.add_separator()
        file_menu.add_command(label="Open Reports Folder", command=self.open_reports_folder)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Scan menu
        scan_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        scan_menu.add_command(label="Start Scan", command=self.start_scan)
        scan_menu.add_command(label="Stop Scan", command=self.stop_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Configure Scanners...", command=self.configure_scanners)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Show HTML Report", command=self.show_html_report)
        view_menu.add_command(label="Show JSON Report", command=self.show_json_report)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
    
    def setup_layout(self):
        """Setup the layout of all widgets."""
        # Main frame
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        self.title_label.pack(pady=(0, 20))
        
        # Repository selection
        self.repo_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(self.repo_frame, text="Repository Path:").grid(row=0, column=0, sticky="w", pady=2)
        self.repo_path_entry.grid(row=0, column=1, sticky="ew", padx=(5, 5), pady=2)
        self.browse_button.grid(row=0, column=2, pady=2)
        
        self.url_label.grid(row=1, column=0, sticky="w", pady=2)
        self.repo_url_entry.grid(row=1, column=1, sticky="ew", padx=(5, 5), pady=2)
        
        self.repo_frame.columnconfigure(1, weight=1)
        
        # Scanner configuration
        self.scanner_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Scan options
        self.options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.parallel_check.grid(row=0, column=0, sticky="w", pady=2)
        
        self.timeout_label.grid(row=1, column=0, sticky="w", pady=2)
        self.timeout_spinbox.grid(row=1, column=1, sticky="w", padx=(5, 20), pady=2)
        
        self.format_label.grid(row=1, column=2, sticky="w", pady=2)
        self.format_combo.grid(row=1, column=3, sticky="w", padx=(5, 0), pady=2)
        
        # Control buttons
        self.button_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        self.open_reports_button.pack(side=tk.LEFT)
        
        # Progress
        self.progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))
        self.status_label.pack()
        
        # Results
        self.results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Results summary
        self.results_summary.pack(fill=tk.X, pady=(0, 10))
        
        self.risk_score_label.grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.risk_score_value.grid(row=0, column=1, sticky="w", padx=(0, 20))
        
        self.risk_level_label.grid(row=0, column=2, sticky="w", padx=(0, 5))
        self.risk_level_value.grid(row=0, column=3, sticky="w", padx=(0, 20))
        
        self.total_findings_label.grid(row=1, column=0, sticky="w", padx=(0, 5))
        self.total_findings_value.grid(row=1, column=1, sticky="w", padx=(0, 20))
        
        self.scan_duration_label.grid(row=1, column=2, sticky="w", padx=(0, 5))
        self.scan_duration_value.grid(row=1, column=3, sticky="w")
        
        # Findings and details
        findings_details_frame = ttk.Frame(self.results_frame)
        findings_details_frame.pack(fill=tk.BOTH, expand=True)
        
        # Findings list
        self.findings_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.findings_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.findings_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Details
        self.details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.details_text.pack(fill=tk.BOTH, expand=True)
    
    def center_window(self):
        """Center the window on the screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def browse_repository(self):
        """Open file dialog to select repository."""
        directory = filedialog.askdirectory(title="Select Repository Directory")
        if directory:
            self.repo_path_var.set(directory)
            self.repo_url_var.set("")  # Clear URL if path is selected
    
    def start_scan(self):
        """Start the security scan in a separate thread."""
        # Validate inputs
        repo_path = self.repo_path_var.get().strip()
        repo_url = self.repo_url_var.get().strip()
        
        if not repo_path and not repo_url:
            messagebox.showerror("Error", "Please select a repository path or enter a Git URL")
            return
        
        # Get selected scanners
        selected_scanners = [
            name for name, var in self.scanner_vars.items() 
            if var.get()
        ]
        
        if not selected_scanners:
            messagebox.showerror("Error", "Please select at least one scanner")
            return
        
        # Update UI state
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_var.set(0)
        self.status_var.set("Starting scan...")
        
        # Clear previous results
        self.clear_results()
        
        # Start scan in separate thread
        scan_thread = threading.Thread(
            target=self.run_scan,
            args=(repo_path, repo_url, selected_scanners),
            daemon=True
        )
        scan_thread.start()
    
    def run_scan(self, repo_path: str, repo_url: str, scanners: list):
        """Run the security scan."""
        try:
            # Update progress
            self.root.after(0, lambda: self.status_var.set("Initializing scan..."))
            self.root.after(0, lambda: self.progress_var.set(10))
            
            # Run the scan
            result = self.orchestrator.scan_repository(
                repo_path=repo_path if repo_path else None,
                repo_url=repo_url if repo_url else None,
                scanners=scanners,
                timeout=self.timeout_var.get(),
                parallel=self.parallel_var.get()
            )
            
            # Update progress
            self.root.after(0, lambda: self.progress_var.set(90))
            self.root.after(0, lambda: self.status_var.set("Generating reports..."))
            
            # Generate reports
            output_dir = Path("reports")
            output_dir.mkdir(exist_ok=True)
            
            format_type = self.format_var.get()
            if format_type in ["json", "all"]:
                json_path = output_dir / f"scan_{result.scan_id}.json"
                self.report_generator.generate_json_report(result, json_path)
            
            if format_type in ["html", "all"]:
                html_path = output_dir / f"scan_{result.scan_id}.html"
                self.report_generator.generate_html_report(result, html_path)
            
            if format_type in ["junit", "all"]:
                junit_path = output_dir / f"scan_{result.scan_id}.xml"
                self.report_generator.generate_junit_report(result, junit_path)
            
            # Update UI with results
            self.root.after(0, lambda: self.update_results(result))
            self.root.after(0, lambda: self.progress_var.set(100))
            self.root.after(0, lambda: self.status_var.set("Scan completed successfully!"))
            
        except Exception as e:
            self.root.after(0, lambda: self.handle_scan_error(str(e)))
        finally:
            # Reset UI state
            self.root.after(0, lambda: self.scan_button.config(state="normal"))
            self.root.after(0, lambda: self.stop_button.config(state="disabled"))
            self.root.after(0, lambda: self.open_reports_button.config(state="normal"))
    
    def update_results(self, result: ScanResult):
        """Update the UI with scan results."""
        self.current_scan_result = result
        
        # Update summary
        self.risk_score_var.set(f"{result.risk_score:.1f}/100")
        self.risk_level_var.set(result.risk_level)
        self.total_findings_var.set(str(len(result.findings)))
        self.scan_duration_var.set(f"{result.scan_duration:.1f}s")
        
        # Update risk level color
        risk_colors = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "yellow",
            "LOW": "green"
        }
        color = risk_colors.get(result.risk_level, "black")
        self.risk_level_value.config(foreground=color)
        self.risk_score_value.config(foreground=color)
        
        # Update findings list
        self.findings_tree.delete(*self.findings_tree.get_children())
        
        for finding in result.findings:
            self.findings_tree.insert("", "end", values=(
                finding.scanner,
                finding.severity.value,
                finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
                finding.file_path or "N/A",
                f"{finding.risk_score:.1f}"
            ))
        
        # Show completion message
        messagebox.showinfo(
            "Scan Complete",
            f"Security scan completed!\n\n"
            f"Risk Level: {result.risk_level}\n"
            f"Total Findings: {len(result.findings)}\n"
            f"Duration: {result.scan_duration:.1f}s"
        )
    
    def clear_results(self):
        """Clear previous scan results."""
        self.current_scan_result = None
        
        # Clear summary
        self.risk_score_var.set("N/A")
        self.risk_level_var.set("N/A")
        self.total_findings_var.set("N/A")
        self.scan_duration_var.set("N/A")
        
        # Clear findings list
        self.findings_tree.delete(*self.findings_tree.get_children())
        
        # Clear details
        self.details_text.delete(1.0, tk.END)
    
    def on_finding_select(self, event):
        """Handle finding selection in the treeview."""
        selection = self.findings_tree.selection()
        if not selection or not self.current_scan_result:
            return
        
        # Get selected finding
        item = self.findings_tree.item(selection[0])
        scanner = item['values'][0]
        severity = item['values'][1]
        title = item['values'][2]
        
        # Find the actual finding object
        finding = None
        for f in self.current_scan_result.findings:
            if (f.scanner == scanner and 
                f.severity.value == severity and 
                f.title.startswith(title.split("...")[0])):
                finding = f
                break
        
        if finding:
            self.show_finding_details(finding)
    
    def show_finding_details(self, finding):
        """Show detailed information about a finding."""
        details = f"""
FINDING DETAILS
===============

Title: {finding.title}
Scanner: {finding.scanner}
Severity: {finding.severity.value}
Risk Score: {finding.risk_score:.1f}/100
Confidence: {finding.confidence:.1f}

Description:
{finding.description}

File: {finding.file_path or 'N/A'}
Line: {finding.line_number or 'N/A'}
Column: {finding.column_number or 'N/A'}

Tags: {', '.join(finding.tags)}

"""
        
        if finding.cwe_id:
            details += f"CWE ID: {finding.cwe_id}\n"
        
        if finding.cve_id:
            details += f"CVE ID: {finding.cve_id}\n"
        
        if finding.cvss_score:
            details += f"CVSS Score: {finding.cvss_score}\n"
        
        if finding.code_snippet:
            details += f"\nCode Snippet:\n{finding.code_snippet}\n"
        
        if finding.remediation:
            details += f"\nREMEDIATION\n===========\n"
            details += f"Description: {finding.remediation.description}\n"
            details += f"Confidence: {finding.remediation.confidence:.1f}\n"
            details += f"Automation Suggested: {finding.remediation.automation_suggested}\n"
            
            if finding.remediation.steps:
                details += f"\nSteps:\n"
                for i, step in enumerate(finding.remediation.steps, 1):
                    details += f"{i}. {step}\n"
            
            if finding.remediation.references:
                details += f"\nReferences:\n"
                for ref in finding.remediation.references:
                    details += f"- {ref}\n"
        
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(1.0, details)
    
    def stop_scan(self):
        """Stop the current scan."""
        # This would need to be implemented with proper thread cancellation
        messagebox.showinfo("Info", "Scan stop functionality not yet implemented")
    
    def open_reports_folder(self):
        """Open the reports folder in the file manager."""
        reports_dir = Path("reports")
        if reports_dir.exists():
            import subprocess
            import platform
            
            system = platform.system()
            if system == "Windows":
                subprocess.run(["explorer", str(reports_dir)])
            elif system == "Darwin":  # macOS
                subprocess.run(["open", str(reports_dir)])
            else:  # Linux
                subprocess.run(["xdg-open", str(reports_dir)])
        else:
            messagebox.showwarning("Warning", "No reports folder found")
    
    def show_html_report(self):
        """Show the HTML report in the default browser."""
        if not self.current_scan_result:
            messagebox.showwarning("Warning", "No scan results available")
            return
        
        html_path = Path("reports") / f"scan_{self.current_scan_result.scan_id}.html"
        if html_path.exists():
            webbrowser.open(f"file://{html_path.absolute()}")
        else:
            messagebox.showwarning("Warning", "HTML report not found")
    
    def show_json_report(self):
        """Show the JSON report in a new window."""
        if not self.current_scan_result:
            messagebox.showwarning("Warning", "No scan results available")
            return
        
        json_path = Path("reports") / f"scan_{self.current_scan_result.scan_id}.json"
        if json_path.exists():
            # Create new window for JSON display
            json_window = tk.Toplevel(self.root)
            json_window.title("JSON Report")
            json_window.geometry("800x600")
            
            text_widget = scrolledtext.ScrolledText(json_window, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            with open(json_path, 'r') as f:
                json_data = json.load(f)
                formatted_json = json.dumps(json_data, indent=2)
                text_widget.insert(1.0, formatted_json)
        else:
            messagebox.showwarning("Warning", "JSON report not found")
    
    def configure_scanners(self):
        """Open scanner configuration dialog."""
        messagebox.showinfo("Info", "Scanner configuration dialog not yet implemented")
    
    def show_about(self):
        """Show about dialog."""
        about_text = """
Repo-Scan Security Scanner
Version 1.0.0

An advanced repository security scanning tool that provides
comprehensive security analysis for software repositories.

Features:
• Multiple security scanners (SAST, SCA, Secret Detection, IaC)
• Advanced risk scoring and prioritization
• Multiple report formats (JSON, HTML, JUnit)
• GUI and CLI interfaces
• CI/CD integration
• Plugin system

© 2024 Security Team
        """
        messagebox.showinfo("About Repo-Scan", about_text)
    
    def show_documentation(self):
        """Open documentation in browser."""
        webbrowser.open("https://github.com/Origonlabs/CVE_Security")
    
    def handle_scan_error(self, error_message: str):
        """Handle scan errors."""
        self.status_var.set(f"Scan failed: {error_message}")
        messagebox.showerror("Scan Error", f"Scan failed with error:\n\n{error_message}")
    
    def run(self):
        """Run the GUI application."""
        self.root.mainloop()


def main():
    """Main function to run the GUI."""
    app = RepoScanGUI()
    app.run()


if __name__ == "__main__":
    main()
