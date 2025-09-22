#!/usr/bin/env python3
"""
Demo script for repo-scan GUI interfaces.
This script demonstrates how to use both the desktop GUI and web interface.
"""

import sys
import subprocess
import time
import webbrowser
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def demo_desktop_gui():
    """Demo the desktop GUI."""
    print("🖥️  Demo: Desktop GUI")
    print("=" * 50)
    
    try:
        from repo_scan.gui.main_window import RepoScanGUI
        
        print("✅ Desktop GUI module loaded successfully")
        print("🚀 Launching desktop GUI...")
        print("📝 Instructions:")
        print("   1. Select a repository path or enter a Git URL")
        print("   2. Choose security scanners to run")
        print("   3. Configure scan options")
        print("   4. Click 'Start Scan' to begin")
        print("   5. View results in the interface")
        print()
        
        # Launch GUI
        app = RepoScanGUI()
        app.run()
        
    except ImportError as e:
        print(f"❌ Error importing desktop GUI: {e}")
        print("💡 Make sure tkinter is installed: sudo dnf install python3-tkinter")
    except Exception as e:
        print(f"❌ Error launching desktop GUI: {e}")


def demo_web_interface():
    """Demo the web interface."""
    print("🌐 Demo: Web Interface")
    print("=" * 50)
    
    try:
        from repo_scan.gui.web_interface import WebInterface
        
        print("✅ Web interface module loaded successfully")
        print("🚀 Starting web interface...")
        print("📝 Instructions:")
        print("   1. Open your browser to http://localhost:8000")
        print("   2. Use the dashboard to start new scans")
        print("   3. View real-time progress and results")
        print("   4. Download reports in multiple formats")
        print()
        
        # Start web interface in background
        web_interface = WebInterface(host="127.0.0.1", port=8000)
        
        # Open browser after a short delay
        def open_browser():
            time.sleep(2)
            webbrowser.open("http://localhost:8000")
        
        import threading
        browser_thread = threading.Thread(target=open_browser, daemon=True)
        browser_thread.start()
        
        # Run web interface
        web_interface.run()
        
    except ImportError as e:
        print(f"❌ Error importing web interface: {e}")
        print("💡 Make sure FastAPI is installed: pip install fastapi uvicorn")
    except Exception as e:
        print(f"❌ Error launching web interface: {e}")


def demo_cli_commands():
    """Demo CLI commands."""
    print("⌨️  Demo: CLI Commands")
    print("=" * 50)
    
    commands = [
        ("repo-scan --help", "Show help information"),
        ("repo-scan list-scanners", "List available scanners"),
        ("repo-scan --path . --format html", "Scan current directory"),
        ("repo-scan-gui", "Launch desktop GUI"),
        ("repo-scan-gui --web", "Launch web interface"),
    ]
    
    print("📋 Available CLI commands:")
    for cmd, desc in commands:
        print(f"   {cmd:<40} # {desc}")
    
    print()
    print("💡 Try running these commands in your terminal!")


def main():
    """Main demo function."""
    print("🔒 Repo-Scan GUI Demo")
    print("=" * 60)
    print()
    
    while True:
        print("Choose a demo option:")
        print("1. Desktop GUI (Tkinter)")
        print("2. Web Interface (FastAPI)")
        print("3. CLI Commands")
        print("4. Exit")
        print()
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            demo_desktop_gui()
        elif choice == "2":
            demo_web_interface()
        elif choice == "3":
            demo_cli_commands()
        elif choice == "4":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter 1-4.")
        
        print()
        input("Press Enter to continue...")


if __name__ == "__main__":
    main()
