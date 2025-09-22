#!/usr/bin/env python3
"""
GUI launcher for repo-scan.
This script provides options to launch either the desktop GUI or web interface.
"""

import argparse
import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from repo_scan.gui.main_window import RepoScanGUI
from repo_scan.gui.web_interface import WebInterface


def main():
    """Main function to launch the appropriate GUI."""
    parser = argparse.ArgumentParser(
        description="Repo-Scan GUI Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  repo-scan-gui                    # Launch desktop GUI
  repo-scan-gui --web              # Launch web interface
  repo-scan-gui --web --port 8080  # Launch web interface on port 8080
        """
    )
    
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch web interface instead of desktop GUI"
    )
    
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host for web interface (default: 127.0.0.1)"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for web interface (default: 8000)"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode"
    )
    
    args = parser.parse_args()
    
    try:
        if args.web:
            print(f"🌐 Starting Repo-Scan Web Interface...")
            print(f"📍 URL: http://{args.host}:{args.port}")
            print(f"🔧 Debug mode: {'ON' if args.debug else 'OFF'}")
            print()
            
            web_interface = WebInterface(host=args.host, port=args.port)
            web_interface.run()
        else:
            print("🖥️  Starting Repo-Scan Desktop GUI...")
            print("🔧 Debug mode:", "ON" if args.debug else "OFF")
            print()
            
            app = RepoScanGUI()
            app.run()
            
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error launching GUI: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
