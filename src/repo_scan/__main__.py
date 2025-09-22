"""
Main entry point for repo-scan CLI tool.
"""

import sys
from typing import Optional

import typer
from rich.console import Console

from .cli import app
from .core.config import Config
from .core.exceptions import RepoScanError

console = Console()


def main() -> None:
    """
    Main entry point for the repo-scan CLI application.
    
    Handles global error handling and configuration loading.
    """
    try:
        # Load configuration
        config = Config()
        
        # Run the CLI application
        app()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(1)
    except RepoScanError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        if Config().debug:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
