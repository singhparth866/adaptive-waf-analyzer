"""
WAF Fingerprinter & Adaptive Bypass Analyzer
Entry point — delegates to the Typer CLI.

Usage:
    python main.py --url https://target.com --mode normal
    python main.py --url https://target.com --mode aggressive --output both -v
    python main.py --url https://target.com --mode passive
"""
import sys
from pathlib import Path

# Make sure project root is on the path when run directly
sys.path.insert(0, str(Path(__file__).parent))

from cli.commands import cli

if __name__ == "__main__":
    cli()
