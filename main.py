#!/usr/bin/env python3
"""
Analyzer2 - Network & System Misconfiguration Scanner
Entry point: launches the GUI by default, or runs a CLI scan with --cli.
"""

import sys
import os
import argparse

# Ensure UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    parser = argparse.ArgumentParser(
        description="Analyzer2 - Network & System Misconfiguration Scanner"
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run scan in CLI mode (no GUI)",
    )
    parser.add_argument(
        "--api",
        action="store_true",
        help="Start the FastAPI server",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip PDF report generation (CLI mode only)",
    )
    parser.add_argument(
        "--report-dir",
        default="reports",
        help="Directory to save reports (default: reports/)",
    )
    args = parser.parse_args()

    if args.api:
        # Start FastAPI server
        try:
            import uvicorn
            from scanner.config import API_HOST, API_PORT

            print(f"Starting Analyzer2 API on {API_HOST}:{API_PORT}")
            uvicorn.run("api:app", host=API_HOST, port=API_PORT, reload=True)
        except ImportError:
            print("Error: uvicorn is required for API mode.")
            print("Install it with: pip install uvicorn")
            sys.exit(1)

    elif args.cli:
        # Run CLI scan
        from scanner.scan_runner import run_scan

        results = run_scan(
            generate_report=not args.no_report,
            report_directory=args.report_dir,
        )

        # Print summary
        issues = results.get("issues", {})
        total = sum(len(v) for v in issues.values())
        if total == 0:
            print("\nNo issues found. Your system looks good!")
        else:
            print(f"\nTotal issues found: {total}")
            for category, items in issues.items():
                if items:
                    print(f"  {category}: {len(items)}")

    else:
        # Launch GUI
        try:
            from gui import run_gui
            run_gui()
        except ImportError as e:
            print(f"GUI requires tkinter: {e}")
            print("Run with --cli for command-line mode instead.")
            sys.exit(1)


if __name__ == "__main__":
    main()
