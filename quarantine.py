#!/usr/bin/env python3
"""
AntiWorm - Standalone Cross-Platform Worm Detection & Quarantine Tool
Usage: python main.py [command] [options]
"""

import argparse
import sys
import os
from core.engine import AntiWormEngine
from utils.banner import print_banner
from utils.logger import setup_logger

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="AntiWorm - Cross-platform worm detection and quarantine tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  scan        Scan a directory or the entire system
  monitor     Start real-time monitoring (background process watching)
  quarantine  Manage quarantined files
  report      Generate a detection report

Examples:
  python main.py scan --path /home/user/downloads
  python main.py scan --full-system
  python main.py monitor --start
  python main.py quarantine --list
  python main.py quarantine --restore <file_id>
  python main.py report --output report.html
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # --- SCAN command ---
    scan_parser = subparsers.add_parser("scan", help="Scan files for worm behavior")
    scan_parser.add_argument("--path", type=str, help="Directory path to scan")
    scan_parser.add_argument("--full-system", action="store_true", help="Scan the entire system")
    scan_parser.add_argument("--deep", action="store_true", help="Enable deep heuristic scanning")
    scan_parser.add_argument("--auto-quarantine", action="store_true", help="Auto-quarantine detected threats")

    # --- MONITOR command ---
    monitor_parser = subparsers.add_parser("monitor", help="Real-time worm activity monitoring")
    monitor_parser.add_argument("--start", action="store_true", help="Start monitoring")
    monitor_parser.add_argument("--stop", action="store_true", help="Stop monitoring")
    monitor_parser.add_argument("--status", action="store_true", help="Check monitor status")

    # --- QUARANTINE command ---
    quar_parser = subparsers.add_parser("quarantine", help="Manage quarantined threats")
    quar_parser.add_argument("--list", action="store_true", help="List all quarantined files")
    quar_parser.add_argument("--restore", type=str, metavar="FILE_ID", help="Restore a quarantined file")
    quar_parser.add_argument("--delete", type=str, metavar="FILE_ID", help="Permanently delete a quarantined file")
    quar_parser.add_argument("--purge", action="store_true", help="Delete ALL quarantined files")

    # --- REPORT command ---
    report_parser = subparsers.add_parser("report", help="Generate security report")
    report_parser.add_argument("--output", type=str, default="antiworm_report.html", help="Output file path")
    report_parser.add_argument("--format", choices=["html", "json", "txt"], default="html", help="Report format")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    logger = setup_logger()
    engine = AntiWormEngine(logger=logger)

    if args.command == "scan":
        if args.full_system:
            scan_path = "/" if sys.platform != "win32" else "C:\\"
        elif args.path:
            scan_path = args.path
        else:
            print("[!] Please specify --path or --full-system")
            sys.exit(1)
        engine.run_scan(
            path=scan_path,
            deep=args.deep,
            auto_quarantine=args.auto_quarantine
        )

    elif args.command == "monitor":
        if args.start:
            engine.start_monitor()
        elif args.stop:
            engine.stop_monitor()
        elif args.status:
            engine.monitor_status()
        else:
            monitor_parser.print_help()

    elif args.command == "quarantine":
        if args.list:
            engine.list_quarantine()
        elif args.restore:
            engine.restore_quarantine(args.restore)
        elif args.delete:
            engine.delete_quarantine(args.delete)
        elif args.purge:
            engine.purge_quarantine()
        else:
            quar_parser.print_help()

    elif args.command == "report":
        engine.generate_report(output=args.output, fmt=args.format)


if __name__ == "__main__":
    main()
