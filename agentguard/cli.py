from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .monitor import AgentMonitor, find_agent_processes


DEFAULT_TARGETS = ["codex.exe", "claude.exe", "claude-code.exe"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="Observe local coding-agent process, file, and network activity.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover", help="Show running supported agents")
    discover.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS)

    monitor = subparsers.add_parser("monitor", help="Start an observation-only session")
    monitor.add_argument("--root", type=Path, default=Path.cwd(), help="Workspace to watch")
    monitor.add_argument("--pid", type=int, action="append", help="Monitor a specific agent PID")
    monitor.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS)
    monitor.add_argument("--duration", type=float, default=0, help="Stop after N seconds; 0 waits")
    monitor.add_argument("--interval", type=float, default=0.5, help="Process polling interval")
    monitor.add_argument("--file-interval", type=float, default=2.0, help="Workspace file scan interval")
    monitor.add_argument("--output", type=Path, help="Output directory")
    monitor.add_argument(
        "--no-command-lines",
        action="store_true",
        help="Do not record process argument lists",
    )

    ui = subparsers.add_parser("ui", help="Open the always-on-top observation window")
    ui.add_argument("--root", type=Path, help="Workspace to watch; defaults to the saved choice")
    ui.add_argument("--pid", type=int, action="append", help="Monitor a specific agent PID")
    ui.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS)
    ui.add_argument("--output", type=Path, help="Output directory")
    ui.add_argument("--no-command-lines", action="store_true")
    ui.add_argument(
        "--language",
        choices=("zh", "en"),
        default="zh",
        help="Floating window language (default: zh)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "discover":
        matches = find_agent_processes(args.targets)
        if not matches:
            print("No matching agent process is running.")
            return 1
        print("PID     PPID    NAME                 WORKING DIRECTORY")
        for item in matches:
            print(
                f"{item['pid']:<7} {item['ppid']:<7} {item['name']:<20} "
                f"{item.get('cwd') or '-'}"
            )
        return 0

    if args.command == "ui":
        from .ui import run_ui

        return run_ui(
            root=args.root.resolve() if args.root else None,
            target_names=args.targets,
            explicit_pids=set(args.pid or []),
            output=args.output,
            capture_command_lines=not args.no_command_lines,
            language=args.language,
        )

    root = args.root.resolve()
    if not root.is_dir():
        print(f"Workspace does not exist: {root}", file=sys.stderr)
        return 2

    monitor = AgentMonitor(
        root=root,
        target_names=args.targets,
        explicit_pids=set(args.pid or []),
        interval=max(args.interval, 0.05),
        file_interval=max(args.file_interval, 0.1),
        output=args.output,
        capture_command_lines=not args.no_command_lines,
    )
    return monitor.run(duration=args.duration)
