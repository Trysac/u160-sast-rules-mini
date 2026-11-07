"""CLI entry point for sast-rules-mini."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from sast_rules_mini import __version__
from sast_rules_mini.errors import SastError
from sast_rules_mini.formatters import format_text, to_sarif
from sast_rules_mini.rules import Severity
from sast_rules_mini.scanner import scan_paths

SEVERITY_ORDER: dict[Severity, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Execute the SAST mini scanner CLI."""
    parser = argparse.ArgumentParser(
        prog="sast-rules-mini",
        description="Lightweight Python static analysis tool with 10 AST security rules.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Paths to files or directories to scan (defaults to current directory).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "sarif"],
        default="text",
        help="Output format (text or sarif, default: text).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="File path to write output to (defaults to stdout).",
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum finding severity to report (default: low).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse uses 2 for argument errors; if clean --help or --version exit with code 0
        return exc.code if isinstance(exc.code, int) else 2

    try:
        findings = scan_paths(args.paths)
    except SastError as err:
        sys.stderr.write(f"Error: {err}\n")
        return 2
    except Exception as err:
        sys.stderr.write(f"Unexpected error: {err}\n")
        return 2

    min_threshold = SEVERITY_ORDER.get(args.min_severity, 1)
    filtered = [f for f in findings if SEVERITY_ORDER.get(f.severity, 1) >= min_threshold]

    if args.format == "sarif":
        sarif_data = to_sarif(filtered, tool_version=__version__)
        output_str = json.dumps(sarif_data, indent=2)
    else:
        output_str = format_text(filtered)

    if args.output:
        try:
            Path(args.output).write_text(output_str + "\n", encoding="utf-8")
        except OSError as err:
            sys.stderr.write(f"Failed to write output file: {err}\n")
            return 2
    else:
        print(output_str)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
