from __future__ import annotations

import argparse
import sys

from .analyzer import AnalyzerOptions, analyze_many, discover_targets
from .reports import write_csv, write_html, write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pe-analyzer", description="Offline PE triage analyzer")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="Scan PE files or directories")
    add_scan_args(scan)
    return parser


def add_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("targets", nargs="*")
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recurse into directories",
    )
    parser.add_argument("--json-out", help="Write JSON report")
    parser.add_argument("--html-out", help="Write HTML report")
    parser.add_argument("--csv-out", help="Write CSV findings")
    parser.add_argument(
        "--md-out",
        "--markdown-out",
        dest="md_out",
        help="Write Markdown report",
    )
    parser.add_argument("--yara", help="Optional YARA file or directory")
    parser.add_argument(
        "--min-string-len",
        type=int,
        default=4,
        help="Minimum string length",
    )
    parser.add_argument(
        "--max-strings",
        type=int,
        default=2000,
        help="Maximum sampled strings",
    )
    parser.add_argument(
        "--no-strings",
        action="store_true",
        help="Disable string extraction",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high"],
        default="none",
        help="Return exit code 3 when findings at or above threshold exist",
    )


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    commands = {"scan"}
    root_only = {"-h", "--help", "--version"}
    if argv and argv[0] not in commands and argv[0] not in root_only:
        argv.insert(0, "scan")

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        from . import __version__

        print(__version__)
        return 0

    if args.command != "scan":
        parser.error("missing command")

    targets = args.targets
    if not targets:
        parser.error("missing target file or directory")

    files = discover_targets(targets, args.recursive)
    if not files:
        print("no PE files found", file=sys.stderr)
        return 1

    options = AnalyzerOptions(
        min_string_len=args.min_string_len,
        max_strings=args.max_strings,
        strings=not args.no_strings,
        yara_path=args.yara,
    )
    report = analyze_many(files, options)
    json_text = write_json(report, args.json_out)
    if args.html_out:
        write_html(report, args.html_out)
    if args.csv_out:
        write_csv(report, args.csv_out)
    if args.md_out:
        write_markdown(report, args.md_out)
    if not args.json_out:
        print(json_text)
    return 3 if report.summary.meets(args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
