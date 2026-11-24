"""Command line interface for ReconX.

Examples
--------
    reconx 127.0.0.1
    reconx scanme.example.com --ports 22,80,443,8000-8010 --timeout 1
    reconx 10.0.0.5 --ports top --no-nmap --formats json,md
    reconx --discover 192.168.1.0/28

Exit codes: ``0`` clean, ``1`` usage/target error, ``2`` findings at or above
``--fail-on`` (useful in CI).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Optional, Sequence

from . import __version__
from . import nmapbridge
from .engine import (
    DEFAULT_TIMEOUT,
    DEFAULT_WORKERS,
    PortSpecError,
    ScanResult,
    TargetError,
    discover_hosts,
    parse_ports,
    scan_host,
    validate_target,
)
from .report import write_reports
from .services import SEVERITY_ORDER, Severity

FAIL_THRESHOLDS = {
    "none": 99,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

COLORS = {
    Severity.CRITICAL: "\033[1;91m",
    Severity.HIGH: "\033[1;93m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _paint(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if _use_color() else text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX - a fast, dependency-free port and surface scanner.",
        epilog=(
            "Only scan systems you own or have written authorization to test. "
            "Unauthorized scanning is illegal in most jurisdictions."
        ),
    )
    parser.add_argument("target", nargs="?", help="hostname or IP address to scan")
    parser.add_argument(
        "--ports",
        default=None,
        help="comma-separated ports, ranges and names (e.g. 22,80,8000-8010,ssh)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=None,
        metavar="N",
        help="scan the first N ports of the curated default list",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"per-port timeout in seconds (default {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"worker threads (default {DEFAULT_WORKERS})",
    )
    parser.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    parser.add_argument("--no-nmap", action="store_true", help="skip Nmap enrichment")
    parser.add_argument(
        "--out",
        default="reconx-reports",
        help="directory for written reports (default reconx-reports)",
    )
    parser.add_argument(
        "--formats",
        default="json,csv,html,md",
        help="comma-separated report formats: json,csv,html,md (default all)",
    )
    parser.add_argument(
        "--discover",
        metavar="CIDR",
        default=None,
        help="sweep a network for live hosts instead of scanning ports",
    )
    parser.add_argument(
        "--fail-on",
        choices=sorted(FAIL_THRESHOLDS),
        default="none",
        help="exit with code 2 when a finding at this severity exists (default none)",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress per-port output")
    parser.add_argument("--version", action="version", version=f"ReconX {__version__}")
    return parser


def _severity_rank(severity: Severity) -> int:
    return 4 - SEVERITY_ORDER[severity]


def print_report(result: ScanResult, quiet: bool) -> None:
    """Print the human-facing summary."""
    header = f"{result.target} ({result.address})"
    print()
    print(_paint(" ReconX ", "\033[1;36m") + _paint(f" {header}", BOLD))
    print(
        _paint(
            f" {len(result.ports)} ports probed in {result.duration_seconds:.1f}s"
            f" | {len(result.open_findings)} open",
            DIM,
        )
    )
    print(_paint(" " + "-" * 78, DIM))

    if not result.open_findings:
        print("  No open ports on the probed set.")
        return

    print(_paint(f" {'PORT':<7}{'SERVICE':<15}{'SEVERITY':<10}DETAIL", BOLD))
    for finding in result.open_findings:
        color = COLORS[finding.severity]
        detail = finding.note or finding.product or ""
        if quiet:
            detail = ""
        print(
            f" {_paint(f'{finding.port:<7}', color)}"
            f"{finding.service:<15}"
            f"{_paint(f'{finding.severity.value:<10}', color)}{detail}"
        )
        wider = finding.banner[:110]
        if wider and not quiet:
            print(_paint(f" {'':7} banner: {wider}", DIM))

    counts = {severity: 0 for severity in Severity}
    for finding in result.open_findings:
        counts[finding.severity] += 1
    summary = "  ".join(
        f"{severity.value}={counts[severity]}" for severity in Severity if counts[severity]
    )
    grade_color = "\033[32m" if result.risk_grade in {"A", "B"} else (
        "\033[33m" if result.risk_grade == "C" else "\033[91m"
    )
    print(_paint(" " + "-" * 78, DIM))
    print(f" {summary}  |  grade {_paint(result.risk_grade, grade_color)} (score {result.risk_score})")


def run_discovery(network: str) -> int:
    """Handle the ``--discover`` mode."""
    try:
        hosts = discover_hosts(network)
    except TargetError as exc:
        print(f"reconx: {exc}", file=sys.stderr)
        return 1

    print(f" {len(hosts)} live host(s) on {network}")
    for host in hosts:
        print(f"   {host}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.discover:
        return run_discovery(args.discover)

    if not args.target:
        parser.print_usage(sys.stderr)
        print("reconx: a target is required (or pass --discover CIDR)", file=sys.stderr)
        return 1

    try:
        _, address = validate_target(args.target)
    except TargetError as exc:
        print(f"reconx: {exc}", file=sys.stderr)
        return 1

    try:
        ports: List[int] = parse_ports(args.ports)
    except PortSpecError as exc:
        print(f"reconx: {exc}", file=sys.stderr)
        return 1

    if args.top:
        ports = ports[: max(1, args.top)]

    formats = [fmt.strip().lower() for fmt in args.formats.split(",") if fmt.strip()]
    unknown = set(formats) - {"json", "csv", "html", "md"}
    if unknown:
        print(f"reconx: unknown report format(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 1

    print(_paint(f" scanning {args.target} ({address}) - {len(ports)} ports", DIM))
    started = time.perf_counter()

    result = scan_host(
        args.target,
        ports=ports,
        timeout=args.timeout,
        workers=args.threads,
        banner=not args.no_banner,
    )

    if not args.no_nmap:
        open_ports = [finding.port for finding in result.open_findings]
        if open_ports and nmapbridge.available():
            print(_paint(f" enriching {len(open_ports)} open port(s) with nmap...", DIM))
            result.nmap = nmapbridge.enrich(address, open_ports)

    print_report(result, quiet=args.quiet)

    paths = write_reports(result, args.out, formats)
    if paths:
        print()
        print(_paint(f" reports written to {os.path.abspath(args.out)}", DIM))
        for fmt, path in paths.items():
            print(_paint(f"   {fmt:<5} {path}", DIM))

    print(_paint(f" finished in {time.perf_counter() - started:.1f}s", DIM))
    print()

    threshold = FAIL_THRESHOLDS[args.fail_on]
    if threshold < 99:
        worst = max(
            (_severity_rank(finding.severity) for finding in result.open_findings),
            default=0,
        )
        if worst >= threshold:
            return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
