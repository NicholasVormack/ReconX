"""ReconX - a fast, dependency-free port and surface scanner.

Public surface:

    from reconx import scan_host, parse_ports, write_reports
"""

__version__ = "2.0.0"
__all__ = [
    "__version__",
    "ScanResult",
    "PortFinding",
    "scan_host",
    "parse_ports",
    "validate_target",
    "discover_hosts",
    "write_reports",
]

from .engine import (  # noqa: E402  (import order keeps the version first)
    PortFinding,
    ScanResult,
    discover_hosts,
    parse_ports,
    scan_host,
    validate_target,
)
from .report import write_reports  # noqa: E402
