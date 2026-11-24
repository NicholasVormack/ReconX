"""Scan engine: port discovery, banner grabbing, TLS inspection, host sweep.

The engine is deliberately transport-thin and dependency-free. It answers four
questions:

    parse_ports("22,80,8000-8100")   -> concrete port list
    validate_target(target)          -> resolved ip + display host
    scan_host(host, ports)           -> ScanResult
    discover_hosts("192.168.1.0/28") -> live addresses

No global state, no work at import time: the previous version created a report
directory the moment the file was imported, which made the code impossible to
unit test and produced empty scan folders everywhere.
"""

from __future__ import annotations

import errno
import ipaddress
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from .services import (
    DEFAULT_PORTS,
    SERVICE_NAMES,
    TLS_PORTS,
    Severity,
    classify,
    fingerprint,
    probe_for,
    service_name,
    sort_key,
)

#: Reverse map so ``--ports ssh,https`` works.
NAME_TO_PORT: Dict[str, int] = {name: port for port, name in SERVICE_NAMES.items()}

#: Socket errors that still prove the host is alive (it answered, negatively).
ALIVE_ERRNOS = frozenset({0, errno.ECONNREFUSED, errno.ECONNRESET, errno.EACCES})

MAX_BANNER_BYTES = 2048
DEFAULT_TIMEOUT = 2.0
DEFAULT_WORKERS = 64


class TargetError(ValueError):
    """Raised when a target cannot be resolved or is malformed."""


class PortSpecError(ValueError):
    """Raised when a port specification cannot be parsed."""


@dataclass
class PortFinding:
    """One probed port."""

    port: int
    state: str
    service: str = "unknown"
    product: Optional[str] = None
    severity: Severity = Severity.INFO
    note: str = ""
    banner: str = ""
    latency_ms: float = 0.0

    def as_row(self) -> Dict[str, object]:
        """Flat representation used by the CSV and JSON writers."""
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "product": self.product or "",
            "severity": self.severity.value,
            "note": self.note,
            "latency_ms": round(self.latency_ms, 1),
            "banner": self.banner,
        }


@dataclass
class ScanResult:
    """Complete result for one host."""

    target: str
    address: str
    ports: Sequence[int]
    findings: List[PortFinding] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    nmap: Optional[Dict[str, object]] = None
    error: Optional[str] = None

    @property
    def open_findings(self) -> List[PortFinding]:
        """Open ports, worst severity first."""
        return sorted(
            [f for f in self.findings if f.state == "open"],
            key=lambda f: (sort_key(f.severity), f.port),
        )

    @property
    def duration_seconds(self) -> float:
        return max((self.finished_at - self.started_at).total_seconds(), 0.0)

    @property
    def risk_score(self) -> int:
        """Weighted sum of finding severities (see ``services.SEVERITY_WEIGHT``)."""
        from .services import SEVERITY_WEIGHT

        return sum(SEVERITY_WEIGHT[finding.severity] for finding in self.open_findings)

    @property
    def risk_grade(self) -> str:
        """Letter grade so a reader gets the headline before the table."""
        score = self.risk_score
        if score == 0:
            return "A"
        if score <= 3:
            return "B"
        if score <= 8:
            return "C"
        if score <= 16:
            return "D"
        return "F"

    @property
    def worst_severity(self) -> Severity:
        findings = self.open_findings
        return findings[0].severity if findings else Severity.INFO


def parse_ports(spec: Optional[str]) -> List[int]:
    """Expand a port specification into a sorted, de-duplicated list.

    Accepts comma-separated ports, ranges (``8000-8010``) and service names
    (``ssh``, ``https``). An empty spec yields the default top-ports list.
    """
    if spec is None or not spec.strip():
        return list(DEFAULT_PORTS)

    ports = set()
    for raw in spec.split(","):
        chunk = raw.strip()
        if not chunk:
            continue
        if "-" in chunk:
            low, _, high = chunk.partition("-")
            try:
                low_i, high_i = int(low), int(high)
            except ValueError as exc:
                raise PortSpecError(f"Invalid port range: {chunk!r}") from exc
            if not (1 <= low_i <= high_i <= 65535):
                raise PortSpecError(f"Port range out of bounds: {chunk!r}")
            ports.update(range(low_i, high_i + 1))
        elif chunk.isdigit():
            port = int(chunk)
            if not 1 <= port <= 65535:
                raise PortSpecError(f"Port out of range: {chunk!r}")
            ports.add(port)
        elif chunk.lower() in NAME_TO_PORT:
            ports.add(NAME_TO_PORT[chunk.lower()])
        else:
            raise PortSpecError(f"Unknown port or service name: {chunk!r}")

    if not ports:
        raise PortSpecError("Port specification resolved to zero ports")
    return sorted(ports)


def validate_target(target: str) -> Tuple[str, str]:
    """Resolve ``target`` and return ``(display_name, ip)``.

    Rejects empty input and anything that is not a hostname or IP literal, so a
    value can never be smuggled into a subprocess command line.
    """
    name = (target or "").strip()
    if not name:
        raise TargetError("Target is empty")
    if any(ch.isspace() for ch in name):
        raise TargetError(f"Target contains whitespace: {name!r}")
    try:
        ipaddress.ip_address(name)
        return name, name
    except ValueError:
        pass
    try:
        return name, socket.gethostbyname(name)
    except socket.gaierror as exc:
        raise TargetError(f"Could not resolve {name!r}: {exc}") from exc


def _decode_banner(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    cleaned = "".join(ch if ch.isprintable() or ch in "\r\n\t" else " " for ch in text)
    first_lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    banner = " | ".join(first_lines[:3])
    return banner[:400]


def grab_banner(ip: str, port: int, host: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Connect to a port and return its banner, or an empty string."""
    if port in TLS_PORTS:
        info = inspect_tls(ip, port, host, timeout)
        if info:
            return " | ".join(f"{k}={v}" for k, v in info.items())
        return ""

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            probe = probe_for(port, host)
            if probe:
                sock.sendall(probe)
            chunks = bytearray()
            sock.settimeout(timeout)
            while len(chunks) < MAX_BANNER_BYTES:
                try:
                    chunk = sock.recv(1024)
                except (socket.timeout, TimeoutError):
                    break
                if not chunk:
                    break
                chunks.extend(chunk)
            return _decode_banner(bytes(chunks))
    except (OSError, ValueError):
        return ""


def inspect_tls(ip: str, port: int, host: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, str]:
    """Return TLS version, cipher and certificate details for a TLS port.

    Tries a verifying handshake first. If the certificate is not trusted the
    handshake is retried without verification so the version and cipher are
    still reported, with the trust failure recorded as the subject.
    """
    def handshake(verify: bool) -> Tuple[Dict[str, str], Optional[str]]:
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cipher = tls.cipher()
                details = {
                    "version": tls.version() or "unknown",
                    "cipher": cipher[0] if cipher else "unknown",
                }
                try:
                    cert = tls.getpeercert() or {}
                except ValueError:
                    cert = {}
                subject = cert.get("subject", ())
                issuer = cert.get("issuer", ())
                if subject:
                    details["subject"] = ", ".join(
                        f"{key}={value}" for pair in subject for key, value in pair
                    )
                if issuer:
                    details["issuer"] = ", ".join(
                        f"{key}={value}" for pair in issuer for key, value in pair
                    )
                if cert.get("notAfter"):
                    details["expires"] = cert["notAfter"]
                return details, None

    try:
        details, _ = handshake(verify=True)
        details["trust"] = "valid"
        return details
    except ssl.SSLCertVerificationError as exc:
        try:
            details, _ = handshake(verify=False)
            details["trust"] = f"untrusted ({exc.verify_message})"
            return details
        except (OSError, ssl.SSLError):
            return {}
    except (OSError, ssl.SSLError, ValueError):
        return {}


def probe_port(ip: str, host: str, port: int, timeout: float, banner: bool) -> PortFinding:
    """Probe a single port and classify the result."""
    started = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            latency = (time.perf_counter() - started) * 1000
    except (socket.timeout, TimeoutError):
        return PortFinding(port=port, state="filtered", service=service_name(port))
    except OSError as exc:
        if exc.errno == errno.ECONNREFUSED:
            return PortFinding(port=port, state="closed", service=service_name(port))
        return PortFinding(
            port=port,
            state="filtered",
            service=service_name(port),
            note=str(exc),
        )

    raw_banner = grab_banner(ip, port, host, timeout) if banner else ""
    severity, note, service = classify(port, raw_banner)
    product = fingerprint(raw_banner)
    return PortFinding(
        port=port,
        state="open",
        service=service,
        product=product,
        severity=severity,
        note=note,
        banner=raw_banner,
        latency_ms=latency,
    )


def scan_host(
    target: str,
    ports: Optional[Sequence[int]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    workers: int = DEFAULT_WORKERS,
    banner: bool = True,
) -> ScanResult:
    """Scan one host across ``ports`` using a bounded thread pool."""
    display, address = validate_target(target)
    port_list = list(ports) if ports else list(DEFAULT_PORTS)

    result = ScanResult(
        target=display,
        address=address,
        ports=port_list,
        started_at=datetime.now(timezone.utc),
    )

    findings: List[PortFinding] = []
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(port_list)))) as pool:
        futures = [
            pool.submit(probe_port, address, display, port, timeout, banner)
            for port in port_list
        ]
        for future in futures:
            try:
                finding = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                result.error = f"probe failed: {exc}"
                continue
            with lock:
                findings.append(finding)

    result.findings = sorted(findings, key=lambda f: f.port)
    result.finished_at = datetime.now(timezone.utc)
    return result


def discover_hosts(
    network: str,
    timeout: float = 0.4,
    workers: int = 96,
) -> List[str]:
    """TCP sweep a network for live addresses.

    Uses a connect() attempt to a handful of common ports: an explicit refusal
    still proves the host is reachable, which a bare ping sweep cannot tell you
    and which needs no raw sockets or root.
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as exc:
        raise TargetError(f"Invalid network: {network!r}") from exc

    if net.num_addresses > 4096:
        raise TargetError(
            f"Network {net} has {net.num_addresses} addresses; refine to a /20 or smaller"
        )

    probe_ports = (80, 443, 22, 445, 3389, 8080)
    alive: List[str] = []
    lock = threading.Lock()

    def check(address: str) -> None:
        for port in probe_ports:
            try:
                with socket.create_connection((address, port), timeout=timeout):
                    with lock:
                        alive.append(address)
                    return
            except OSError as exc:
                if exc.errno in ALIVE_ERRNOS:
                    with lock:
                        alive.append(address)
                    return
            except (socket.timeout, TimeoutError):
                continue

    hosts = [str(host) for host in net.hosts()]
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(hosts)))) as pool:
        list(pool.map(check, hosts))

    return sorted(set(alive), key=lambda ip: ipaddress.ip_address(ip))
