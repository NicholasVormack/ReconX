"""Port registry, banner fingerprinting and risk classification.

Everything in this module is pure and side-effect free so it can be unit tested
without a network. The scanner asks three questions of it:

    service_name(port)          -> human label for a port
    fingerprint(banner)         -> product/version string guessed from a banner
    classify(port, banner)      -> (severity, note, service) for one open port

Risk notes deliberately describe *why* an exposed service matters, because a
port list on its own tells a reader nothing.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Dict, List, Optional, Tuple


class Severity(str, Enum):
    """Ordered finding severity. ``INFO`` means "open, nothing notable"."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Relative weight used when aggregating a host score from its findings.
SEVERITY_WEIGHT: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 7,
    Severity.CRITICAL: 12,
}

#: Sort order for reports (most severe first).
SEVERITY_ORDER: Dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

#: Ports scanned when the operator does not pass ``--ports``.
DEFAULT_PORTS: Tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
    8443, 9200, 11211, 27017,
)

#: Ports that carry a well-known service name.
SERVICE_NAMES: Dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    512: "exec",
    513: "login",
    514: "shell",
    587: "submission",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2181: "zookeeper",
    2375: "docker",
    2376: "docker-tls",
    3000: "node-dev",
    3306: "mysql",
    3389: "rdp",
    4369: "epmd",
    5000: "flask-dev",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6443: "k8s-api",
    7001: "weblogic",
    8000: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9092: "kafka",
    9200: "elasticsearch",
    9300: "elasticsearch",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
    27018: "mongodb",
}

#: Ports where plaintext HTTP is worth trying (used to pick a probe).
HTTP_LIKE_PORTS = frozenset({80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9200, 15672})

#: Ports where a TLS handshake is expected.
TLS_PORTS = frozenset({443, 465, 636, 993, 995, 2376, 6443, 8443})

#: Ports where the service speaks first, so sending data can confuse it.
GREETING_PORTS = frozenset({21, 22, 25, 110, 143, 587, 993, 995, 3306, 5432})

#: Severity and rationale for services that should not be reachable from an
#: untrusted network. Absent ports are reported as ``info``.
PORT_RISK: Dict[int, Tuple[Severity, str]] = {
    21: (Severity.MEDIUM, "FTP is cleartext and anonymous access is a common misconfiguration."),
    23: (Severity.CRITICAL, "Telnet sends credentials in cleartext; replace with SSH."),
    69: (Severity.MEDIUM, "TFTP has no authentication and is used for file exfiltration."),
    111: (Severity.LOW, "rpcbind leaks the RPC service map to unauthenticated clients."),
    135: (Severity.MEDIUM, "MSRPC is a common lateral-movement and enumeration target on Windows."),
    137: (Severity.LOW, "NetBIOS name service leaks host and workgroup names."),
    139: (Severity.MEDIUM, "NetBIOS session service exposes legacy SMB file sharing."),
    161: (Severity.MEDIUM, "SNMP often ships with the public/private community strings."),
    445: (Severity.HIGH, "SMB is the primary ransomware propagation path; keep it off the internet."),
    512: (Severity.CRITICAL, "rexec runs remote commands without encryption."),
    513: (Severity.CRITICAL, "rlogin trusts remote host identity and is trivially spoofed."),
    514: (Severity.CRITICAL, "rsh allows unauthenticated remote shells."),
    873: (Severity.MEDIUM, "rsync modules are frequently world-readable."),
    1433: (Severity.HIGH, "A database port is reachable; it should be behind a private network."),
    1521: (Severity.HIGH, "A database port is reachable; it should be behind a private network."),
    2049: (Severity.HIGH, "NFS exports can be mounted by unauthenticated hosts."),
    2375: (Severity.CRITICAL, "An unauthenticated Docker API grants root on the host."),
    2376: (Severity.HIGH, "A remote Docker API is exposed; verify TLS client auth."),
    3306: (Severity.HIGH, "MySQL is exposed; databases belong on a private network."),
    3389: (Severity.HIGH, "RDP is a top brute-force and BlueKeep target; require a VPN."),
    5432: (Severity.HIGH, "PostgreSQL is exposed; databases belong on a private network."),
    5900: (Severity.HIGH, "VNC is usually unauthenticated or weakly protected."),
    5984: (Severity.HIGH, "CouchDB had a wildcard-admin CVE; verify the admin party is off."),
    6379: (Severity.CRITICAL, "Redis has no auth by default; it allows arbitrary file writes."),
    9200: (Severity.HIGH, "Elasticsearch is unauthenticated by default and leaks all indexed data."),
    9300: (Severity.HIGH, "Elasticsearch transport port leaks cluster data."),
    11211: (Severity.CRITICAL, "Memcached needs no auth and enables amplification attacks."),
    27017: (Severity.HIGH, "MongoDB historically allowed unauthenticated access to every database."),
    27018: (Severity.HIGH, "MongoDB shard port is exposed."),
}

#: ``(regex, product, severity_hint)``. Ordered: first match wins.
BANNER_SIGNATURES: List[Tuple[str, str, Optional[Severity]]] = [
    (r"OpenSSH[_-]?([\d.p]+)?", "OpenSSH", None),
    (r"dropbear[_-]?([\d.]*)", "Dropbear SSH", None),
    (r"SSH-2\.0-([\w.]+)", "SSH", None),
    (r"ProFTPD ([\d.]+)", "ProFTPD", None),
    (r"vsftpd ([\d.]+)", "vsftpd", None),
    (r"Pure-FTPd", "Pure-FTPd", None),
    (r"Microsoft FTP Service", "Microsoft FTP", None),
    (r"Apache/([\d.]+)", "Apache httpd", None),
    (r"nginx/([\d.]+)", "nginx", None),
    (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS", None),
    (r"Microsoft-HTTPAPI/([\d.]+)", "Microsoft HTTPAPI", None),
    (r"Lighttpd/([\d.]+)", "lighttpd", None),
    (r"caddy", "Caddy", None),
    (r"Jetty\(([\d.]+)\)", "Jetty", None),
    (r"gunicorn", "Gunicorn", None),
    (r"Werkzeug/([\d.]+)", "Werkzeug dev server", Severity.LOW),
    (r"SimpleHTTP/([\d.]+)", "Python http.server", Severity.LOW),
    (r"Postfix", "Postfix", None),
    (r"Exim ([\d.]+)", "Exim", None),
    (r"Sendmail ([\d.]+)", "Sendmail", None),
    (r"MySQL", "MySQL", None),
    (r"MariaDB", "MariaDB", None),
    (r"PostgreSQL", "PostgreSQL", None),
    (r"Redis", "Redis", None),
    (r"Memcached", "Memcached", None),
    (r"MongoDB", "MongoDB", None),
    (r"Windows RPC", "Microsoft Windows RPC", None),
]

#: Version strings old enough to be worth flagging regardless of port.
OUTDATED_PATTERNS: List[Tuple[str, str]] = [
    (r"OpenSSH[_-]?([1-6])\.", "OpenSSH older than 7.x"),
    (r"Apache/(1\.|2\.[0-3]\.)", "Apache httpd 1.x/2.0-2.3 (end of life)"),
    (r"nginx/0\.", "nginx 0.x (end of life)"),
    (r"Microsoft-IIS/(5|6|7\.0)", "IIS 5/6/7.0 (end of life)"),
    (r"PHP/(4|5)\.[0-6]", "PHP 4/5.x (end of life)"),
    (r"ProFTPD (1\.[0-2]\.)", "ProFTPD before 1.3"),
]

_USER_AGENT = b"ReconX/2.0 (authorized security assessment)"
_HOST_LINE = b"Host: {target}\r\n"


def service_name(port: int) -> str:
    """Return a label for ``port``, falling back to ``unknown``."""
    return SERVICE_NAMES.get(port, "unknown")


def fingerprint(banner: str) -> Optional[str]:
    """Guess a product (and version when visible) from a raw banner."""
    if not banner:
        return None
    for pattern, product, _hint in BANNER_SIGNATURES:
        match = re.search(pattern, banner, re.IGNORECASE)
        if not match:
            continue
        version = None
        if match.groups():
            candidate = (match.group(1) or "").strip(" ._-")
            if candidate:
                version = candidate
        return f"{product} {version}" if version else product
    return None


def outdated_reason(banner: str) -> Optional[str]:
    """Return a human note when the banner matches a known end-of-life build."""
    for pattern, reason in OUTDATED_PATTERNS:
        if re.search(pattern, banner, re.IGNORECASE):
            return reason
    return None


def classify(port: int, banner: str = "") -> Tuple[Severity, str, str]:
    """Classify one open port.

    Returns ``(severity, note, service)``. The note is operator-facing prose, so
    an empty string is never returned for a risky port.
    """
    service = service_name(port)
    stale = outdated_reason(banner)

    if port in PORT_RISK:
        severity, note = PORT_RISK[port]
        product = fingerprint(banner)
        if product:
            note = f"{note} Banner: {product}."
        if stale:
            severity = _raise(severity)
            note = f"{note} {stale}."
        return severity, note, service

    if stale:
        return Severity.MEDIUM, f"{stale} on {service}.", service

    if service in {"http-proxy", "http-alt", "node-dev", "flask-dev"}:
        return (
            Severity.LOW,
            f"{service} is often a development service that was never hardened.",
            service,
        )

    if service in {"http", "https", "http-alt"}:
        return Severity.INFO, "Standard web service.", service

    return Severity.INFO, "", service


def _raise(severity: Severity) -> Severity:
    """Step one severity level up, capped at ``CRITICAL``."""
    ordered = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return ordered[min(ordered.index(severity) + 1, len(ordered) - 1)]


def http_probe(target: str, path: str = "/") -> bytes:
    """Build a minimal HTTP/1.1 request used for banner grabbing."""
    request = (
        f"HEAD {path} HTTP/1.1\r\n".encode()
        + _HOST_LINE.replace(b"{target}", target.encode())
        + b"User-Agent: "
        + _USER_AGENT
        + b"\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
    return request


def probe_for(port: int, target: str) -> Optional[bytes]:
    """Pick a probe for ``port``, or ``None`` when the service speaks first."""
    if port in GREETING_PORTS:
        return None
    if port in TLS_PORTS:
        return None
    if port in HTTP_LIKE_PORTS or port in {80, 443}:
        return http_probe(target)
    if port == 25:
        return b"EHLO reconx.local\r\n"
    if port == 110:
        return None
    if port == 143:
        return b"a CAPABILITY\r\n"
    # Unknown port: a bare CRLF is harmless and coaxes text protocols to answer.
    return b"\r\n"


def sort_key(severity: Severity) -> int:
    """Sort key so the worst findings come first."""
    return SEVERITY_ORDER[severity]
