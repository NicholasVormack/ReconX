"""Optional Nmap enrichment.

Nmap is not required. When it is installed, service/version detection is run
once per host against the ports that were already found open, and the XML output
is parsed with the standard library. When it is missing, the scanner still works
from its own banner grabbing.

The old implementation shelled out to ``nmap -O -sV <target>`` from inside the
per-port worker, so a host with eight open ports triggered sixteen full Nmap
runs, each of which also required root for ``-O`` and silently failed.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Dict, Iterable, List, Optional
from xml.etree import ElementTree


def available() -> bool:
    """True when an ``nmap`` binary is on PATH."""
    return shutil.which("nmap") is not None


def _ports_argument(ports: Iterable[int]) -> str:
    return ",".join(str(port) for port in sorted(set(ports)))


def enrich(ip: str, ports: Iterable[int], host_timeout: int = 120) -> Optional[Dict[str, object]]:
    """Run ``nmap -sV`` against ``ports`` and return structured results.

    Returns ``None`` when Nmap is unavailable, the port list is empty, or the
    scan produced no parseable output.
    """
    port_list: List[int] = sorted(set(ports))
    if not available() or not port_list:
        return None

    command = [
        "nmap",
        "-sV",
        "--version-light",
        "-Pn",
        "-n",
        "--host-timeout",
        f"{host_timeout}s",
        "-p",
        _ports_argument(port_list),
        "-oX",
        "-",
        ip,
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=host_timeout + 15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if not completed.stdout.strip():
        return None

    return parse_xml(completed.stdout, command)


def parse_xml(xml_text: str, command: Optional[List[str]] = None) -> Dict[str, object]:
    """Parse ``nmap -oX`` output into a small JSON-friendly structure."""
    services: List[Dict[str, str]] = []
    os_matches: List[str] = []

    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return {"error": "could not parse nmap XML", "services": [], "os": []}

    for port_node in root.iter("port"):
        state = port_node.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port_node.find("service")
        entry = {"port": port_node.get("portid", "?"), "protocol": port_node.get("protocol", "tcp")}
        if service is not None:
            for attribute in ("name", "product", "version", "extrainfo"):
                value = service.get(attribute)
                if value:
                    entry[attribute] = value
            if service.get("tunnel") == "ssl":
                entry["tunnel"] = "ssl"
        services.append(entry)

    for match in root.iter("osmatch"):
        name = match.get("name")
        accuracy = match.get("accuracy")
        if name:
            os_matches.append(f"{name} ({accuracy}%)" if accuracy else name)

    result: Dict[str, object] = {"services": services, "os": os_matches[:3]}
    if command:
        result["command"] = " ".join(command[:-1]) + " <target>"
    return result
