"""Engine tests. No external network access and no Nmap required."""

from __future__ import annotations

import socket
import unittest

from reconx.engine import (
    PortSpecError,
    TargetError,
    discover_hosts,
    parse_ports,
    probe_port,
    scan_host,
    validate_target,
)
from reconx.services import DEFAULT_PORTS, Severity


class ParsePortsTests(unittest.TestCase):
    def test_default_when_empty(self) -> None:
        self.assertEqual(parse_ports(None), list(DEFAULT_PORTS))
        self.assertEqual(parse_ports("   "), list(DEFAULT_PORTS))

    def test_single_ports_are_sorted_and_deduplicated(self) -> None:
        self.assertEqual(parse_ports("443,22,22,80"), [22, 80, 443])

    def test_ranges_expand(self) -> None:
        self.assertEqual(parse_ports("8000-8002"), [8000, 8001, 8002])

    def test_service_names_resolve(self) -> None:
        self.assertEqual(parse_ports("ssh,https"), [22, 443])

    def test_mixed_spec(self) -> None:
        self.assertEqual(parse_ports("ssh,8000-8001,53"), [22, 53, 8000, 8001])

    def test_out_of_bounds_rejected(self) -> None:
        with self.assertRaises(PortSpecError):
            parse_ports("0")
        with self.assertRaises(PortSpecError):
            parse_ports("70000")
        with self.assertRaises(PortSpecError):
            parse_ports("900-100")

    def test_unknown_name_rejected(self) -> None:
        with self.assertRaises(PortSpecError):
            parse_ports("definitely-not-a-service")


class ValidateTargetTests(unittest.TestCase):
    def test_ip_literal(self) -> None:
        self.assertEqual(validate_target("127.0.0.1"), ("127.0.0.1", "127.0.0.1"))

    def test_empty_rejected(self) -> None:
        with self.assertRaises(TargetError):
            validate_target("   ")

    def test_whitespace_rejected(self) -> None:
        # Guards against smuggling extra arguments into a subprocess call.
        with self.assertRaises(TargetError):
            validate_target("127.0.0.1 -O")

    def test_unresolvable_rejected(self) -> None:
        with self.assertRaises(TargetError):
            validate_target("this-host-should-not-exist.invalid")


class LiveScanTests(unittest.TestCase):
    """Scan a socket this test binds itself, so it never touches the network."""

    def setUp(self) -> None:
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(5)
        self.open_port = self.server.getsockname()[1]

    def tearDown(self) -> None:
        self.server.close()

    def test_open_port_detected(self) -> None:
        finding = probe_port("127.0.0.1", "127.0.0.1", self.open_port, 1.0, banner=False)
        self.assertEqual(finding.state, "open")
        self.assertGreaterEqual(finding.latency_ms, 0.0)

    def test_scan_host_summarises(self) -> None:
        result = scan_host("127.0.0.1", ports=[self.open_port], timeout=1.0, banner=False)
        self.assertEqual(len(result.open_findings), 1)
        self.assertEqual(result.open_findings[0].port, self.open_port)
        self.assertIn(result.risk_grade, {"A", "B", "C", "D", "F"})

    def test_closed_port_is_closed(self) -> None:
        # Bind a port, note it, close it: connecting must now be refused.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()

        finding = probe_port("127.0.0.1", "127.0.0.1", closed_port, 1.0, banner=False)
        self.assertIn(finding.state, {"closed", "filtered"})

    def test_risky_port_gets_severity(self) -> None:
        result = scan_host("127.0.0.1", ports=[self.open_port], timeout=1.0, banner=False)
        # An unlisted high port carries no known risk, so it must stay INFO.
        self.assertEqual(result.open_findings[0].severity, Severity.INFO)


class DiscoverTests(unittest.TestCase):
    def test_localhost_is_found_in_its_own_slash30(self) -> None:
        # A /30 around 127.0.0.1 contains the loopback interface itself.
        hosts = discover_hosts("127.0.0.0/30", timeout=0.3)
        self.assertIn("127.0.0.1", hosts)

    def test_oversized_network_rejected(self) -> None:
        with self.assertRaises(TargetError):
            discover_hosts("10.0.0.0/8")

    def test_invalid_network_rejected(self) -> None:
        with self.assertRaises(TargetError):
            discover_hosts("not-a-network")


if __name__ == "__main__":
    unittest.main()
