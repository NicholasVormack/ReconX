"""Classification tests: pure functions, no sockets."""

from __future__ import annotations

import unittest

from reconx.services import (
    SEVERITY_WEIGHT,
    Severity,
    classify,
    fingerprint,
    outdated_reason,
    probe_for,
    service_name,
    sort_key,
)


class ServiceNameTests(unittest.TestCase):
    def test_known_ports(self) -> None:
        self.assertEqual(service_name(22), "ssh")
        self.assertEqual(service_name(6379), "redis")

    def test_unknown_port(self) -> None:
        self.assertEqual(service_name(54321), "unknown")


class FingerprintTests(unittest.TestCase):
    def test_ssh_banner(self) -> None:
        self.assertEqual(fingerprint("SSH-2.0-OpenSSH_9.6p1 Ubuntu"), "OpenSSH 9.6p1")

    def test_http_server_header(self) -> None:
        self.assertEqual(
            fingerprint("HTTP/1.1 200 OK | Server: nginx/1.24.0"), "nginx 1.24.0"
        )

    def test_iis_banner(self) -> None:
        self.assertEqual(
            fingerprint("HTTP/1.1 404 | Server: Microsoft-IIS/10.0"), "Microsoft IIS 10.0"
        )

    def test_unknown_banner(self) -> None:
        self.assertIsNone(fingerprint("hello there"))
        self.assertIsNone(fingerprint(""))


class OutdatedTests(unittest.TestCase):
    def test_old_openssh(self) -> None:
        self.assertIn("OpenSSH", outdated_reason("SSH-2.0-OpenSSH_5.3") or "")

    def test_current_build_is_not_flagged(self) -> None:
        self.assertIsNone(outdated_reason("SSH-2.0-OpenSSH_9.6p1"))


class ClassifyTests(unittest.TestCase):
    def test_telnet_is_critical(self) -> None:
        severity, note, service = classify(23, "")
        self.assertEqual(severity, Severity.CRITICAL)
        self.assertEqual(service, "telnet")
        self.assertTrue(note)

    def test_redis_is_critical(self) -> None:
        self.assertEqual(classify(6379, "")[0], Severity.CRITICAL)

    def test_rdp_is_high(self) -> None:
        self.assertEqual(classify(3389, "")[0], Severity.HIGH)

    def test_https_is_info(self) -> None:
        severity, _note, service = classify(443, "")
        self.assertEqual(severity, Severity.INFO)
        self.assertEqual(service, "https")

    def test_developer_server_is_low(self) -> None:
        self.assertEqual(classify(8080, "")[0], Severity.LOW)

    def test_product_is_appended_to_note(self) -> None:
        _severity, note, _service = classify(445, "SMB | Server: Microsoft-IIS/10.0")
        self.assertIn("Microsoft IIS", note)

    def test_stale_banner_raises_severity(self) -> None:
        baseline = classify(445, "")[0]
        raised = classify(445, "Microsoft-IIS/6.0")[0]
        self.assertGreaterEqual(SEVERITY_WEIGHT[raised], SEVERITY_WEIGHT[baseline])

    def test_unknown_high_port_has_no_note(self) -> None:
        severity, note, _service = classify(45678, "")
        self.assertEqual(severity, Severity.INFO)
        self.assertEqual(note, "")


class ProbeTests(unittest.TestCase):
    def test_http_port_gets_http_probe(self) -> None:
        probe = probe_for(80, "example.com")
        self.assertIsNotNone(probe)
        self.assertIn(b"HEAD / HTTP/1.1", probe or b"")

    def test_greeting_port_sends_nothing(self) -> None:
        self.assertIsNone(probe_for(22, "example.com"))
        self.assertIsNone(probe_for(21, "example.com"))

    def test_tls_port_sends_nothing(self) -> None:
        self.assertIsNone(probe_for(443, "example.com"))


class OrderingTests(unittest.TestCase):
    def test_critical_sorts_before_info(self) -> None:
        self.assertLess(sort_key(Severity.CRITICAL), sort_key(Severity.INFO))

    def test_weights_monotonic(self) -> None:
        ordered = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        weights = [SEVERITY_WEIGHT[s] for s in ordered]
        self.assertEqual(weights, sorted(weights))
        self.assertEqual(len(set(weights)), len(weights))


if __name__ == "__main__":
    unittest.main()
