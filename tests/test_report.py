"""Report writer tests: format correctness and escaping."""

from __future__ import annotations

import csv
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone

from reconx.engine import PortFinding, ScanResult
from reconx.nmapbridge import parse_xml
from reconx.report import build_html, build_json, build_markdown, write_reports
from reconx.services import Severity


def sample_result() -> ScanResult:
    return ScanResult(
        target="127.0.0.1",
        address="127.0.0.1",
        ports=[22, 23, 445],
        findings=[
            PortFinding(port=22, state="open", service="ssh", severity=Severity.LOW,
                        note="SSH exposed.", banner="SSH-2.0-OpenSSH_9.6", latency_ms=1.2),
            PortFinding(port=23, state="open", service="telnet", severity=Severity.CRITICAL,
                        note="Telnet is cleartext.", latency_ms=0.9),
            PortFinding(port=445, state="open", service="smb", severity=Severity.HIGH,
                        note="SMB exposed.", latency_ms=2.4),
            PortFinding(port=8080, state="closed", service="http-proxy"),
        ],
        started_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, 12, 0, 3, tzinfo=timezone.utc),
    )


class GradeTests(unittest.TestCase):
    def test_clean_host_gets_an_a(self) -> None:
        result = ScanResult(target="t", address="1.2.3.4", ports=[80])
        self.assertEqual(result.risk_grade, "A")
        self.assertEqual(result.risk_score, 0)

    def test_critical_findings_drop_the_grade(self) -> None:
        self.assertEqual(sample_result().risk_grade, "F")


class HtmlTests(unittest.TestCase):
    def test_contains_findings_and_grade(self) -> None:
        html = build_html(sample_result())
        self.assertIn("telnet", html)
        self.assertIn("critical", html)
        self.assertIn("Risk grade", html)

    def test_is_self_contained(self) -> None:
        html = build_html(sample_result())
        self.assertNotIn("<script", html.lower())
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)

    def test_escapes_html_in_banners(self) -> None:
        result = sample_result()
        result.findings[0].banner = "<script>alert(1)</script>"
        html = build_html(result)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_closed_ports_are_not_listed(self) -> None:
        html = build_html(sample_result())
        self.assertNotIn("<td class=\"port\">8080</td>", html)


class MarkdownTests(unittest.TestCase):
    def test_table_rows(self) -> None:
        md = build_markdown(sample_result())
        self.assertIn("| 23 | telnet | critical |", md)
        self.assertIn("**Risk grade:** F", md)

    def test_pipe_in_note_is_escaped(self) -> None:
        result = sample_result()
        result.findings[1].note = "a | b"
        self.assertIn("a \\| b", build_markdown(result))


class JsonTests(unittest.TestCase):
    def test_payload_shape(self) -> None:
        payload = build_json(sample_result())
        self.assertEqual(payload["schema"], "reconx.report/2")
        self.assertEqual(len(payload["findings"]), 3)
        self.assertIn("disclaimer", payload)

    def test_is_json_serialisable(self) -> None:
        json.dumps(build_json(sample_result()))


class WriteTests(unittest.TestCase):
    def test_all_formats_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = write_reports(sample_result(), directory)
            self.assertEqual(set(paths), {"json", "csv", "html", "md"})
            for path in paths.values():
                self.assertTrue(os.path.exists(path))
                self.assertGreater(os.path.getsize(path), 0)

    def test_csv_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_reports(sample_result(), directory, formats=("csv",))["csv"]
            with open(path, newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 3)
            # Rows are severity-sorted, so the critical finding leads the file.
            self.assertEqual(rows[0]["port"], "23")
            self.assertEqual(rows[0]["severity"], "critical")
            self.assertEqual([row["port"] for row in rows], ["23", "445", "22"])

    def test_subset_of_formats(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = write_reports(sample_result(), directory, formats=("md",))
            self.assertEqual(list(paths), ["md"])


class NmapTests(unittest.TestCase):
    XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80"><state state="closed"/></port>
    </ports>
  </host>
  <os><osmatch name="Linux 5.0 - 5.14" accuracy="92"/></os>
</nmaprun>"""

    def test_open_services_parsed(self) -> None:
        parsed = parse_xml(self.XML)
        services = parsed["services"]
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["name"], "ssh")
        self.assertEqual(services[0]["version"], "9.6p1")

    def test_os_matches_parsed(self) -> None:
        self.assertIn("Linux 5.0 - 5.14", parse_xml(self.XML)["os"][0])

    def test_bad_xml_is_handled(self) -> None:
        self.assertIn("error", parse_xml("<not-xml"))


if __name__ == "__main__":
    unittest.main()
