"""
tests/test_report_generator.py
Unit tests untuk ReportGenerator — Darkyn SQLi Framework v2.0
"""

import json
import os
import tempfile
import unittest

from darkyn.attack.report_generator import (
    Finding,
    ReportGenerator,
    ScanReport,
    CVSS_MAP,
    REMEDIATION_MAP,
)


def _sample_report() -> ScanReport:
    return ScanReport(
        target_url="http://testphp.vulnweb.com/artists.php?artist=1",
        scan_mode="HYBRID",
        duration_seconds=12.4,
        waf_detected=False,
        findings=[
            Finding(
                parameter="artist",
                technique="time-based",
                dbms="MySQL",
                severity="High",
                cvss_score=7.5,
                evidence_request="GET /artists.php?artist=1' HTTP/1.1",
                evidence_response="Response delayed 5.2s",
                remediation=REMEDIATION_MAP["time-based"],
            )
        ],
    )


class TestScanReport(unittest.TestCase):

    def test_risk_level_high(self) -> None:
        report = _sample_report()
        self.assertEqual(report.risk_level, "High")

    def test_risk_level_none_when_no_findings(self) -> None:
        report = ScanReport(target_url="http://example.com", scan_mode="AUTO")
        self.assertEqual(report.risk_level, "None")

    def test_risk_level_critical(self) -> None:
        report = ScanReport(
            target_url="http://example.com",
            scan_mode="HYBRID",
            findings=[
                Finding(
                    parameter="id",
                    technique="union",
                    dbms="MySQL",
                    severity="Critical",
                    cvss_score=9.1,
                    evidence_request="GET /?id=1 UNION SELECT...",
                    evidence_response="admin:hash",
                    remediation=REMEDIATION_MAP["union"],
                )
            ],
        )
        self.assertEqual(report.risk_level, "Critical")

    def test_total_findings_count(self) -> None:
        report = _sample_report()
        self.assertEqual(report.total_findings, 1)

    def test_to_dict_keys(self) -> None:
        report = _sample_report()
        d = report.to_dict()
        for key in ["target_url", "scan_mode", "findings", "risk_level", "total_findings"]:
            self.assertIn(key, d)


class TestReportGenerator(unittest.TestCase):

    def setUp(self) -> None:
        self.gen = ReportGenerator(company_name="Test Tester")
        self.report = _sample_report()
        self.tmpdir = tempfile.mkdtemp()

    def _out(self, name: str) -> str:
        return os.path.join(self.tmpdir, name)

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def test_generate_json_creates_file(self) -> None:
        path = self._out("report.json")
        self.gen.generate(self.report, path, fmt="json")
        self.assertTrue(os.path.exists(path))

    def test_generate_json_valid_structure(self) -> None:
        path = self._out("report2.json")
        self.gen.generate(self.report, path, fmt="json")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["target_url"], self.report.target_url)
        self.assertEqual(data["total_findings"], 1)
        self.assertIsInstance(data["findings"], list)

    def test_generate_json_no_findings(self) -> None:
        empty = ScanReport(target_url="http://clean.com", scan_mode="AUTO")
        path = self._out("empty.json")
        self.gen.generate(empty, path, fmt="json")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["total_findings"], 0)
        self.assertEqual(data["risk_level"], "None")

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def test_generate_html_creates_file(self) -> None:
        path = self._out("report.html")
        self.gen.generate(self.report, path, fmt="html")
        self.assertTrue(os.path.exists(path))

    def test_generate_html_contains_target(self) -> None:
        path = self._out("report2.html")
        self.gen.generate(self.report, path, fmt="html")
        content = open(path, encoding="utf-8").read()
        self.assertIn(self.report.target_url, content)

    def test_generate_html_contains_finding_param(self) -> None:
        path = self._out("report3.html")
        self.gen.generate(self.report, path, fmt="html")
        content = open(path, encoding="utf-8").read()
        self.assertIn("artist", content)

    def test_generate_html_no_findings_message(self) -> None:
        empty = ScanReport(target_url="http://clean.com", scan_mode="AUTO")
        path = self._out("empty.html")
        self.gen.generate(empty, path, fmt="html")
        content = open(path, encoding="utf-8").read()
        self.assertIn("Tidak ada SQLi", content)

    # ------------------------------------------------------------------
    # Invalid format
    # ------------------------------------------------------------------

    def test_invalid_format_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.gen.generate(self.report, self._out("x.pdf"), fmt="pdf")

    # ------------------------------------------------------------------
    # HTML escape
    # ------------------------------------------------------------------

    def test_escape_xss_in_evidence(self) -> None:
        report = ScanReport(
            target_url="http://example.com",
            scan_mode="HYBRID",
            findings=[
                Finding(
                    parameter="q",
                    technique="error-based",
                    dbms="MySQL",
                    severity="High",
                    cvss_score=8.0,
                    evidence_request="GET /?q=<script>alert(1)</script>",
                    evidence_response="<error>syntax near...</error>",
                    remediation=REMEDIATION_MAP["error-based"],
                )
            ],
        )
        path = self._out("xss.html")
        self.gen.generate(report, path, fmt="html")
        content = open(path, encoding="utf-8").read()
        self.assertNotIn("<script>", content)
        self.assertIn("&lt;script&gt;", content)


if __name__ == "__main__":
    unittest.main()
