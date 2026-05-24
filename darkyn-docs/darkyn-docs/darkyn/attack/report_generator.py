"""
darkyn/attack/report_generator.py
HTML & JSON Report Generator — Darkyn SQLi Framework v2.0

Generate laporan pentest dari hasil scan dalam format
HTML (human-readable) dan JSON (machine-readable).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Satu temuan SQLi."""

    parameter: str
    technique: str                    # time-based, union, boolean, error
    dbms: Optional[str]
    severity: str                     # Critical / High / Medium / Low
    cvss_score: float
    evidence_request: str
    evidence_response: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    """Laporan lengkap satu sesi scan."""

    target_url: str
    scan_mode: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration_seconds: float = 0.0
    waf_detected: bool = False
    waf_name: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)
    scanner_version: str = "2.0.0"
    tester: str = "Darkyn SQLi Framework"

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def risk_level(self) -> str:
        if not self.findings:
            return "None"
        max_cvss = max(f.cvss_score for f in self.findings)
        if max_cvss >= 9.0:
            return "Critical"
        elif max_cvss >= 7.0:
            return "High"
        elif max_cvss >= 4.0:
            return "Medium"
        return "Low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url":       self.target_url,
            "scan_mode":        self.scan_mode,
            "timestamp":        self.timestamp,
            "duration_seconds": self.duration_seconds,
            "scanner_version":  self.scanner_version,
            "tester":           self.tester,
            "waf_detected":     self.waf_detected,
            "waf_name":         self.waf_name,
            "risk_level":       self.risk_level,
            "total_findings":   self.total_findings,
            "findings":         [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# CVSS helper
# ---------------------------------------------------------------------------

CVSS_MAP: dict[str, float] = {
    "time-based":  7.5,
    "union":       9.1,
    "boolean":     7.5,
    "error-based": 8.0,
}

REMEDIATION_MAP: dict[str, str] = {
    "time-based": (
        "Gunakan parameterized queries / prepared statements. "
        "Jangan pernah interpolasi input user ke SQL string langsung. "
        "Terapkan WAF sebagai defense-in-depth."
    ),
    "union": (
        "Gunakan ORM atau prepared statements. "
        "Batasi privilege database user (principle of least privilege). "
        "Disable error verbose di production."
    ),
    "boolean": (
        "Validasi dan sanitasi semua input. "
        "Gunakan allowlist untuk karakter yang diizinkan. "
        "Terapkan prepared statements di semua query."
    ),
    "error-based": (
        "Disable detailed database error messages di production. "
        "Gunakan generic error page. "
        "Terapkan prepared statements."
    ),
}


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """
    Generate laporan pentest dalam format HTML dan JSON.

    Args:
        company_name: Nama perusahaan penguji (opsional, untuk header report).
    """

    def __init__(self, company_name: str = "Security Researcher") -> None:
        self.company_name = company_name

    def generate(
        self,
        report: ScanReport,
        output_path: str,
        fmt: str = "html",
    ) -> str:
        """
        Generate laporan ke file.

        Args:
            report: ScanReport dari hasil scan.
            output_path: Path file output.
            fmt: Format output: 'html' atau 'json'.

        Returns:
            Absolute path file yang dibuat.

        Raises:
            ValueError: Jika format tidak dikenal.
        """
        fmt = fmt.lower()
        if fmt == "html":
            content = self._render_html(report)
        elif fmt == "json":
            content = self._render_json(report)
        else:
            raise ValueError(f"Unknown format: {fmt!r}. Use 'html' or 'json'.")

        abs_path = os.path.abspath(output_path)
        with open(abs_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        return abs_path

    # ------------------------------------------------------------------
    # JSON renderer
    # ------------------------------------------------------------------

    def _render_json(self, report: ScanReport) -> str:
        """Serialize ScanReport ke JSON string."""
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # HTML renderer
    # ------------------------------------------------------------------

    def _render_html(self, report: ScanReport) -> str:
        """Render ScanReport ke HTML report."""

        severity_colors = {
            "Critical": "#e74c3c",
            "High":     "#e67e22",
            "Medium":   "#f1c40f",
            "Low":      "#2ecc71",
            "None":     "#95a5a6",
        }
        risk_color = severity_colors.get(report.risk_level, "#95a5a6")

        findings_html = ""
        for i, f in enumerate(report.findings, 1):
            sev_color = severity_colors.get(f.severity, "#95a5a6")
            findings_html += f"""
            <div class="finding-card">
              <div class="finding-header">
                <span class="finding-num">#{i}</span>
                <span class="finding-param">Parameter: <code>{f.parameter}</code></span>
                <span class="badge" style="background:{sev_color}">{f.severity}</span>
                <span class="cvss">CVSS: {f.cvss_score}</span>
              </div>
              <table class="detail-table">
                <tr><td>Technique</td><td><code>{f.technique}</code></td></tr>
                <tr><td>DBMS</td><td>{f.dbms or "Unknown"}</td></tr>
              </table>
              <h4>Evidence — Request</h4>
              <pre class="code-block">{self._escape(f.evidence_request)}</pre>
              <h4>Evidence — Response (snippet)</h4>
              <pre class="code-block">{self._escape(f.evidence_response)}</pre>
              <h4>Remediation</h4>
              <p class="remediation">{f.remediation}</p>
            </div>"""

        if not report.findings:
            findings_html = '<p class="no-finding">✅ Tidak ada SQLi yang terdeteksi.</p>'

        waf_info = (
            f"<span class='badge-waf'>⚔️ {report.waf_name}</span>"
            if report.waf_detected and report.waf_name
            else "<span class='badge-waf-none'>Tidak terdeteksi</span>"
        )

        return f"""<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Darkyn SQLi Report — {report.target_url}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
    .container {{ max-width: 960px; margin: 0 auto; padding: 32px 20px; }}

    header {{ border-bottom: 2px solid #30363d; padding-bottom: 24px; margin-bottom: 32px; }}
    header h1 {{ font-size: 1.8rem; color: #58a6ff; }}
    header p {{ color: #8b949e; margin-top: 4px; }}

    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .meta-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }}
    .meta-card .label {{ font-size: .75rem; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; }}
    .meta-card .value {{ font-size: 1.1rem; font-weight: 600; margin-top: 4px; }}

    .risk-banner {{ background: {risk_color}22; border: 1px solid {risk_color}; border-radius: 8px;
                    padding: 16px 20px; margin-bottom: 32px; display: flex; align-items: center; gap: 12px; }}
    .risk-banner .risk-label {{ font-size: 1.3rem; font-weight: 700; color: {risk_color}; }}

    .section-title {{ font-size: 1.1rem; font-weight: 600; color: #58a6ff;
                      border-bottom: 1px solid #30363d; padding-bottom: 8px; margin-bottom: 16px; }}

    .finding-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                     padding: 20px; margin-bottom: 20px; }}
    .finding-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }}
    .finding-num {{ font-weight: 700; color: #8b949e; }}
    .finding-param {{ flex: 1; }}
    .badge {{ padding: 2px 10px; border-radius: 20px; font-size: .8rem; font-weight: 600; color: #fff; }}
    .cvss {{ font-size: .85rem; color: #8b949e; }}

    .detail-table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; }}
    .detail-table td {{ padding: 6px 12px; border: 1px solid #30363d; }}
    .detail-table td:first-child {{ width: 120px; color: #8b949e; font-size: .85rem; }}

    h4 {{ font-size: .9rem; color: #8b949e; margin: 12px 0 6px; }}
    .code-block {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
                   padding: 12px; font-family: monospace; font-size: .82rem;
                   white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; }}
    .remediation {{ background: #1a2a1a; border-left: 3px solid #2ecc71;
                    padding: 10px 14px; border-radius: 0 6px 6px 0; font-size: .9rem; }}

    .no-finding {{ color: #2ecc71; padding: 20px; text-align: center; }}
    .badge-waf {{ background: #e67e2222; border: 1px solid #e67e22; color: #e67e22;
                  padding: 2px 10px; border-radius: 20px; font-size: .85rem; }}
    .badge-waf-none {{ color: #8b949e; font-size: .85rem; }}

    footer {{ margin-top: 48px; padding-top: 20px; border-top: 1px solid #30363d;
              text-align: center; color: #8b949e; font-size: .8rem; }}
    code {{ background: #30363d; padding: 1px 5px; border-radius: 4px; font-size: .9em; }}
  </style>
</head>
<body>
<div class="container">

  <header>
    <h1>🔍 Darkyn SQLi Framework — Scan Report</h1>
    <p>Generated by {self.company_name} &bull; {report.timestamp}</p>
  </header>

  <div class="meta-grid">
    <div class="meta-card">
      <div class="label">Target</div>
      <div class="value" style="font-size:.85rem;word-break:break-all">{report.target_url}</div>
    </div>
    <div class="meta-card">
      <div class="label">Scan Mode</div>
      <div class="value">{report.scan_mode}</div>
    </div>
    <div class="meta-card">
      <div class="label">Duration</div>
      <div class="value">{report.duration_seconds:.1f}s</div>
    </div>
    <div class="meta-card">
      <div class="label">Findings</div>
      <div class="value">{report.total_findings}</div>
    </div>
    <div class="meta-card">
      <div class="label">WAF</div>
      <div class="value">{waf_info}</div>
    </div>
    <div class="meta-card">
      <div class="label">Scanner</div>
      <div class="value">v{report.scanner_version}</div>
    </div>
  </div>

  <div class="risk-banner">
    <span>Overall Risk Level:</span>
    <span class="risk-label">{report.risk_level}</span>
  </div>

  <div class="section-title">Findings ({report.total_findings})</div>
  {findings_html}

  <footer>
    ⚠️ Laporan ini hanya untuk authorized security testing.<br>
    Darkyn SQLi Framework v{report.scanner_version} &bull; {report.timestamp}
  </footer>

</div>
</body>
</html>"""

    @staticmethod
    def _escape(text: str) -> str:
        """HTML-escape string untuk code blocks."""
        return (
            text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
        )
