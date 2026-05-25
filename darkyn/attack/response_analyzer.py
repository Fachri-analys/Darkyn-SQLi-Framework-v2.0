"""
darkyn/attack/response_analyzer.py
Response Analyzer — Darkyn SQLi Framework v2.0

Fitur:
- Analisis respons kompleks (JSON, HTML, XML, plaintext)
- Handling blind SQL injection (time-based, boolean-based diff)
- Adaptasi terhadap response yang "dibungkus" frontend modern
  (React/Next.js, SPA, CORS preflight, JWT-protected API)
- Deteksi anomali status code, panjang response, waktu respons
"""

from __future__ import annotations

import difflib
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class BaselineResponse:
    """Response baseline dari request normal (tanpa payload)."""

    status_code: int
    body_length: int
    response_time: float            # detik
    body_hash: str                  # MD5 hash body
    content_type: str
    is_json: bool
    json_keys: list[str] = field(default_factory=list)  # top-level JSON keys


@dataclass
class AnalysisResult:
    """Hasil analisis satu response terhadap baseline."""

    is_anomalous: bool
    anomaly_type: str               # sql_error | time_delay | boolean_diff | length_diff | status_diff
    confidence: float               # 0.0 – 1.0
    details: str
    response_time: float
    status_code: int


# ---------------------------------------------------------------------------
# SQL error & warning patterns (extended)
# ---------------------------------------------------------------------------

SQL_ERROR_SIGNATURES: dict[str, list[str]] = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "mysql_fetch_array()",
        "mysql_num_rows()",
        "supplied argument is not a valid mysql result",
        "mysql server version for the right syntax",
        "error: query was empty",
    ],
    "PostgreSQL": [
        "pg_query(): query failed",
        "pg_exec(): query failed",
        "unterminated quoted string at or near",
        "syntax error at or near",
        "column .* does not exist",
        "relation .* does not exist",
        "invalid input syntax for",
    ],
    "MSSQL": [
        "unclosed quotation mark after the character string",
        "incorrect syntax near",
        "microsoft ole db provider for sql server",
        "sql server does not exist",
        "sqlstate",
        "microsoft sql native client",
        "[microsoft][odbc sql server driver]",
    ],
    "Oracle": [
        "ora-00907",
        "ora-00933",
        "ora-01756",
        "ora-00936",
        "quoted string not properly terminated",
        "oracle error",
        "oci_parse",
    ],
    "SQLite": [
        "sqlite3.operationalerror",
        "sqlite error",
        "sqliteexception",
        "no such column",
        "unrecognized token",
    ],
    "Generic": [
        "sql syntax",
        "syntax error",
        "database error",
        "db error",
        "invalid query",
        "sql command not properly ended",
        "operationalerror",
        "pdoexception",
        "sqlexception",
        "jdbc",
        "hibernateexception",
        "org.springframework.dao",
    ],
}

# Flatten untuk quick search
ALL_SQL_ERRORS: list[tuple[str, str]] = [
    (dbms, sig)
    for dbms, sigs in SQL_ERROR_SIGNATURES.items()
    for sig in sigs
]


# ---------------------------------------------------------------------------
# Modern Frontend Response Wrapper Patterns
# ---------------------------------------------------------------------------

# Banyak SPA/Next.js/API Gateway membungkus error di dalam struktur JSON
WRAPPED_ERROR_PATHS: list[list[str]] = [
    ["error"],
    ["message"],
    ["errors", 0, "message"],
    ["errors", 0, "extensions", "code"],
    ["data", "error"],
    ["data", "message"],
    ["response", "error"],
    ["result", "error"],
    ["meta", "error"],
    ["payload", "message"],
    ["body", "error"],
    ["detail"],
    ["details"],
    ["exception"],
    ["stackTrace"],
    ["stack"],
]


# ---------------------------------------------------------------------------
# Response Analyzer
# ---------------------------------------------------------------------------

class ResponseAnalyzer:
    """
    Analisis response HTTP untuk deteksi SQL injection.

    Mendukung tiga mode deteksi:
    1. Error-based  — cari SQL error signature di body
    2. Boolean-based — bandingkan response TRUE vs FALSE condition
    3. Time-based   — deteksi delay yang tidak wajar

    Args:
        time_threshold_multiplier: Response dianggap ter-delay jika
            response_time > baseline_time * multiplier. Default 2.5x.
        length_diff_threshold: Persentase perbedaan panjang yang dianggap signifikan.
    """

    def __init__(
        self,
        time_threshold_multiplier: float = 2.5,
        length_diff_threshold: float = 0.15,
    ) -> None:
        self.time_multiplier = time_threshold_multiplier
        self.length_threshold = length_diff_threshold

    # ------------------------------------------------------------------
    # Baseline
    # ------------------------------------------------------------------

    def measure_baseline(
        self,
        session: requests.Session,
        url: str,
        method: str = "GET",
        **kwargs,
    ) -> BaselineResponse:
        """
        Ukur baseline response dari target sebelum inject payload.

        Melakukan 3 request dan ambil rata-rata waktu respons
        untuk mengurangi noise jaringan.

        Args:
            session: requests.Session.
            url: Target URL.
            method: HTTP method.

        Returns:
            BaselineResponse.
        """
        times = []
        last_resp = None

        for _ in range(3):
            start = time.perf_counter()
            last_resp = session.request(method, url, **kwargs)
            times.append(time.perf_counter() - start)

        avg_time = sum(times) / len(times)
        body = last_resp.text
        is_json = "application/json" in last_resp.headers.get("Content-Type", "")
        json_keys: list[str] = []

        if is_json:
            try:
                data = last_resp.json()
                if isinstance(data, dict):
                    json_keys = list(data.keys())
            except Exception:
                pass

        return BaselineResponse(
            status_code=last_resp.status_code,
            body_length=len(body),
            response_time=avg_time,
            body_hash=hashlib.md5(body.encode()).hexdigest(),
            content_type=last_resp.headers.get("Content-Type", ""),
            is_json=is_json,
            json_keys=json_keys,
        )

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
        response: requests.Response,
        response_time: float,
        baseline: BaselineResponse,
    ) -> AnalysisResult:
        """
        Analisis satu response terhadap baseline.

        Cek secara berurutan:
        1. SQL error signature (highest confidence)
        2. Time delay anomaly
        3. Boolean-based length diff
        4. Status code change

        Returns:
            AnalysisResult.
        """
        body = response.text
        body_lower = body.lower()
        content_type = response.headers.get("Content-Type", "")

        # ---- 1. SQL error signature ----
        for dbms, sig in ALL_SQL_ERRORS:
            if sig in body_lower:
                return AnalysisResult(
                    is_anomalous=True,
                    anomaly_type="sql_error",
                    confidence=0.95,
                    details=f"[{dbms}] SQL error signature: '{sig}'",
                    response_time=response_time,
                    status_code=response.status_code,
                )

        # ---- 2. Wrapped JSON error ----
        if "application/json" in content_type:
            wrapped = self._check_wrapped_json_error(response)
            if wrapped:
                return AnalysisResult(
                    is_anomalous=True,
                    anomaly_type="sql_error",
                    confidence=0.85,
                    details=f"SQL error in wrapped JSON: {wrapped[:150]}",
                    response_time=response_time,
                    status_code=response.status_code,
                )

        # ---- 3. Time-based delay ----
        if baseline.response_time > 0:
            threshold = baseline.response_time * self.time_multiplier
            if response_time > threshold and response_time > 2.0:
                return AnalysisResult(
                    is_anomalous=True,
                    anomaly_type="time_delay",
                    confidence=0.80,
                    details=(
                        f"Response time {response_time:.2f}s vs baseline "
                        f"{baseline.response_time:.2f}s "
                        f"({response_time/baseline.response_time:.1f}x slower)"
                    ),
                    response_time=response_time,
                    status_code=response.status_code,
                )

        # ---- 4. Status code change (prioritas lebih tinggi dari length diff) ----
        if response.status_code != baseline.status_code:
            confidence = 0.7 if response.status_code == 500 else 0.4
            return AnalysisResult(
                is_anomalous=True,
                anomaly_type="status_diff",
                confidence=confidence,
                details=(
                    f"Status code changed: {baseline.status_code} → "
                    f"{response.status_code}"
                ),
                response_time=response_time,
                status_code=response.status_code,
            )

        # ---- 5. Length-based boolean diff ----
        length_diff = abs(len(body) - baseline.body_length)
        if baseline.body_length > 0:
            diff_ratio = length_diff / baseline.body_length
            if diff_ratio > self.length_threshold:
                confidence = min(0.6, diff_ratio * 0.5)
                return AnalysisResult(
                    is_anomalous=True,
                    anomaly_type="boolean_diff",
                    confidence=confidence,
                    details=(
                        f"Response length changed: {baseline.body_length} → "
                        f"{len(body)} bytes ({diff_ratio:.1%} diff)"
                    ),
                    response_time=response_time,
                    status_code=response.status_code,
                )

        return AnalysisResult(
            is_anomalous=False,
            anomaly_type="none",
            confidence=0.0,
            details="No anomaly detected",
            response_time=response_time,
            status_code=response.status_code,
        )

    def compare_boolean(
        self,
        resp_true: requests.Response,
        resp_false: requests.Response,
    ) -> tuple[bool, float]:
        """
        Bandingkan dua response (TRUE condition vs FALSE condition).

        Digunakan untuk boolean-based blind detection:
        - TRUE: payload yang seharusnya menghasilkan data
        - FALSE: payload yang seharusnya tidak menghasilkan data

        Returns:
            (is_different, similarity_ratio)
        """
        ratio = difflib.SequenceMatcher(
            None,
            resp_true.text[:5000],
            resp_false.text[:5000],
        ).ratio()

        # Jika similarity < 0.85 → response berbeda → potensi boolean SQLi
        is_different = ratio < 0.85
        return is_different, ratio

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check_wrapped_json_error(self, response: requests.Response) -> str:
        """
        Cari SQL error di dalam JSON response yang dibungkus.

        Handles pola seperti:
        { "success": false, "error": { "message": "SQL syntax error..." } }
        { "data": null, "errors": [{ "message": "..." }] }
        """
        try:
            data = response.json()
        except Exception:
            return ""

        for path in WRAPPED_ERROR_PATHS:
            value = self._navigate_json(data, path)
            if isinstance(value, str):
                for _, sig in ALL_SQL_ERRORS:
                    if sig in value.lower():
                        return value

        return ""

    def _navigate_json(self, obj: Any, path: list) -> Any:
        """Navigate JSON object dengan path (list of keys/indices)."""
        current = obj
        for key in path:
            if isinstance(current, dict) and isinstance(key, str):
                current = current.get(key)
            elif isinstance(current, list) and isinstance(key, int):
                try:
                    current = current[key]
                except IndexError:
                    return None
            else:
                return None
            if current is None:
                return None
        return current

    def detect_dbms_from_error(self, body: str) -> Optional[str]:
        """
        Identifikasi DBMS dari pesan error.

        Returns:
            Nama DBMS atau None.
        """
        body_lower = body.lower()
        for dbms, sigs in SQL_ERROR_SIGNATURES.items():
            if dbms == "Generic":
                continue
            for sig in sigs:
                if sig in body_lower:
                    return dbms
        return None
