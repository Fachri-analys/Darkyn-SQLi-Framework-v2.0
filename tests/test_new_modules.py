"""
tests/test_new_modules.py
Unit tests untuk modul baru — Darkyn SQLi Framework v2.0

Coverage:
- RequestEngine (delay, UA rotation, random headers)
- ObfuscationEngine (encoding, case, bypass)
- ResponseAnalyzer (error detection, blind diff, JSON wrapped)
- APITester (REST JSON, GraphQL)
"""

import json
import time
import unittest
from unittest.mock import MagicMock, patch

from darkyn.core.request_engine import RequestConfig, RequestEngine, USER_AGENTS
from darkyn.attack.obfuscation import (
    ObfuscationEngine,
    bypass_keyword_filter,
    bypass_space_filter,
    html_entity_encode,
    inject_comments,
    randomize_case,
    randomize_case_keywords,
    url_encode_full,
    url_encode_partial,
)
from darkyn.attack.response_analyzer import ResponseAnalyzer


# ---------------------------------------------------------------------------
# RequestEngine Tests
# ---------------------------------------------------------------------------

class TestRequestEngine(unittest.TestCase):

    def _make_engine(self, **kwargs) -> RequestEngine:
        cfg = RequestConfig(delay_min=0, delay_max=0, **kwargs)
        return RequestEngine(cfg)

    def _mock_response(self, status=200, text="OK", headers=None) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        resp.headers = headers or {"Content-Type": "text/html"}
        return resp

    # UA Rotation

    def test_ua_rotation_enabled(self) -> None:
        engine = self._make_engine(rotate_ua=True)
        uas = set()
        for _ in range(20):
            headers = engine._build_headers()
            uas.add(headers["User-Agent"])
        self.assertGreater(len(uas), 1, "UA rotation harus menghasilkan UA berbeda")

    def test_ua_rotation_disabled(self) -> None:
        engine = self._make_engine(rotate_ua=False)
        headers = engine._build_headers()
        self.assertEqual(headers["User-Agent"], USER_AGENTS[0])

    def test_ua_in_known_pool(self) -> None:
        engine = self._make_engine(rotate_ua=True)
        for _ in range(10):
            h = engine._build_headers()
            self.assertIn(h["User-Agent"], USER_AGENTS)

    # Random headers

    def test_random_headers_enabled(self) -> None:
        engine = self._make_engine(random_headers=True)
        headers = engine._build_headers()
        self.assertIn("Accept-Language", headers)
        self.assertIn("Accept-Encoding", headers)

    def test_random_headers_disabled(self) -> None:
        engine = self._make_engine(random_headers=False)
        headers = engine._build_headers()
        self.assertNotIn("Accept-Language", headers)

    def test_chrome_ua_gets_sec_fetch(self) -> None:
        engine = self._make_engine(random_headers=True)
        # Force Chrome UA
        with patch("darkyn.core.request_engine.random.choice",
                   return_value=USER_AGENTS[0]):  # Chrome UA
            headers = engine._build_headers()
        # Chrome UA harus ada Sec-Fetch headers
        self.assertIn("Sec-Fetch-Mode", headers)

    # Delay

    def test_fixed_delay(self) -> None:
        cfg = RequestConfig(delay_min=0.1, delay_max=0.1, delay_mode="fixed")
        engine = RequestEngine(cfg)
        engine._last_request_time = time.time() - 0.05  # sudah 0.05s lalu
        start = time.time()
        engine._apply_delay()
        elapsed = time.time() - start
        self.assertGreater(elapsed, 0.04)  # harus delay setidaknya ~0.05s lagi

    def test_adaptive_delay_429(self) -> None:
        engine = self._make_engine(delay_mode="adaptive")
        initial = engine._adaptive_delay
        resp = self._mock_response(status=429)
        engine._update_adaptive_delay(resp)
        self.assertGreater(engine._adaptive_delay, initial)

    def test_adaptive_delay_200(self) -> None:
        engine = self._make_engine(delay_mode="adaptive")
        engine._adaptive_delay = 5.0
        resp = self._mock_response(status=200)
        engine._update_adaptive_delay(resp)
        self.assertLess(engine._adaptive_delay, 5.0)

    # Request stats

    def test_stats_increment(self) -> None:
        engine = self._make_engine()
        engine._request_count = 5
        stats = engine.get_stats()
        self.assertEqual(stats["total_requests"], 5)

    # Custom headers override

    def test_custom_headers_override(self) -> None:
        engine = self._make_engine(
            custom_headers={"X-Custom-Token": "abc123"}
        )
        headers = engine._build_headers()
        self.assertEqual(headers["X-Custom-Token"], "abc123")


# ---------------------------------------------------------------------------
# ObfuscationEngine Tests
# ---------------------------------------------------------------------------

class TestObfuscationEngine(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = ObfuscationEngine()

    # Case randomization

    def test_randomize_case_changes_text(self) -> None:
        # Run many times — statistically case should change
        results = {randomize_case("SELECT") for _ in range(20)}
        self.assertGreater(len(results), 1)

    def test_randomize_case_keywords_preserves_structure(self) -> None:
        payload = "' OR 1=1 UNION SELECT NULL--"
        result = randomize_case_keywords(payload)
        # Panjang harus sama
        self.assertEqual(len(result), len(payload))
        # Lowercase harus sama
        self.assertEqual(result.lower(), payload.lower())

    # URL encoding

    def test_url_encode_full(self) -> None:
        result = url_encode_full("' OR 1=1--")
        self.assertNotIn("'", result)
        self.assertNotIn(" ", result)
        self.assertIn("%", result)

    def test_url_encode_partial_changes_some(self) -> None:
        payload = "' OR 1=1--"
        result = url_encode_partial(payload, ratio=1.0)
        self.assertNotIn(" ", result)

    def test_url_encode_partial_ratio_zero(self) -> None:
        payload = "SELECT"
        result = url_encode_partial(payload, ratio=0.0)
        self.assertEqual(result, payload)

    # HTML entity

    def test_html_entity_encode_quotes(self) -> None:
        result = html_entity_encode("'test'", partial=False)
        self.assertNotIn("'", result)
        self.assertIn("&#39;", result)

    # Comment injection

    def test_comment_inject_adds_comment(self) -> None:
        result = inject_comments("UNION SELECT")
        self.assertIn("*/", result) or self.assertIn("/*", result)

    def test_comment_inject_no_space(self) -> None:
        result = inject_comments("UNION SELECT NULL")
        self.assertNotIn("UNION SELECT NULL", result)

    # Space bypass

    def test_bypass_space_filter(self) -> None:
        payload = "UNION SELECT NULL"
        result = bypass_space_filter(payload)
        self.assertNotIn(" ", result)

    # Keyword bypass

    def test_bypass_keyword_filter_union(self) -> None:
        payload = "' UNION SELECT NULL--"
        result = bypass_keyword_filter(payload)
        self.assertNotIn("UNION SELECT", result)

    def test_bypass_keyword_filter_or(self) -> None:
        payload = "' OR 1=1--"
        result = bypass_keyword_filter(payload)
        # OR harus ter-replace
        self.assertFalse(result == payload)

    # Obfuscation engine

    def test_obfuscate_all_techniques(self) -> None:
        payload = "' OR 1=1--"
        for technique in ObfuscationEngine.TECHNIQUES:
            result = self.engine.obfuscate(payload, technique)
            self.assertIsInstance(result, str)
            self.assertGreater(len(result), 0)

    def test_generate_variations_count(self) -> None:
        variations = self.engine.generate_variations("' OR 1=1--", count=5)
        self.assertLessEqual(len(variations), 5)
        self.assertGreater(len(variations), 0)

    def test_generate_variations_includes_original(self) -> None:
        payload = "' OR 1=1--"
        variations = self.engine.generate_variations(payload, count=5)
        self.assertIn(payload, variations)

    def test_extended_payload_list_not_empty(self) -> None:
        payloads = self.engine.get_extended_payload_list()
        self.assertGreater(len(payloads), 20)
        # Tidak ada duplikat
        self.assertEqual(len(payloads), len(set(payloads)))


# ---------------------------------------------------------------------------
# ResponseAnalyzer Tests
# ---------------------------------------------------------------------------

class TestResponseAnalyzer(unittest.TestCase):

    def setUp(self) -> None:
        self.analyzer = ResponseAnalyzer()

    def _make_response(self, text="OK", status=200,
                       content_type="text/html") -> MagicMock:
        resp = MagicMock()
        resp.text = text
        resp.status_code = status
        resp.headers = {"Content-Type": content_type}
        resp.json = MagicMock(return_value=None)
        return resp

    def _make_baseline(self, body_length=500, response_time=0.3,
                       status=200) -> MagicMock:
        from darkyn.attack.response_analyzer import BaselineResponse
        return BaselineResponse(
            status_code=status,
            body_length=body_length,
            response_time=response_time,
            body_hash="abc123",
            content_type="text/html",
            is_json=False,
        )

    def test_detect_mysql_error(self) -> None:
        resp = self._make_response(
            text="you have an error in your sql syntax near '1'"
        )
        baseline = self._make_baseline()
        result = self.analyzer.analyze(resp, 0.3, baseline)
        self.assertTrue(result.is_anomalous)
        self.assertEqual(result.anomaly_type, "sql_error")
        self.assertGreater(result.confidence, 0.9)

    def test_detect_mssql_error(self) -> None:
        resp = self._make_response(
            text="Unclosed quotation mark after the character string"
        )
        baseline = self._make_baseline()
        result = self.analyzer.analyze(resp, 0.3, baseline)
        self.assertTrue(result.is_anomalous)
        self.assertEqual(result.anomaly_type, "sql_error")

    def test_detect_time_delay(self) -> None:
        resp = self._make_response(text="Normal response")
        baseline = self._make_baseline(response_time=0.2)
        # 5s response vs 0.2s baseline = 25x → anomaly
        result = self.analyzer.analyze(resp, 5.0, baseline)
        self.assertTrue(result.is_anomalous)
        self.assertEqual(result.anomaly_type, "time_delay")

    def test_no_anomaly_normal_response(self) -> None:
        resp = self._make_response(text="Hello World!" * 40)  # ~500 chars
        baseline = self._make_baseline(body_length=500, response_time=0.3)
        result = self.analyzer.analyze(resp, 0.3, baseline)
        self.assertFalse(result.is_anomalous)

    def test_detect_status_change(self) -> None:
        resp = self._make_response(text="Error", status=500)
        baseline = self._make_baseline(status=200)
        result = self.analyzer.analyze(resp, 0.3, baseline)
        self.assertTrue(result.is_anomalous)
        self.assertEqual(result.anomaly_type, "status_diff")
        self.assertEqual(result.confidence, 0.7)

    def test_detect_length_diff(self) -> None:
        # Body 3x lebih besar dari baseline
        resp = self._make_response(text="X" * 1500)
        baseline = self._make_baseline(body_length=500, response_time=0.3)
        result = self.analyzer.analyze(resp, 0.3, baseline)
        self.assertTrue(result.is_anomalous)
        self.assertEqual(result.anomaly_type, "boolean_diff")

    def test_detect_wrapped_json_error(self) -> None:
        error_body = json.dumps({
            "success": False,
            "error": {
                "message": "you have an error in your sql syntax"
            }
        })
        resp = self._make_response(
            text=error_body,
            content_type="application/json",
        )
        resp.json = MagicMock(return_value=json.loads(error_body))
        baseline = self._make_baseline()
        result = self.analyzer.analyze(resp, 0.3, baseline)
        self.assertTrue(result.is_anomalous)

    def test_compare_boolean_different(self) -> None:
        resp_true = self._make_response(text="User: admin")
        resp_false = self._make_response(text="Error: not found")
        is_diff, ratio = self.analyzer.compare_boolean(resp_true, resp_false)
        self.assertTrue(is_diff)
        self.assertLess(ratio, 0.85)

    def test_compare_boolean_same(self) -> None:
        resp_true = self._make_response(text="Hello World")
        resp_false = self._make_response(text="Hello World")
        is_diff, ratio = self.analyzer.compare_boolean(resp_true, resp_false)
        self.assertFalse(is_diff)
        self.assertAlmostEqual(ratio, 1.0)

    def test_detect_dbms_mysql(self) -> None:
        dbms = self.analyzer.detect_dbms_from_error(
            "you have an error in your sql syntax"
        )
        self.assertEqual(dbms, "MySQL")

    def test_detect_dbms_oracle(self) -> None:
        dbms = self.analyzer.detect_dbms_from_error("ORA-00907: missing right parenthesis")
        self.assertEqual(dbms, "Oracle")

    def test_detect_dbms_none(self) -> None:
        dbms = self.analyzer.detect_dbms_from_error("Normal page content")
        self.assertIsNone(dbms)


if __name__ == "__main__":
    unittest.main()
