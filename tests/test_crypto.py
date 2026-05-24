# tests/test_crypto.py
import unittest
from darkyn.core.crypto import QuantumCryptoDNS

class TestQuantumCryptoDNS(unittest.TestCase):
    """Test suite untuk Quantum Crypto DNS dengan bug fixes."""

    def setUp(self):
        self.crypto = QuantumCryptoDNS()

    def test_encrypt_decrypt_basic(self):
        """Test: encrypt data dan decrypt harus identik."""
        original = "SELECT database()"
        encrypted = self.crypto.encrypt(original, layer=7)
        decrypted = self.crypto.decrypt(encrypted)
        self.assertEqual(original, decrypted)

    def test_encrypt_decrypt_long_data(self):
        """Test: handle long strings."""
        original = "admin' OR '1'='1'; DROP TABLE users;--" * 10
        encrypted = self.crypto.encrypt(original, layer=7)
        decrypted = self.crypto.decrypt(encrypted)
        self.assertEqual(original, decrypted)

    def test_chaos_xor_pure_function(self):
        """Test: _chaos_xor tidak mutate state (BUG-01 fix)."""
        data = b"test_payload"
        seed1 = 0.5

        result1, final_seed1 = self.crypto._chaos_xor(data, 0, seed1)
        result2, final_seed2 = self.crypto._chaos_xor(data, 0, seed1)

        # Hasil harus identik untuk seed yang sama
        self.assertEqual(result1, result2)
        self.assertEqual(final_seed1, final_seed2)

    def test_dns_encode_decode_order_independent(self):
        """Test: dns_decode sort by seq (BUG-03 fix) - order-independent."""
        data = "SELECT table_name FROM information_schema.tables"
        chunks = self.crypto.dns_encode(data, max_label_len=20)

        # Shuffle chunks
        import random
        shuffled = chunks.copy()
        random.shuffle(shuffled)

        # Decode shuffled chunks - harus sama dengan original
        decoded = self.crypto.dns_decode(shuffled)
        self.assertEqual(data, decoded)

    def test_encrypt_header_format(self):
        """Test: cek format header yang benar (BUG-09 fix)."""
        data = "test123"
        encrypted = self.crypto.encrypt(data, layer=7)

        # Format: fingerprint:aes_flag:seed0:seed1:seed2:l6seed:final
        parts = encrypted.split(':')
        self.assertGreaterEqual(len(parts), 7)

        # AES flag harus 0 atau 1
        aes_flag = parts[1]
        self.assertIn(aes_flag, ['0', '1'])

        # Seeds harus valid hex (16 chars each = 8 bytes)
        for i in range(2, 6):
            self.assertEqual(len(parts[i]), 16)
            bytes.fromhex(parts[i])  # Harus valid hex

    def test_decrypt_invalid_header(self):
        """Test: invalid header harus return None (tidak crash)."""
        invalid_cases = [
            "tooshort",
            "a:b:c",
            "fingerprint:x:badhex:seed1:seed2:seed3:data",  # bad hex
        ]

        for invalid in invalid_cases:
            result = self.crypto.decrypt(invalid)
            self.assertIsNone(result)

    def test_hash_consistency(self):
        """Test: hash sama untuk data sama."""
        data = "darkyn_test_data"
        hash1 = self.crypto.hash(data)
        hash2 = self.crypto.hash(data)
        self.assertEqual(hash1, hash2)

if __name__ == '__main__':
    unittest.main()
