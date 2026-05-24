# core/crypto.py
# FIXED: BUG-01, BUG-09 - _chaos_xor pure function + AES flag in header
# FIXED: BUG-03 - dns_decode sort by sequence
import base64
import hashlib
import secrets
import zlib
import hmac
import struct
from typing import Optional, List, Dict, Tuple

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class QuantumCryptoDNS:
    """
    Fixed version:
    - BUG-01: _chaos_xor jadi pure function (tidak mutate state).
              Seeds per-round disimpan di header → decrypt bisa reproduce exact.
    - BUG-09: AES flag disimpan di header untuk consistency.
    Header format: fingerprint:aes_flag:seed0:seed1:seed2:layer6_seed:data
    """

    def __init__(self, session_id: Optional[str] = None):
        self.session_id       = session_id or secrets.token_hex(16)
        self.master_key       = secrets.token_bytes(32)
        self.rotation_counter = 0
        self._generate_round_keys()
        self._chaos_seed      = secrets.randbelow(1_000_000) / 1_000_000

    def _generate_round_keys(self):
        self.round_keys = []
        for i in range(32):
            key = hashlib.shake_256(
                self.master_key + i.to_bytes(4, 'big') + self.session_id.encode()
            ).digest(32)
            self.round_keys.append(key)

    def _chaos_xor(self, data: bytes, round_num: int, seed: float) -> Tuple[bytes, float]:
        """Pure function — tidak mutate self._chaos_seed. Return (result, final_seed)."""
        result = bytearray(data)
        r      = 3.9
        x      = seed
        for i in range(len(result)):
            x          = r * x * (1 - x)
            chaos_byte = int(x * 255) & 0xFF
            result[i] ^= chaos_byte ^ self.round_keys[round_num % 32][i % 32]
        return bytes(result), x

    def encrypt(self, data: str, layer: int = 7) -> str:
        self.rotation_counter += 1
        plain     = data.encode('utf-8')
        seeds     = []

        curr_seed = self._chaos_seed
        for i in range(min(3, layer)):
            seeds.append(curr_seed)
            plain, curr_seed = self._chaos_xor(plain, i, curr_seed)
        self._chaos_seed = curr_seed

        compressed = zlib.compress(plain, level=9)
        aes_used   = False
        if CRYPTO_AVAILABLE and layer >= 5:
            iv        = secrets.token_bytes(12)
            cipher    = Cipher(algorithms.AES(self.round_keys[16][:32]), modes.GCM(iv), backend=default_backend())
            enc_obj   = cipher.encryptor()
            encrypted = enc_obj.update(compressed) + enc_obj.finalize()
            compressed = iv + enc_obj.tag + encrypted
            aes_used   = True

        if layer >= 6:
            compressed, _ = self._chaos_xor(compressed, 7, curr_seed)

        final       = base64.b64encode(compressed).decode()
        fingerprint = hmac.new(self.round_keys[0][:16], final.encode(), hashlib.sha256).hexdigest()[:16]
        seeds_hex   = ':'.join(struct.pack('>d', s).hex() for s in seeds)
        l6seed_hex  = struct.pack('>d', curr_seed).hex()
        aes_flag    = '1' if aes_used else '0'

        return f"{fingerprint}:{aes_flag}:{seeds_hex}:{l6seed_hex}:{final}"

    def decrypt(self, enc_str: str) -> Optional[str]:
        try:
            parts = enc_str.split(':')
            # FIXED: Validate minimal panjang (BUG-03 fix)
            if len(parts) < 7:
                raise ValueError(f"Invalid format: expected >=7 parts, got {len(parts)}")

            fingerprint = parts[0]
            aes_flag    = parts[1]

            # Validate hex format before unpack
            for i, part in enumerate(parts[2:5]):
                if len(part) != 16:  # 8 bytes = 16 hex chars
                    raise ValueError(f"Invalid seed hex at index {i+2}")

            seed0       = struct.unpack('>d', bytes.fromhex(parts[2]))[0]
            seed1       = struct.unpack('>d', bytes.fromhex(parts[3]))[0]
            seed2       = struct.unpack('>d', bytes.fromhex(parts[4]))[0]
            l6seed      = struct.unpack('>d', bytes.fromhex(parts[5]))[0]
            data        = ':'.join(parts[6:])

            expected_fp = hmac.new(self.round_keys[0][:16], data.encode(), hashlib.sha256).hexdigest()[:16]
            if not hmac.compare_digest(fingerprint, expected_fp):
                return None

            decoded = base64.b64decode(data)
            decoded, _ = self._chaos_xor(decoded, 7, l6seed)

            if aes_flag == '1' and CRYPTO_AVAILABLE:
                iv, tag, ct = decoded[:12], decoded[12:28], decoded[28:]
                cipher      = Cipher(algorithms.AES(self.round_keys[16][:32]), modes.GCM(iv, tag), backend=default_backend())
                dec_obj     = cipher.decryptor()
                decoded     = dec_obj.update(ct) + dec_obj.finalize()

            decompressed = zlib.decompress(decoded)
            seeds = [seed0, seed1, seed2]
            for i in range(2, -1, -1):
                decompressed, _ = self._chaos_xor(decompressed, i, seeds[i])

            return decompressed.decode('utf-8')
        except (ValueError, struct.error, Exception) as e:
            return None

    def dns_encode(self, data: str, max_label_len: int = 63) -> List[Dict]:
        """Return list of {seq, chunk} dicts — receiver sort by seq untuk reassembly."""
        compressed = zlib.compress(data.encode(), level=9)
        b32        = base64.b32encode(compressed).decode().rstrip('=')
        return [{"seq": i // max_label_len, "chunk": b32[i:i+max_label_len]}
                for i in range(0, len(b32), max_label_len)]

    def dns_decode(self, chunk_list: List[Dict]) -> Optional[str]:
        """FIXED: Sort by seq sebelum reconstruct — aman untuk out-of-order delivery."""
        try:
            sorted_chunks = sorted(chunk_list, key=lambda x: x["seq"])
            reconstructed = ''.join(c["chunk"] for c in sorted_chunks)
            padding       = 8 - (len(reconstructed) % 8)
            if padding != 8:
                reconstructed += '=' * padding
            decoded      = base64.b32decode(reconstructed)
            decompressed = zlib.decompress(decoded)
            return decompressed.decode('utf-8')
        except Exception:
            return None

    def hash(self, data: str) -> str:
        return hashlib.sha3_512(data.encode()).hexdigest()

    def rotate_keys(self):
        self.master_key = hashlib.sha3_512(self.master_key).digest()[:32]
        self._generate_round_keys()
