# Darkyn SQLi Framework v2.0 - Security Testing Tool

⚠️ **DISCLAIMER**: Tool ini hanya untuk **authorized penetration testing, security research, CTF competitions, dan educational purposes**.

**Unauthorized access to computer systems is illegal.** Pastikan Anda memiliki izin tertulis dari pemilik target sebelum menggunakan framework ini.

## 📋 Features

- ✅ **Quantum Crypto DNS**: Enkripsi 7-layer dengan chaos XOR + AES-256-GCM
- ✅ **TLS Fingerprint JA3/JA4**: Impersonate Chrome 124 via curl_cffi
- ✅ **Polymorphic Payload Engine**: Setiap payload unik, bypass WAF signature
- ✅ **Time-Based Binary Search**: 95→7 requests/char untuk blind extraction  
- ✅ **Union-Based Extractor**: Database enum & data dumping
- ✅ **Stealth DNS Tunneling**: Exfiltrate via DNS queries dengan rate limiting
- ✅ **Multi-DB Support**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite

## 📁 Folder Structure (AMAN)

```
darkyn-framework/
├── README.md                          # Ini (disclaimer + docs)
├── LICENSE                            # Pemakaian hanya authorized testing
├── .gitignore                         # Exclude sensitive files
├── requirements.txt                   # Dependencies
├── setup.py                           # Install script
│
├── darkyn/
│   ├── __init__.py                   # Package init
│   ├── core/
│   │   ├── __init__.py
│   │   ├── crypto.py                 # Quantum Crypto DNS (FIXED)
│   │   ├── http_client.py            # TLS Fingerprint client
│   │   ├── exceptions.py             # Custom exceptions
│   │   └── types.py                  # Enums & types
│   │
│   ├── attack/
│   │   ├── __init__.py
│   │   ├── injection_engine.py       # SQLi detection & exploitation
│   │   ├── payloads.py               # Payload arsenal
│   │   ├── polymorphic.py            # Obfuscation engine
│   │   ├── union_extractor.py        # Union-based extraction
│   │   ├── time_blind_extractor.py   # Binary search time-based
│   │   └── dns_tunnel.py             # DNS exfiltration
│   │
│   ├── cli.py                        # Command-line interface
│   └── framework.py                  # Main framework class
│
├── tests/
│   ├── __init__.py
│   ├── test_crypto.py                # Quantum crypto tests
│   ├── test_payloads.py              # Payload tests
│   ├── test_polymorphic.py           # Obfuscation tests
│   └── test_binary_search.py         # Binary search algorithm
│
├── examples/
│   ├── basic_usage.py                # Contoh dasar
│   ├── blind_extraction.py           # Time-based blind demo
│   └── full_attack.py                # Full automated attack
│
└── docs/
    ├── INSTALL.md                    # Installation guide
    ├── USAGE.md                      # Detailed usage
    ├── API.md                        # API reference
    └── BUGFIXES.md                   # Daftar bug fixes v2
git clone <repo>
cd darkyn-framework
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 2. Run
python -m darkyn.cli
```

## 📊 Bug Fixes v2.0

Lihat `BUGFIXES.md` untuk daftar lengkap perbaikan dari v1.
