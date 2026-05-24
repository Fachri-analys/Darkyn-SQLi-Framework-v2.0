# Darkyn SQLi Framework v2.0

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/github/license/Fachri-analys/Darkyn-SQLi-Framework-v2.0)
![Version](https://img.shields.io/badge/version-2.0.0-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-lightgrey)
![Status](https://img.shields.io/badge/status-active-brightgreen)

> ⚠️ **DISCLAIMER**: Tool ini hanya untuk **authorized penetration testing, security research, CTF competitions, dan educational purposes**.
> **Unauthorized access to computer systems is illegal.** Pastikan Anda memiliki izin tertulis dari pemilik target sebelum menggunakan framework ini.

---

## 🔍 What is Darkyn?

Darkyn SQLi Framework adalah security testing tool berbasis Python yang dirancang untuk mendeteksi dan menganalisis SQL Injection vulnerability pada web application secara otomatis, dengan kontrol manual di tahap kritis.

Framework ini menggabungkan:
- Detection engine yang akurat dengan false positive rendah
- WAF fingerprinting untuk context awareness
- HTML/JSON report generator siap pakai untuk dokumentasi pentest
- Mode hybrid: otomatis untuk scanning, manual untuk aksi sensitif

---

## ✨ Features

| Feature | Status | Keterangan |
|---|---|---|
| SQLi Detection (time-based, union, boolean, error) | ✅ | Multi-teknik |
| WAF Fingerprinting | ✅ | 15+ vendor (Cloudflare, ModSecurity, Akamai, dll) |
| Polymorphic Payload Engine | ✅ | Bypass signature WAF |
| Binary Search Time-Based | ✅ | 95→7 requests/char (13x efisien) |
| Union-Based Extractor | ✅ | DB enum & data discovery |
| Multi-DB Support | ✅ | MySQL, PostgreSQL, MSSQL, Oracle, SQLite |
| HTML/JSON Report Generator | ✅ | Laporan pentest siap pakai |
| TLS Fingerprint JA3/JA4 | ✅ | Impersonate Chrome 124 |
| AES-256-GCM Crypto Layer | ✅ | Enkripsi internal |
| Proxy Support | ✅ | Burp Suite compatible |
| Config File (YAML) | ✅ | Repeatability |
| Hybrid Mode | ✅ | Auto scan + manual exploitation gate |

---

## 🚀 Quick Start

```bash
# Clone & install
git clone https://github.com/Fachri-analys/Darkyn-SQLi-Framework-v2.0.git
cd Darkyn-SQLi-Framework-v2.0
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Scan (authorized target only)
python -m darkyn.cli --target "https://target.com/page?id=1"
```

---

## 📊 Scan Modes

```
AUTO    → Detection only, tidak ada exploitation
HYBRID  → Otomatis + manual gate sebelum aksi sensitif (default)
MANUAL  → Full user-driven, step-by-step
```

---

## 📁 Structure

```
darkyn-framework/
├── darkyn/
│   ├── core/
│   │   ├── crypto.py           # AES-256-GCM layer
│   │   ├── http_client.py      # TLS fingerprint client
│   │   ├── exceptions.py       # Custom exceptions
│   │   └── types.py            # Enums & data classes
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
```

## 🔒 .gitignore

```
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual env
venv/
ENV/
env/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Local config (CRITICAL - never commit!)
config.local.json
.env
.env.local
secrets.json
credentials.json
*.pem
*.key
*.crt

# Target/victim info (never commit!)
targets.json
results/
dumps/
exfil/

# Testing
.pytest_cache/
.coverage
htmlcov/

# Logs
*.log
logs/
```

## 🔧 Requirements

```
cryptography>=41.0.0
requests>=2.31.0
dnspython>=2.4.0
curl-cffi>=0.5.0  # TLS fingerprint (optional, fallback ke requests)
pytest>=7.4.0
```

## ⚡ Quick Start

```bash
# 1. Install
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
