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
│   │   ├── crypto.py           
│   │   ├── http_client.py     
│   │   ├── exceptions.py      
│   │   └── types.py            
│   ├── attack/
<<<<<<< HEAD
│   │   ├── injection_engine.py # SQLi detection
│   │   ├── payloads.py         # Payload arsenal
│   │   ├── polymorphic.py      # Obfuscation engine
│   │   ├── union_extractor.py  # Union-based discovery
│   │   ├── time_blind_extractor.py # Binary search time-based
│   │   ├── waf_detector.py     # WAF fingerprinting (15+ vendor)
│   │   ├── dns_tunnel.py       # DNS exfiltration
│   │   └── report_generator.py # HTML/JSON reports
│   ├── cli.py                  # Command-line interface
│   └── framework.py            # Main framework class
├── tests/                      # Unit tests (pytest)
├── examples/                   # Usage examples
├── docs/                       # Full documentation
├── requirements.txt
└── CHANGELOG.md
```

---

## 📄 Report Output

Setiap scan menghasilkan laporan HTML profesional:

- Target info & scan metadata
- WAF detection result
- Per-finding detail: parameter, teknik, CVSS score
- Evidence (request + response snippet)
- Remediation recommendation

```bash
python -m darkyn.cli --target URL --output laporan.html
python -m darkyn.cli --target URL --report json --output findings.json
=======
│   │   ├── __init__.py
│   │   ├── injection_engine.py       
│   │   ├── payloads.py               
│   │   ├── polymorphic.py            
│   │   ├── union_extractor.py       
│   │   ├── time_blind_extractor.py   
│   │   └── dns_tunnel.py            
│   │
│   ├── cli.py                        
│   └── framework.py                  
│
├── tests/
│   ├── __init__.py
│   ├── test_crypto.py                
│   ├── test_payloads.py             
│   ├── test_polymorphic.py           
│   └── test_binary_search.py         
│
├── examples/
│   ├── basic_usage.py               
│   ├── blind_extraction.py           
│   └── full_attack.py               
│
└── docs/
    ├── INSTALL.md                    
    ├── USAGE.md                     
    ├── API.md                        
    └── BUGFIXES.md                   
```

## ⚡ Quick Start

```bash
# 1. Install
git clone https://github.com/Fachri-analys/Darkyn-SQLi-Framework-v2.0.git
cd darkyn-framework
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 2. Run
python -m darkyn.cli
>>>>>>> 11216dafdcaf368e3c40e0f0333a587ef56cb7af
```

---

## 📚 Documentation

- [Installation Guide](docs/INSTALL.md)
- [Usage Guide](docs/USAGE.md)
- [API Reference](docs/API.md)
- [Bug Fixes v2.0](docs/BUGFIXES.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)

---

## 🧪 Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v
pytest tests/ --cov=darkyn --cov-report=term-missing
```

---

## ⚖️ Legal & Ethics

Framework ini dibuat untuk:
- ✅ Authorized penetration testing dengan izin tertulis
- ✅ CTF competitions
- ✅ Security research & education
- ✅ Bug bounty (sesuai scope program)

**Penggunaan tanpa izin pada sistem orang lain adalah ilegal.**

---

## 👤 Author

**Fachri** — Security Researcher & Pentester
- GitHub: [@Fachri-analys](https://github.com/Fachri-analys)
- Medium: [@fachrifunandar](https://medium.com/@fachrifunandar)

---

## 📜 License

Lihat [LICENSE](LICENSE) untuk detail. Penggunaan hanya untuk authorized testing.
