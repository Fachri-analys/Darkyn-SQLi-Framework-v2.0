# Installation Guide — Darkyn SQLi Framework v2.0

## Requirements

| Dependency | Version |
|---|---|
| Python | >= 3.9 |
| pip | >= 21.0 |
| OS | Linux / macOS / Windows (WSL recommended) |

---

## Quick Install

```bash
git clone https://github.com/Fachri-analys/Darkyn-SQLi-Framework-v2.0.git
cd Darkyn-SQLi-Framework-v2.0
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Verify Installation

```bash
python -m darkyn.cli --version
```

Expected output:
```
Darkyn SQLi Framework v2.0
Author: Fachri-analys
```

---

## Dependencies Breakdown

```
requests        — HTTP client dasar
curl_cffi       — TLS fingerprint impersonation (JA3/JA4)
cryptography    — AES-256-GCM encryption layer
dnspython       — DNS tunneling support
rich            — Terminal output formatting
pyyaml          — Config file parsing
jinja2          — HTML report generation
```

---

## Platform Notes

### Parrot OS / Kali Linux
```bash
sudo apt update && sudo apt install python3-pip python3-venv -y
```

### Windows (WSL)
```bash
# Gunakan WSL2 dengan Ubuntu 20.04+
sudo apt install python3-pip python3-venv curl -y
```

---

## Troubleshooting

**Error: `curl_cffi` build fail**
```bash
pip install curl_cffi --pre
```

**Error: `cryptography` version conflict**
```bash
pip install --upgrade cryptography
```

**Permission denied saat run**
```bash
chmod +x darkyn/cli.py
```
