# Contributing to Darkyn SQLi Framework

Terima kasih sudah mau berkontribusi! Baca panduan ini sebelum mulai.

---

## ⚠️ Code of Conduct

Framework ini **hanya untuk authorized security testing**. Setiap kontribusi harus:
- Tidak memfasilitasi unauthorized access
- Tidak menghilangkan authorization gates yang ada
- Menyertakan disclaimer jika menambah fitur baru yang sensitif

Kontribusi yang melanggar ini akan langsung ditolak.

---

## Getting Started

```bash
git clone https://github.com/Fachri-analys/Darkyn-SQLi-Framework-v2.0.git
cd Darkyn-SQLi-Framework-v2.0
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-cov black flake8
```

---

## Workflow

### 1. Fork & Branch

```bash
git checkout -b feature/nama-fitur
# atau
git checkout -b fix/nama-bug
```

### 2. Coding Standards

- **Python 3.9+** — gunakan type hints di semua fungsi
- **Black** untuk formatting: `black darkyn/`
- **Flake8** untuk linting: `flake8 darkyn/ --max-line-length=100`
- Semua fungsi publik **wajib punya docstring**

Contoh:
```python
def detect_waf(url: str, timeout: int = 10) -> WAFResult:
    """
    Detect WAF presence pada target URL.

    Args:
        url: Target URL yang akan dianalisis.
        timeout: Request timeout dalam detik.

    Returns:
        WAFResult dengan nama WAF dan confidence score.

    Raises:
        ConnectionError: Jika target tidak dapat dijangkau.
    """
    ...
```

### 3. Testing

Setiap fitur baru **wajib disertai test**:

```bash
pytest tests/ -v
pytest tests/ --cov=darkyn --cov-report=term-missing
```

Target coverage: **>= 80%**

### 4. Commit Message Format

```
type(scope): deskripsi singkat

feat(waf): tambah deteksi F5 BIG-IP
fix(crypto): handle missing nonce di response header
docs(api): update WAFDetector reference
test(blind): tambah test untuk dynamic baseline
refactor(cli): pisah parsing dan execution logic
```

### 5. Pull Request

Pastikan sebelum PR:
- [ ] `black` sudah dijalankan
- [ ] `flake8` tidak ada error
- [ ] Semua test pass
- [ ] Ada test untuk fitur/fix baru
- [ ] CHANGELOG.md diupdate

---

## Area Kontribusi

| Area | Status | Prioritas |
|---|---|---|
| WAF signature baru | Open | Tinggi |
| Support DBMS tambahan | Open | Medium |
| Improve report template | Open | Medium |
| Bug fixes | Open | Tinggi |
| Dokumentasi / typo fix | Open | Rendah |

---

## Questions?

Buka [Issue](https://github.com/Fachri-analys/Darkyn-SQLi-Framework-v2.0/issues) dengan label `question`.
