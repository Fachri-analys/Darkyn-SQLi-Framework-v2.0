# Usage Guide — Darkyn SQLi Framework v2.0

> ⚠️ Hanya untuk **authorized penetration testing**. Pastikan ada izin tertulis sebelum testing.

---

## Basic Usage

```bash
python -m darkyn.cli --target "https://target.com/page?id=1"
```

---

## CLI Options

```
Options:
  --target URL        Target URL dengan parameter
  --mode MODE         AUTO | HYBRID | MANUAL (default: HYBRID)
  --db DBMS           Force DBMS: mysql | pgsql | mssql | oracle | sqlite
  --delay FLOAT       Delay antar request (detik, default: 1.0)
  --timeout INT       Request timeout (detik, default: 10)
  --proxy URL         HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)
  --output FILE       Simpan report ke file (HTML/JSON)
  --report FORMAT     Format report: html | json (default: html)
  --config FILE       Load config dari YAML file
  --verbose           Verbose output
  --version           Tampilkan versi
```

---

## Mode Explanation

### AUTO Mode
```bash
python -m darkyn.cli --target URL --mode AUTO
```
- Scan + deteksi saja
- Tidak ada exploitation sama sekali
- Cocok untuk automated CI/CD pipeline

### HYBRID Mode (Default)
```bash
python -m darkyn.cli --target URL --mode HYBRID
```
- Scan + deteksi otomatis
- Exploitation butuh konfirmasi manual
- Direkomendasikan untuk pentest

### MANUAL Mode
```bash
python -m darkyn.cli --target URL --mode MANUAL
```
- Semua aksi dikontrol pengguna
- Step-by-step interaktif

---

## Config File (YAML)

Buat file `config.yaml`:

```yaml
mode: HYBRID
delay: 1.5
timeout: 15
proxy: http://127.0.0.1:8080
output: report.html
report: html
verbose: true
```

Jalankan:
```bash
python -m darkyn.cli --target URL --config config.yaml
```

---

## Output Report

HTML report otomatis disimpan ke `darkyn_report_<timestamp>.html`:

```bash
python -m darkyn.cli --target URL --output laporan_pentest.html
```

JSON report untuk integrasi dengan tools lain:
```bash
python -m darkyn.cli --target URL --report json --output findings.json
```

---

## Examples

Scan dengan proxy Burp Suite:
```bash
python -m darkyn.cli --target "http://target.local/item?id=1" \
  --proxy http://127.0.0.1:8080 \
  --mode HYBRID \
  --verbose
```

Scan multiple targets dari file:
```bash
cat targets.txt | while read url; do
  python -m darkyn.cli --target "$url" --mode AUTO --output "report_$(date +%s).html"
done
```
