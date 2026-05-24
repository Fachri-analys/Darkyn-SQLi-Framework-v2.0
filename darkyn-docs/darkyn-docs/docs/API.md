# API Reference — Darkyn SQLi Framework v2.0

## DarkynFramework (Main Class)

```python
from darkyn.framework import DarkynFramework

fw = DarkynFramework(mode="HYBRID", delay=1.0, proxy=None)
result = fw.scan(target_url="https://target.com/page?id=1")
```

### Constructor Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `mode` | str | `"HYBRID"` | Scan mode: AUTO / HYBRID / MANUAL |
| `delay` | float | `1.0` | Delay antar request (detik) |
| `proxy` | str | `None` | Proxy URL |
| `timeout` | int | `10` | Request timeout |
| `verbose` | bool | `False` | Verbose logging |

### Methods

#### `scan(target_url, params=None)`
Jalankan full scan pipeline (Phase 1 + 2).

```python
result = fw.scan("https://target.com/page?id=1")
print(result.sqli_detected)   # True/False
print(result.dbms)            # "MySQL", "PostgreSQL", dll
print(result.technique)       # "time-based", "union", dll
```

#### `generate_report(result, output_path, format="html")`
Generate laporan dari hasil scan.

```python
fw.generate_report(result, "laporan.html", format="html")
fw.generate_report(result, "findings.json", format="json")
```

---

## ScanResult (Data Class)

```python
from darkyn.core.types import ScanResult

result.target_url       # str
result.sqli_detected    # bool
result.dbms             # str | None
result.technique        # str | None
result.vulnerable_params # list[str]
result.waf_detected     # bool
result.waf_name         # str | None
result.privilege_level  # str | None
result.timestamp        # datetime
```

---

## WAFDetector

```python
from darkyn.attack.waf_detector import WAFDetector

detector = WAFDetector(http_client=client)
waf_result = detector.detect("https://target.com")

print(waf_result.detected)   # True/False
print(waf_result.name)       # "Cloudflare" / "ModSecurity" / dll
print(waf_result.confidence) # 0.0 - 1.0
```

---

## ReportGenerator

```python
from darkyn.attack.report_generator import ReportGenerator

gen = ReportGenerator()
gen.generate(result, output_path="report.html", format="html")
gen.generate(result, output_path="report.json", format="json")
```

---

## PolymorphicEngine

```python
from darkyn.attack.polymorphic import PolymorphicEngine

engine = PolymorphicEngine()
obfuscated = engine.obfuscate("' OR 1=1--")
print(obfuscated)  # Variasi payload yang berbeda setiap kali
```

---

## Exceptions

```python
from darkyn.core.exceptions import (
    DarkynException,        # Base exception
    ConnectionError,        # Gagal koneksi ke target
    WAFBlockedError,        # Request diblokir WAF
    InvalidTargetError,     # URL tidak valid
    AuthorizationError,     # Konfirmasi tidak diberikan
)
```
