# Bug Fixes — v2.0

Daftar lengkap perbaikan dari v1 ke v2.0.

---

## Critical Fixes

### [FIX-001] Crypto Layer — KeyError pada decrypt
**Severity:** Critical
**Module:** `darkyn/core/crypto.py`

**Problem:**
```python
# v1 — crash kalau nonce tidak ada di header
nonce = response.headers['X-Nonce']  # KeyError!
```

**Fix:**
```python
# v2 — safe fallback
nonce = response.headers.get('X-Nonce', os.urandom(12))
```

---

### [FIX-002] HTTP Client — TLS Handshake Timeout
**Severity:** High
**Module:** `darkyn/core/http_client.py`

**Problem:** `curl_cffi` timeout tidak di-handle, menyebabkan hanging scan.

**Fix:** Tambah explicit timeout + retry logic dengan exponential backoff.

---

### [FIX-003] Time-Based Extractor — False Positive Rate Tinggi
**Severity:** High
**Module:** `darkyn/attack/time_blind_extractor.py`

**Problem:** Threshold waktu statis (5s) menyebabkan false positive di target lambat.

**Fix:** Dynamic baseline — ukur response time normal target sebelum inject, gunakan `baseline * 2.5` sebagai threshold.

---

### [FIX-004] Union Extractor — Column Count Detection Error
**Severity:** High
**Module:** `darkyn/attack/union_extractor.py`

**Problem:** Loop column count tidak berhenti kalau target return 500.

**Fix:** Tambah pengecekan status code + early exit.

---

## Medium Fixes

### [FIX-005] Payload Engine — Duplikasi Payload
**Module:** `darkyn/attack/payloads.py`
Payload arsenal v1 mengandung ~30% duplikat. Deduplication diterapkan.

### [FIX-006] DNS Tunnel — Rate Limit Tidak Aktif
**Module:** `darkyn/attack/dns_tunnel.py`
Rate limiting ada di code tapi tidak dipanggil. Fixed dengan decorator.

### [FIX-007] CLI — `--proxy` Flag Tidak Passed ke HTTP Client
**Module:** `darkyn/cli.py`
Proxy config dari CLI tidak diteruskan ke `HTTPClient`. Fixed.

---

## Minor Fixes

### [FIX-008] Logging — Output ke stderr bukan stdout
Semua log sekarang ke stderr, output data ke stdout. Memudahkan piping.

### [FIX-009] Exception — Pesan error tidak informatif
Custom exceptions sekarang include context (URL, parameter, phase).

### [FIX-010] Types — `ScanResult` tidak serializable
`ScanResult` sekarang punya method `.to_dict()` dan `.to_json()`.
