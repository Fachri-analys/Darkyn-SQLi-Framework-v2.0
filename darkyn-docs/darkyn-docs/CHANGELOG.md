# Changelog

All notable changes to Darkyn SQLi Framework are documented here.

Format: [Semantic Versioning](https://semver.org/)

---

## [2.0.0] — 2025

### Added
- **WAF Detection Engine** — fingerprint 15+ WAF vendors (Cloudflare, ModSecurity, Akamai, dll)
- **HTML/JSON Report Generator** — laporan pentest siap pakai dengan evidence
- **Dynamic Baseline Timing** — time-based detection lebih akurat, false positive turun drastis
- **Config File Support** — load setting dari `.yaml` tanpa ulang ketik CLI flags
- **Resume Scan** — lanjut scan kalau terputus via checkpoint file
- **Multi-target Support** — scan dari file list target
- **CVSS Scoring** — estimasi skor CVSS per temuan
- **Proxy Integration** — full Burp Suite compatibility
- **Rate Limiting Engine** — adaptive delay biar tidak ke-ban
- **Type Hints** — semua fungsi sekarang fully typed
- **Docstrings** — dokumentasi inline lengkap di semua modul

### Fixed
- FIX-001: KeyError di crypto layer saat nonce hilang
- FIX-002: TLS handshake hanging tanpa timeout
- FIX-003: False positive tinggi di time-based detection
- FIX-004: Union column count loop infinite saat 500 error
- FIX-005: Duplikasi payload di arsenal (~30%)
- FIX-006: Rate limiter tidak aktif di DNS tunnel
- FIX-007: `--proxy` CLI flag tidak diteruskan ke HTTP client
- FIX-008: Log output ke stdout (seharusnya stderr)
- FIX-009: Exception message tidak informatif
- FIX-010: `ScanResult` tidak JSON-serializable

### Changed
- Binary search extractor: 95 → 7 requests/char (13x lebih efisien)
- HTTP client di-rewrite pakai `curl_cffi` untuk JA3/JA4 fingerprinting
- Payload arsenal direstrukturisasi per DBMS dan teknik
- CLI interface di-improve dengan `rich` untuk output lebih readable
- Exception hierarchy di-refactor

### Security
- Tambah strict authorization gate sebelum setiap aksi sensitif
- Semua aksi dicatat di audit log lokal

---

## [1.0.0] — 2024

### Added
- SQLi detection dasar (time-based, union-based)
- Multi-DB support: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- Basic AES encryption layer
- CLI interface minimal
- DNS tunneling prototype

### Known Issues (diperbaiki di v2.0)
- False positive rate tinggi di jaringan lambat
- Tidak ada WAF detection
- Tidak ada reporting
- Proxy tidak berfungsi dari CLI
