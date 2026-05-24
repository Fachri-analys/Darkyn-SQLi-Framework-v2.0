# BUGFIXES.md - v2.0 Complete Bug Report

## 🔴 CRITICAL BUGS (High Severity)

### BUG-02: Database Type Detection Logic Error
**File**: Line 374  
**Issue**: MySQL dan MSSQL pakai payload yang sama `' AND @@version--`
```python
# WRONG (Line 374)
("' AND @@version--", ["microsoft", "sql server"], DBType.MSSQL),

# CORRECT
("' AND SERVERPROPERTY('ProductVersion')--", ["microsoft", "sql server"], DBType.MSSQL),
```
**Impact**: MSSQL targets selalu terdeteksi sebagai MySQL  
**Fix**: Gunakan payload unik per database  

---

### BUG-03: DNS Decoding - Out-of-Order Chunks
**File**: Line 196-208, Line 193  
**Issue**: `dns_encode()` return list tapi tidak di-sort saat decode, menyebabkan reassembly error jika chunks sampai out-of-order
```python
# WRONG
def dns_decode(self, chunk_list):
    reconstructed = ''.join(c["chunk"] for c in chunk_list)  # ← no sort!

# CORRECT
def dns_decode(self, chunk_list):
    sorted_chunks = sorted(chunk_list, key=lambda x: x["seq"])
    reconstructed = ''.join(c["chunk"] for c in sorted_chunks)
```
**Impact**: Data corruption saat DNS exfiltration via multiple queries  
**Fix**: Sort by sequence number sebelum reassembly  

---

### BUG-04: Invalid PostgreSQL CHR() Syntax
**File**: Line 756  
**Issue**: PostgreSQL tidak support multi-argument CHR(), syntax error saat encode_strings()
```python
# WRONG (Line 756)
chars = ",".join(str(ord(c)) for c in s)
return f"CHR({chars})"  # ← CHR(65,66,67) invalid di PostgreSQL

# CORRECT
chars = "||".join(f"CHR({ord(c)})" for c in s)
return f"({chars})"  # ← CHR(65)||CHR(66)||CHR(67)
```
**Impact**: String encoding gagal untuk PostgreSQL targets  
**Fix**: Gunakan CHR() dengan || concatenation operator  

---

### BUG-05: SSL Certificate Verification Disabled
**File**: Line 605, 618, 634  
**Issue**: `verify=False` disable SSL certificate validation, membuka MITM attack
```python
# WRONG (Line 605)
sess.verify = False  # ← Dangerous for HTTPS targets

# CORRECT
sess.verify = verify_ssl  # ← Default True, override jika dibutuhkan untuk pentest
```
**Impact**: Vulnerable ke man-in-the-middle attack pada HTTPS targets  
**Fix**: Enable cert verification by default, allow override hanya untuk testing  

---

### BUG-06: Invalid Header Parsing Format
**File**: Line 156-165  
**Issue**: `decrypt()` tidak validate header format sebelum struct.unpack, bisa crash dengan invalid hex
```python
# WRONG
seed0 = struct.unpack('>d', bytes.fromhex(parts[2]))[0]  # ← no validation

# CORRECT
if len(parts[i]) != 16:  # 8 bytes = 16 hex chars
    raise ValueError(f"Invalid seed hex at index {i}")
seed0 = struct.unpack('>d', bytes.fromhex(parts[2]))[0]
```
**Impact**: Exception handling tidak robust, unhandled crash  
**Fix**: Validate hex format & length sebelum decode  

---

## ⚠️ MEDIUM SEVERITY BUGS

### BUG-07: Duplicate WHITESPACE_SUBS Definition
**File**: Line 688 dan Line 773  
**Issue**: `WHITESPACE_SUBS` didefinisikan 2x di dalam class, yang kedua override yang pertama
```python
# Line 688
WHITESPACE_SUBS = ["\t", "\n", "/**/", "%09", "%0a"]

# Line 773 (DUPLICATE!)
WHITESPACE_SUBS = ["\t", "\n", "/**/", "%09", "%0a"]
```
**Impact**: Code confusion, maintenance nightmare  
**Fix**: Remove duplicate definition (keep hanya satu)  

---

### BUG-08: Incomplete Engine Compatibility
**File**: Line 939-940  
**Issue**: `TimeBinaryExtractor._probe()` assume `test_payload()` method, tapi tidak handle edge case
```python
# Line 932-940
if hasattr(self.engine, 'test_payload'):
    result = self.engine.test_payload(payload)
else:
    # ← Incomplete, tidak set elapsed untuk TLSHttpClient
    self.engine.post(...)  # ← Missing target_url & target_field attributes
```
**Impact**: Binary search extractor tidak kompatibel dengan TLSHttpClient standalone  
**Fix**: Add proper fallback logic atau standardize interface  

---

### BUG-09: Broad Exception Handling
**File**: Line 186, 207  
**Issue**: `except Exception` terlalu broad, hide real errors
```python
# WRONG
except Exception:
    return None  # ← hide ValueError, TypeError, etc

# CORRECT
except (ValueError, struct.error, zlib.error) as e:
    return None  # ← specific exceptions
```
**Impact**: Debugging difficult, unknown errors silently fail  
**Fix**: Catch specific exceptions, log others  

---

## 📊 Summary Table

| BugID | Severity | Component | Status | Line(s) |
|-------|----------|-----------|--------|---------|
| BUG-01 | ✅ Fixed | crypto | FIXED | 109-118 |
| BUG-02 | 🔴 CRITICAL | union_extractor | FIXED | 374 |
| BUG-03 | 🔴 CRITICAL | crypto | FIXED | 196-208 |
| BUG-04 | 🔴 CRITICAL | polymorphic | FIXED | 756 |
| BUG-05 | 🔴 CRITICAL | http_client | FIXED | 605,618,634 |
| BUG-06 | 🔴 CRITICAL | crypto | FIXED | 156-165 |
| BUG-07 | ⚠️ MEDIUM | polymorphic | FIXED | 688,773 |
| BUG-08 | ⚠️ MEDIUM | time_blind_extractor | FIXED | 932-940 |
| BUG-09 | ⚠️ MEDIUM | crypto | FIXED | 186,207 |

---

## 🔐 Security Recommendations (Non-Bug)

1. **Rate Limiting**: Tambah delay antara queries untuk avoid DoS target
2. **Input Validation**: Validate semua user input (URL, field names, queries)
3. **Logging**: Jangan log sensitive data (passwords, tokens) ke file
4. **Config Management**: Use environment variables untuk credentials, bukan hardcoded
5. **Error Messages**: Jangan expose error details ke attacker (generic messages)

---

## 📝 Changelog

### v2.0
- ✅ Fixed 9 bugs (6 critical, 3 medium)
- ✅ Added TLS fingerprint impersonation (JA3/JA4)
- ✅ Added binary search time-based blind extractor
- ✅ Improved polymorphic engine database compatibility
- ✅ Enhanced SSL/TLS security
- ✅ Better exception handling

### v1.0
- Initial release (buggy version)
