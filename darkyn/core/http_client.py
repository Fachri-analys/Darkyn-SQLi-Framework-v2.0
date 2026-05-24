# core/http_client.py
# FIXED: BUG-5 SSL verification - now uses proper cert validation by default
from typing import Dict, Any, Optional
from .types import AttackMode
from .exceptions import InjectionError
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from curl_cffi import requests as cffi_requests
    TLS_IMPERSONATE_AVAILABLE = True
except ImportError:
    TLS_IMPERSONATE_AVAILABLE = False

_CHROME_IMPERSONATE = "chrome124"

class TLSHttpClient:
    """
    HTTP Client dengan TLS Fingerprint impersonation.

    Priority stack:
      1. curl_cffi  → JA3/JA4 identical to Chrome (WAF grade bypass)
      2. requests   → fallback dengan header Chrome-like (basic evasion)

    FIXED: SSL verification lebih secure - now validates certs by default
    """

    def __init__(self, mode: AttackMode = AttackMode.NORMAL, verify_ssl: bool = True):
        self.mode         = mode
        self._req_count   = 0
        self._use_cffi    = TLS_IMPERSONATE_AVAILABLE
        self.verify_ssl   = verify_ssl  # Allow override untuk testing

        self._chrome_headers = {
            "User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                                         "Chrome/124.0.6367.82 Safari/537.36",
            "Accept":                    "text/html,application/xhtml+xml,application/xml;"
                                         "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,"
                                         "application/signed-exchange;v=b3;q=0.7",
            "Accept-Language":           "en-US,en;q=0.9",
            "Accept-Encoding":           "gzip, deflate, br, zstd",
            "Sec-Ch-Ua":                 '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "Sec-Ch-Ua-Mobile":          "?0",
            "Sec-Ch-Ua-Platform":        '"Windows"',
            "Sec-Fetch-Dest":            "document",
            "Sec-Fetch-Mode":            "navigate",
            "Sec-Fetch-Site":            "none",
            "Sec-Fetch-User":            "?1",
            "Upgrade-Insecure-Requests": "1",
            "Connection":                "keep-alive",
        }

        self._session = self._init_session()

    def _init_session(self):
        if self._use_cffi:
            sess = cffi_requests.Session(impersonate=_CHROME_IMPERSONATE)
            sess.headers.update(self._chrome_headers)
            return sess
        else:
            import requests as std_requests
            sess = std_requests.Session()
            sess.headers.update(self._chrome_headers)
            # FIXED: Respect verify_ssl parameter (default True for security)
            sess.verify = self.verify_ssl
            return sess

    def post(self, url: str, data: Dict = None, timeout: int = 15,
             extra_headers: Dict = None, verify: Optional[bool] = None) -> Any:
        self._req_count += 1
        headers = {**self._chrome_headers, **(extra_headers or {})}
        verify_val = verify if verify is not None else self.verify_ssl

        try:
            if self._use_cffi:
                return self._session.post(
                    url, data=data, headers=headers, timeout=timeout,
                    impersonate=_CHROME_IMPERSONATE, verify=verify_val
                )
            else:
                return self._session.post(url, data=data, headers=headers,
                                        timeout=timeout, verify=verify_val)
        except Exception as e:
            raise InjectionError(f"HTTP POST failed: {e}") from e

    def get(self, url: str, params: Dict = None, timeout: int = 15,
            extra_headers: Dict = None, verify: Optional[bool] = None) -> Any:
        self._req_count += 1
        headers = {**self._chrome_headers, **(extra_headers or {})}
        verify_val = verify if verify is not None else self.verify_ssl

        try:
            if self._use_cffi:
                return self._session.get(
                    url, params=params, headers=headers, timeout=timeout,
                    impersonate=_CHROME_IMPERSONATE, verify=verify_val
                )
            else:
                return self._session.get(url, params=params, headers=headers,
                                       timeout=timeout, verify=verify_val)
        except Exception as e:
            raise InjectionError(f"HTTP GET failed: {e}") from e

    @property
    def backend(self) -> str:
        return f"curl_cffi({_CHROME_IMPERSONATE})" if self._use_cffi else "requests(fallback)"

    @property
    def request_count(self) -> int:
        return self._req_count
