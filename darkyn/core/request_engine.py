"""
darkyn/core/request_engine.py
Request Engine — Darkyn SQLi Framework v2.0

Fitur:
- Delay request (fixed / random / adaptive)
- Random header injection
- User-Agent rotation (100+ UA)
- Proxy support
- Session management
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# User-Agent Pool
# ---------------------------------------------------------------------------

USER_AGENTS: list[str] = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81",
    # Mobile Chrome Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.80 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Redmi Note 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36",
    # Mobile Safari iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    # Curl / CLI (low priority, kadang berguna)
    "curl/8.7.1",
    "python-requests/2.31.0",
]

# ---------------------------------------------------------------------------
# Random header pools
# ---------------------------------------------------------------------------

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "id-ID,id;q=0.9,en;q=0.8",
    "en-US,en;q=0.9,id;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
]

ACCEPT_ENCODING = [
    "gzip, deflate, br",
    "gzip, deflate",
    "gzip, deflate, br, zstd",
]

CACHE_CONTROL = [
    "max-age=0",
    "no-cache",
    "no-store",
    "",  # kadang tidak ada header ini
]

SEC_FETCH_MODES = ["navigate", "cors", "no-cors", "same-origin"]
SEC_FETCH_SITES = ["same-origin", "cross-site", "none", "same-site"]
SEC_FETCH_DESTS = ["document", "empty", "image", "script", "style"]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class RequestConfig:
    """Konfigurasi request engine."""

    delay_min: float = 0.5          # detik, minimum delay antar request
    delay_max: float = 2.0          # detik, maximum delay
    delay_mode: str = "random"      # fixed | random | adaptive
    rotate_ua: bool = True          # aktifkan UA rotation
    random_headers: bool = True     # aktifkan random header injection
    timeout: int = 15
    proxy: Optional[str] = None
    verify_ssl: bool = False
    max_retries: int = 3
    retry_delay: float = 3.0
    custom_headers: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class RequestEngine:
    """
    HTTP request engine dengan delay, UA rotation, dan random headers.

    Args:
        config: RequestConfig instance.
    """

    def __init__(self, config: Optional[RequestConfig] = None) -> None:
        self.config = config or RequestConfig()
        self._session = requests.Session()
        self._last_request_time: float = 0.0
        self._request_count: int = 0
        self._adaptive_delay: float = self.config.delay_min

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get(self, url: str, params: Optional[dict] = None, **kwargs) -> requests.Response:
        """HTTP GET dengan delay dan header rotation."""
        return self._request("GET", url, params=params, **kwargs)

    def post(self, url: str, data=None, json=None, **kwargs) -> requests.Response:
        """HTTP POST dengan delay dan header rotation."""
        return self._request("POST", url, data=data, json=json, **kwargs)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Generic request."""
        return self._request(method, url, **kwargs)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Internal request handler dengan retry logic."""
        self._apply_delay()
        headers = self._build_headers()
        headers.update(kwargs.pop("headers", {}))

        proxies = None
        if self.config.proxy:
            proxies = {"http": self.config.proxy, "https": self.config.proxy}

        last_exc: Optional[Exception] = None
        for attempt in range(self.config.max_retries):
            try:
                resp = self._session.request(
                    method,
                    url,
                    headers=headers,
                    timeout=self.config.timeout,
                    proxies=proxies,
                    verify=self.config.verify_ssl,
                    **kwargs,
                )
                self._request_count += 1
                self._last_request_time = time.time()
                if self.config.delay_mode == "adaptive":
                    self._update_adaptive_delay(resp)
                return resp
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay)

        raise ConnectionError(f"Request failed after {self.config.max_retries} retries: {last_exc}")

    def _apply_delay(self) -> None:
        """Terapkan delay sebelum request."""
        mode = self.config.delay_mode

        if mode == "fixed":
            delay = self.config.delay_min
        elif mode == "random":
            delay = random.uniform(self.config.delay_min, self.config.delay_max)
        elif mode == "adaptive":
            delay = self._adaptive_delay
        else:
            delay = 0.0

        elapsed = time.time() - self._last_request_time
        remaining = delay - elapsed
        if remaining > 0:
            time.sleep(remaining)

    def _update_adaptive_delay(self, resp: requests.Response) -> None:
        """
        Adaptasi delay berdasarkan response:
        - 429 Too Many Requests → naikkan delay
        - 200 OK → turunkan delay perlahan
        """
        if resp.status_code == 429:
            # Naik dari current atau minimal 0.5s, whichever is greater
            base = max(self._adaptive_delay, 0.5)
            self._adaptive_delay = min(base * 2, 30.0)
        elif resp.status_code == 200:
            self._adaptive_delay = max(
                self._adaptive_delay * 0.9,
                self.config.delay_min,
            )

    def _build_headers(self) -> dict:
        """Build header dict dengan random values."""
        ua = (
            random.choice(USER_AGENTS)
            if self.config.rotate_ua
            else USER_AGENTS[0]
        )

        headers: dict = {"User-Agent": ua}

        if self.config.random_headers:
            headers.update({
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": random.choice(ACCEPT_LANGUAGES),
                "Accept-Encoding": random.choice(ACCEPT_ENCODING),
                "Connection": random.choice(["keep-alive", "close"]),
            })

            # Cache-Control (50% chance)
            cc = random.choice(CACHE_CONTROL)
            if cc:
                headers["Cache-Control"] = cc

            # Sec-Fetch headers (hanya untuk Chrome-like UA)
            if "Chrome" in ua:
                headers.update({
                    "Sec-Fetch-Mode": random.choice(SEC_FETCH_MODES),
                    "Sec-Fetch-Site": random.choice(SEC_FETCH_SITES),
                    "Sec-Fetch-Dest": random.choice(SEC_FETCH_DESTS),
                    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"']),
                })

        # Custom headers override
        headers.update(self.config.custom_headers)
        return headers

    def get_stats(self) -> dict:
        """Return request statistics."""
        return {
            "total_requests": self._request_count,
            "current_adaptive_delay": self._adaptive_delay,
        }
