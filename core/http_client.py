from __future__ import annotations

import asyncio
import random
import ssl
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit

from config import DEFAULT_UAS


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status: int
    headers: Dict[str, str]
    body: bytes
    set_cookies: Tuple[str, ...] = ()

    def header(self, name: str) -> str:
        return str(self.headers.get(name.lower(), "")).strip()


def _normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        if not k:
            continue
        out[str(k).lower()] = str(v)
    return out


def _default_headers(*, ua: str) -> Dict[str, str]:
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.8,id;q=0.7",
        "Connection": "close",
    }


def _merge_headers(base: Dict[str, str], extra: Dict[str, str]) -> Dict[str, str]:
    out = dict(base or {})
    for k, v in (extra or {}).items():
        kk = str(k).strip()
        if not kk:
            continue
        out[kk] = str(v)
    return out


def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _make_ssl_context_insecure() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _fetch_with_aiohttp(
    url: str,
    *,
    timeout_s: float,
    max_bytes: int,
    delay_s: float,
    ua_pool: Tuple[str, ...],
    max_redirects: int,
    insecure: bool,
    extra_headers: Dict[str, str],
) -> HttpResponse:
    import aiohttp

    if delay_s > 0:
        await asyncio.sleep(float(delay_s))

    ua = random.choice(ua_pool) if ua_pool else random.choice(DEFAULT_UAS)
    hdrs = _merge_headers(_default_headers(ua=ua), extra_headers)

    timeout = aiohttp.ClientTimeout(total=float(timeout_s))
    async with aiohttp.ClientSession(timeout=timeout) as session:
        ssl_ctx = _make_ssl_context_insecure() if insecure else _make_ssl_context()
        async with session.get(url, headers=hdrs, allow_redirects=True, max_redirects=int(max_redirects), ssl=ssl_ctx) as resp:
            body = await resp.content.read(max_bytes) if max_bytes > 0 else await resp.read()
            try:
                cookies = tuple(resp.headers.getall("Set-Cookie", []))
            except Exception:
                cookies = ()
            headers = _normalize_headers({k: v for k, v in resp.headers.items()})
            return HttpResponse(url=str(resp.url), status=int(resp.status), headers=headers, body=body, set_cookies=cookies)


def _fetch_with_urllib(
    url: str,
    *,
    timeout_s: float,
    max_bytes: int,
    delay_s: float,
    ua_pool: Tuple[str, ...],
    max_redirects: int,
    insecure: bool,
    extra_headers: Dict[str, str],
) -> HttpResponse:
    import time
    import urllib.error
    import urllib.request

    if delay_s > 0:
        time.sleep(float(delay_s))

    ua = random.choice(ua_pool) if ua_pool else random.choice(DEFAULT_UAS)
    hdrs = _merge_headers(_default_headers(ua=ua), extra_headers)

    req = urllib.request.Request(url, headers=hdrs, method="GET")
    ctx = _make_ssl_context_insecure() if insecure else _make_ssl_context()
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler(), urllib.request.HTTPSHandler(context=ctx))
    opener.addheaders = list(hdrs.items())
    try:
        with opener.open(req, timeout=float(timeout_s)) as resp:
            body = resp.read(max_bytes if max_bytes > 0 else None)
            try:
                cookies = tuple(resp.headers.get_all("Set-Cookie") or [])
            except Exception:
                cookies = ()
            headers = _normalize_headers(dict(resp.headers.items()))
            return HttpResponse(url=url, status=int(resp.getcode() or 0), headers=headers, body=body, set_cookies=cookies)
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(max_bytes if max_bytes > 0 else None) or b""
        except Exception:
            body = b""
        hdr_obj = getattr(e, "headers", None)
        try:
            cookies = tuple(hdr_obj.get_all("Set-Cookie") or []) if hdr_obj else ()
        except Exception:
            cookies = ()
        headers = _normalize_headers(dict(hdr_obj.items()) if hdr_obj else {})
        return HttpResponse(url=url, status=int(getattr(e, "code", 0) or 0), headers=headers, body=body, set_cookies=cookies)


class HttpClient:
    def __init__(
        self,
        *,
        timeout_s: float,
        delay_s: float = 0.0,
        ua_pool: Optional[Tuple[str, ...]] = None,
        max_bytes: int = 800_000,
        retries: int = 2,
        max_redirects: int = 6,
        insecure: bool = False,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.timeout_s = float(timeout_s)
        self.delay_s = float(delay_s)
        self.ua_pool = tuple(ua_pool or ())
        self.max_bytes = int(max_bytes)
        self.retries = int(retries)
        self.max_redirects = int(max_redirects)
        self.insecure = bool(insecure)
        self.headers = dict(headers or {})

    async def fetch(self, url: str) -> HttpResponse:
        last: Optional[BaseException] = None
        for attempt in range(max(1, self.retries + 1)):
            try:
                return await self._fetch_once(url)
            except Exception as e:
                last = e
                msg = str(e).lower()
                if isinstance(e, (TimeoutError, asyncio.TimeoutError)) or "timed out" in msg or "timeout" in msg:
                    break
                await asyncio.sleep(0.05)
        if last:
            raise last
        raise RuntimeError("fetch gagal")

    async def _fetch_once(self, url: str) -> HttpResponse:
        s = urlsplit(url)
        if s.scheme not in {"http", "https"}:
            raise ValueError("URL scheme harus http/https")

        try:
            return await _fetch_with_aiohttp(
                url,
                timeout_s=self.timeout_s,
                max_bytes=self.max_bytes,
                delay_s=self.delay_s,
                ua_pool=self.ua_pool,
                max_redirects=self.max_redirects,
                insecure=self.insecure,
                extra_headers=self.headers,
            )
        except Exception:
            return await asyncio.wait_for(
                asyncio.to_thread(
                    _fetch_with_urllib,
                    url,
                    timeout_s=self.timeout_s,
                    max_bytes=self.max_bytes,
                    delay_s=self.delay_s,
                    ua_pool=self.ua_pool,
                    max_redirects=self.max_redirects,
                    insecure=self.insecure,
                    extra_headers=self.headers,
                ),
                timeout=float(self.timeout_s) + 2.0,
            )
