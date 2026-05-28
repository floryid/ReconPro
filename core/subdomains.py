from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from core.cache import Cache
from core.dns_resolver import resolve_ips_socket


def _http_json(
    url: str,
    *,
    timeout_s: float,
    headers: Optional[Dict[str, str]] = None,
    retries: int = 2,
    backoff_s: float = 0.5,
) -> Any:
    h = {"User-Agent": "ReconScanPro/2.0", "Accept": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h, method="GET")
    last: Optional[BaseException] = None
    for i in range(max(1, int(retries) + 1)):
        try:
            with urllib.request.urlopen(req, timeout=float(timeout_s)) as resp:
                raw = resp.read()
            try:
                return json.loads(raw.decode("utf-8", errors="replace"))
            except Exception:
                return None
        except urllib.error.HTTPError as e:
            last = e
            code = int(getattr(e, "code", 0) or 0)
            if code in {429, 500, 502, 503, 504} and i < int(retries):
                time.sleep(float(backoff_s) * (2**i))
                continue
            return None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            last = e
            if i < int(retries):
                time.sleep(float(backoff_s) * (2**i))
                continue
            return None
    return None


def fetch_crtsh(domain: str, *, timeout_s: float, limit: int, cache: Optional[Cache] = None, ttl_s: int = 0) -> List[str]:
    d = str(domain).strip().strip(".")
    key = f"subs:crtsh:{d}:{int(limit)}"
    cached = cache.get(key, ttl_s=ttl_s) if cache else None
    if isinstance(cached, list):
        return [str(x) for x in cached]

    url = f"https://crt.sh/?q={urllib.parse.quote('%25.' + d)}&output=json"
    data = _http_json(url, timeout_s=timeout_s)
    out: Set[str] = set()
    if isinstance(data, list):
        for row in data:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name_value") or "").strip()
            if not name:
                continue
            for part in name.splitlines():
                s = part.strip().lower().strip(".")
                if not s or "*" in s:
                    continue
                if s.endswith("." + d) or s == d:
                    out.add(s)
            if len(out) >= int(limit):
                break
    res = sorted(out)[: int(limit)]
    if cache:
        cache.set(key, res)
    return res


def fetch_certspotter(domain: str, *, timeout_s: float, limit: int, cache: Optional[Cache] = None, ttl_s: int = 0) -> List[str]:
    d = str(domain).strip().strip(".")
    key = f"subs:certspotter:{d}:{int(limit)}"
    cached = cache.get(key, ttl_s=ttl_s) if cache else None
    if isinstance(cached, list):
        return [str(x) for x in cached]

    url = "https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode(
        {"domain": d, "include_subdomains": "true", "expand": "dns_names", "match_wildcards": "false"}
    )
    data = _http_json(url, timeout_s=timeout_s)
    out: Set[str] = set()
    if isinstance(data, list):
        for row in data:
            if not isinstance(row, dict):
                continue
            names = row.get("dns_names")
            if not isinstance(names, list):
                continue
            for n in names:
                s = str(n or "").strip().lower().strip(".")
                if not s or "*" in s:
                    continue
                if s.endswith("." + d) or s == d:
                    out.add(s)
            if len(out) >= int(limit):
                break
    res = sorted(out)[: int(limit)]
    if cache:
        cache.set(key, res)
    return res


def fetch_virustotal(domain: str, *, timeout_s: float, limit: int, api_key: str) -> List[str]:
    d = str(domain).strip().strip(".")
    url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(d)}/subdomains?limit={int(limit)}"
    data = _http_json(url, timeout_s=timeout_s, headers={"x-apikey": api_key})
    out: Set[str] = set()
    if isinstance(data, dict):
        items = data.get("data")
        if isinstance(items, list):
            for it in items:
                if not isinstance(it, dict):
                    continue
                attr = it.get("id") or (it.get("attributes") or {}).get("id")
                s = str(attr or "").strip().lower().strip(".")
                if s.endswith("." + d) or s == d:
                    out.add(s)
    return sorted(out)[: int(limit)]


def fetch_securitytrails(domain: str, *, timeout_s: float, limit: int, api_key: str) -> List[str]:
    d = str(domain).strip().strip(".")
    url = f"https://api.securitytrails.com/v1/domain/{urllib.parse.quote(d)}/subdomains"
    data = _http_json(url, timeout_s=timeout_s, headers={"APIKEY": api_key})
    out: Set[str] = set()
    if isinstance(data, dict):
        subs = data.get("subdomains")
        if isinstance(subs, list):
            for s0 in subs:
                s = str(s0 or "").strip().lower().strip(".")
                if not s:
                    continue
                out.add(f"{s}.{d}")
    return sorted(out)[: int(limit)]


def brute_subdomains(domain: str, words: Sequence[str]) -> List[str]:
    d = str(domain).strip().strip(".").lower()
    out: List[str] = []
    for w in words:
        ww = str(w).strip().lower()
        if not ww or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", ww):
            continue
        out.append(f"{ww}.{d}")
    return out


DEFAULT_BRUTE_WORDS = [
    "www",
    "mail",
    "mx",
    "smtp",
    "imap",
    "pop",
    "webmail",
    "ftp",
    "api",
    "admin",
    "adminpanel",
    "dashboard",
    "portal",
    "dev",
    "dev1",
    "staging",
    "uat",
    "qa",
    "test",
    "test1",
    "beta",
    "cdn",
    "static",
    "img",
    "files",
    "sso",
    "vpn",
    "origin",
    "direct",
    "ns1",
    "ns2",
    "ns3",
    "m",
    "app",
]


def enumerate_subdomains(
    domain: str,
    *,
    timeout_s: float,
    limit: int,
    sources: Sequence[str],
    brute: bool,
    cache: Optional[Cache],
    ttl_s: int,
) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    by_src: Dict[str, List[str]] = {}
    errors: Dict[str, str] = {}
    srcs = [s.strip().lower() for s in sources if str(s).strip()]
    if "crtsh" in srcs or "ct" in srcs:
        try:
            by_src["crtsh"] = fetch_crtsh(domain, timeout_s=timeout_s, limit=limit, cache=cache, ttl_s=ttl_s)
        except Exception as e:
            by_src["crtsh"] = []
            errors["crtsh"] = f"{type(e).__name__}: {e}"
    if "certspotter" in srcs:
        try:
            by_src["certspotter"] = fetch_certspotter(domain, timeout_s=timeout_s, limit=limit, cache=cache, ttl_s=ttl_s)
        except Exception as e:
            by_src["certspotter"] = []
            errors["certspotter"] = f"{type(e).__name__}: {e}"
    if "virustotal" in srcs:
        key = os.environ.get("VT_API_KEY", "").strip()
        if key:
            try:
                by_src["virustotal"] = fetch_virustotal(domain, timeout_s=timeout_s, limit=limit, api_key=key)
            except Exception as e:
                by_src["virustotal"] = []
                errors["virustotal"] = f"{type(e).__name__}: {e}"
        else:
            by_src["virustotal"] = []
    if "securitytrails" in srcs:
        key = os.environ.get("SECURITYTRAILS_API_KEY", "").strip()
        if key:
            try:
                by_src["securitytrails"] = fetch_securitytrails(domain, timeout_s=timeout_s, limit=limit, api_key=key)
            except Exception as e:
                by_src["securitytrails"] = []
                errors["securitytrails"] = f"{type(e).__name__}: {e}"
        else:
            by_src["securitytrails"] = []
    if brute:
        by_src["brute"] = brute_subdomains(domain, DEFAULT_BRUTE_WORDS)
    return by_src, errors


def resolve_subdomains(subs: Sequence[str], *, workers: int) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as ex:
        futs = {ex.submit(resolve_ips_socket, s): s for s in subs}
        for fut in as_completed(futs):
            s = futs[fut]
            try:
                ips = fut.result() or []
            except Exception:
                ips = []
            out[str(s)] = [str(ip) for ip in ips]
    return out
