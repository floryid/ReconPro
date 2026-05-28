from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from core.cache import Cache


def _http_json(url: str, *, timeout_s: float) -> Dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "ReconScanPro/2.0",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=float(timeout_s)) as resp:
            raw = resp.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError):
        return {}
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return {}


def _doh_google(name: str, rtype: str, *, timeout_s: float) -> List[str]:
    q = urllib.parse.quote(str(name).strip())
    t = urllib.parse.quote(str(rtype).strip().upper())
    url = f"https://dns.google/resolve?name={q}&type={t}"
    data = _http_json(url, timeout_s=timeout_s)
    ans = data.get("Answer")
    out: List[str] = []
    if isinstance(ans, list):
        for it in ans:
            if not isinstance(it, dict):
                continue
            v = str(it.get("data") or "").strip()
            if not v:
                continue
            out.append(v)
    return out


def resolve_ips_socket(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return []
    ips: List[str] = []
    for fam, _, _, _, sa in infos:
        if fam == socket.AF_INET and isinstance(sa, tuple):
            ips.append(str(sa[0]))
        elif fam == socket.AF_INET6 and isinstance(sa, tuple):
            ips.append(str(sa[0]))
    seen = set()
    out: List[str] = []
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


def dns_lookup_all(
    domain: str,
    *,
    timeout_s: float,
    cache: Optional[Cache] = None,
    ttl_s: int = 0,
) -> Dict[str, List[str]]:
    d = str(domain).strip().strip(".")
    order = ["CNAME", "A", "AAAA", "NS", "MX", "TXT", "SOA"]
    out: Dict[str, List[str]] = {}
    for t in order:
        key = f"dns:{d}:{t}"
        cached = cache.get(key, ttl_s=ttl_s) if cache else None
        if isinstance(cached, list):
            out[t] = [str(x) for x in cached]
            continue
        vals = _doh_google(d, t, timeout_s=timeout_s)
        out[t] = vals
        if cache:
            cache.set(key, vals)
    return out


def dns_email_security(
    domain: str,
    *,
    timeout_s: float,
    cache: Optional[Cache] = None,
    ttl_s: int = 0,
) -> Dict[str, List[str]]:
    d = str(domain).strip().strip(".")
    out: Dict[str, List[str]] = {}
    queries = {
        "DMARC": f"_dmarc.{d}",
        "MTA-STS": f"_mta-sts.{d}",
        "TLS-RPT": f"_smtp._tls.{d}",
    }
    for label, q in queries.items():
        key = f"dns:{q}:TXT"
        cached = cache.get(key, ttl_s=ttl_s) if cache else None
        if isinstance(cached, list):
            out[label] = [str(x) for x in cached]
            continue
        vals = _doh_google(q, "TXT", timeout_s=timeout_s)
        out[label] = vals
        if cache:
            cache.set(key, vals)
    return out
