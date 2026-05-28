from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from core.cache import Cache


def rdap_servers_for_ip(ip: str) -> List[str]:
    q = urllib.parse.quote(str(ip))
    return [
        f"https://rdap.arin.net/registry/ip/{q}",
        f"https://rdap.db.ripe.net/ip/{q}",
        f"https://rdap.apnic.net/ip/{q}",
        f"https://rdap.lacnic.net/rdap/ip/{q}",
        f"https://rdap.afrinic.net/rdap/ip/{q}",
    ]


def _http_get_json_rdap(url: str, *, timeout_s: float) -> Dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ReconScanPro/2.0",
            "Accept": "application/rdap+json, application/json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=float(timeout_s)) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        try:
            raw = e.read() if hasattr(e, "read") else b""
        except Exception:
            raw = b""
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return {}


def rdap_lookup_ip(
    ip: str,
    *,
    timeout_s: float,
    cache: Optional[Cache] = None,
    ttl_s: int = 0,
) -> Tuple[Optional[str], Dict[str, Any]]:
    key = f"rdap:ip:{ip}"
    cached = cache.get(key, ttl_s=ttl_s) if cache else None
    if isinstance(cached, dict) and cached.get("url") and cached.get("data"):
        return str(cached.get("url")), dict(cached.get("data") or {})

    for url in rdap_servers_for_ip(ip):
        data = {}
        try:
            data = _http_get_json_rdap(url, timeout_s=timeout_s)
        except Exception:
            data = {}
        if not data:
            continue
        if isinstance(data, dict) and data.get("errorCode") in (400, 404, 410):
            continue
        if isinstance(data, dict) and (data.get("startAddress") or data.get("handle") or data.get("name")):
            if cache:
                cache.set(key, {"url": url, "data": data})
            return url, data
    return None, {}
