from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlsplit

from core.http_client import HttpClient


_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def _same_host(url: str, host: str) -> bool:
    try:
        return urlsplit(url).netloc.lower() == host.lower()
    except Exception:
        return False


def _is_http(url: str) -> bool:
    try:
        return urlsplit(url).scheme in {"http", "https"}
    except Exception:
        return False


def _extract_sitemaps_from_robots(text: str) -> List[str]:
    out: List[str] = []
    for line in str(text or "").splitlines():
        ln = line.strip()
        if not ln:
            continue
        if ln.lower().startswith("sitemap:"):
            u = ln.split(":", 1)[1].strip()
            if u:
                out.append(u)
    return out


def _extract_urls_from_sitemap_xml(xml_text: str) -> List[str]:
    return [m.group(1).strip() for m in _LOC_RE.finditer(str(xml_text or "")) if m.group(1).strip()]


async def discover_urls_from_sitemaps(
    *,
    base_url: str,
    client: HttpClient,
    limit_sitemaps: int = 6,
    limit_urls: int = 1200,
) -> Dict[str, Any]:
    base = str(base_url).rstrip("/") + "/"
    host = urlsplit(base).netloc
    robots_url = urljoin(base, "robots.txt")

    robots_text = ""
    try:
        r = await asyncio.wait_for(client.fetch(robots_url), timeout=8.0)
        robots_text = r.body.decode("utf-8", errors="replace")[:400_000]
    except Exception:
        robots_text = ""

    sitemaps: List[str] = []
    sitemaps.extend(_extract_sitemaps_from_robots(robots_text))
    sitemaps.extend([urljoin(base, "sitemap.xml"), urljoin(base, "sitemap_index.xml")])

    uniq_sm: List[str] = []
    seen_sm: Set[str] = set()
    for u in sitemaps:
        uu = str(u).strip()
        if not uu or uu in seen_sm:
            continue
        seen_sm.add(uu)
        uniq_sm.append(uu)

    urls: Set[str] = set()
    used_sitemaps: List[Dict[str, Any]] = []
    for sm in uniq_sm[: max(0, int(limit_sitemaps))]:
        info: Dict[str, Any] = {"url": sm}
        try:
            resp = await asyncio.wait_for(client.fetch(sm), timeout=10.0)
            info["status"] = int(resp.status)
            ctype = resp.header("content-type")
            info["content_type"] = ctype
            text = resp.body.decode("utf-8", errors="replace")
            found = _extract_urls_from_sitemap_xml(text)
            kept = 0
            for u in found:
                if len(urls) >= int(limit_urls):
                    break
                if not _is_http(u):
                    continue
                if host and not _same_host(u, host):
                    continue
                if u not in urls:
                    urls.add(u)
                    kept += 1
            info["urls_added"] = kept
        except Exception as e:
            info["error"] = f"{type(e).__name__}: {e}"
        used_sitemaps.append(info)

    return {
        "robots_url": robots_url,
        "sitemaps": used_sitemaps,
        "urls": sorted(urls)[: int(limit_urls)],
        "url_count": len(urls),
    }
