from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from typing import Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from config import AUTH_PARAM_HINTS, FOCUS_PATH_HINTS, LOGIN_URL_HINTS, STATIC_EXT_BLACKLIST
from core.http_client import HttpClient


_SKIP_SCHEMES = {"data", "mailto", "tel", "javascript", "about", "file"}


def _norm_url(url: str) -> str:
    s = urlsplit(str(url).strip())
    path = s.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    fragless = urlunsplit((s.scheme, s.netloc, path, s.query, ""))
    return fragless


def _ext(path: str) -> str:
    p = str(path or "")
    i = p.rfind(".")
    if i < 0:
        return ""
    j = p.rfind("/")
    if j >= 0 and i < j:
        return ""
    return p[i:].lower()


def is_noise_url(url: str) -> bool:
    s = urlsplit(str(url))
    e = _ext(s.path or "")
    return bool(e and e in STATIC_EXT_BLACKLIST)


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


def _is_skipped(url: str) -> bool:
    try:
        s = urlsplit(url)
        if not s.scheme:
            return False
        return s.scheme.lower() in _SKIP_SCHEMES
    except Exception:
        return True


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.hidden: List[Tuple[str, str]] = []
        self.has_password_input = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "a":
            href = a.get("href", "")
            if href:
                self.links.append(href)
        if t in {"img", "script"}:
            src = a.get("src", "")
            if src:
                self.links.append(src)
        if t == "form":
            act = a.get("action", "")
            if act:
                self.links.append(act)
        if t == "input":
            typ = a.get("type", "").lower()
            if typ == "password":
                self.has_password_input = True
            if typ == "hidden":
                name = a.get("name", "").strip()
                val = a.get("value", "").strip()
                if name:
                    self.hidden.append((name, val))


def _looks_like_login_url(url: str) -> bool:
    u = str(url).lower()
    return any(h in u for h in LOGIN_URL_HINTS)


def _looks_like_admin_url(url: str) -> bool:
    u = str(url).lower()
    return any(h in u for h in ("/admin", "administrator", "wp-admin", "cpanel", "plesk"))


def _focus_hint(url: str) -> bool:
    u = str(url).lower()
    return any(h in u for h in FOCUS_PATH_HINTS)


def _extract_query_params(url: str) -> List[str]:
    try:
        q = urlsplit(url).query
        if not q:
            return []
        keys = [k for k, _ in parse_qsl(q, keep_blank_values=True)]
        out: List[str] = []
        seen = set()
        for k in keys:
            kk = str(k).strip()
            if not kk or kk in seen:
                continue
            seen.add(kk)
            out.append(kk)
        return out
    except Exception:
        return []


def _extract_params_from_html(html: str) -> List[str]:
    rx = re.findall(r"[?&]([A-Za-z0-9_\-]{1,60})=", html or "")
    out: List[str] = []
    seen = set()
    for p in rx:
        pp = str(p).strip()
        if not pp or pp in seen:
            continue
        seen.add(pp)
        out.append(pp)
    return out


async def crawl(
    start_url: str,
    *,
    client: HttpClient,
    max_pages: int,
    max_depth: int,
    max_bytes: int,
    same_host: Optional[str] = None,
    allow_external: bool = False,
    seed_urls: Sequence[str] = (),
) -> Dict[str, object]:
    u0 = _norm_url(start_url)
    host = same_host or urlsplit(u0).netloc
    q: asyncio.Queue[Tuple[str, int]] = asyncio.Queue()
    await q.put((u0, 0))
    for su in list(seed_urls or [])[: max(0, int(max_pages))]:
        s = str(su).strip()
        if not s:
            continue
        await q.put((s, 0))
    seen: Set[str] = set()
    seen_lock = asyncio.Lock()
    counters_lock = asyncio.Lock()

    pages_ok = 0
    pages_err = 0

    endpoints: List[str] = []
    urls_with_params: List[str] = []
    param_names: List[str] = []
    hidden_fields: List[str] = []
    login_pages: List[str] = []
    admin_panels: List[str] = []
    external_links: List[str] = []

    param_seen: Set[str] = set()
    ep_seen: Set[str] = set()
    urlp_seen: Set[str] = set()
    hidden_seen: Set[str] = set()
    login_seen: Set[str] = set()
    admin_seen: Set[str] = set()
    ext_seen: Set[str] = set()

    async def handle_url(url: str, depth: int) -> None:
        nonlocal pages_ok, pages_err
        nu = _norm_url(url)
        if _is_skipped(nu):
            return
        if not _is_http(nu):
            return
        if not allow_external and not _same_host(nu, host):
            if nu not in ext_seen and len(external_links) < 120:
                ext_seen.add(nu)
                external_links.append(nu)
            return
        if is_noise_url(nu) and not _focus_hint(nu):
            return
        async with seen_lock:
            if len(seen) >= int(max_pages):
                return
            if nu in seen:
                return
            seen.add(nu)
        try:
            resp = await client.fetch(nu)
        except Exception:
            async with counters_lock:
                pages_err += 1
            return

        async with counters_lock:
            pages_ok += 1
        ctype = resp.header("content-type").lower()
        url_params = _extract_query_params(resp.url)
        if url_params and resp.url not in urlp_seen and not is_noise_url(resp.url):
            urlp_seen.add(resp.url)
            urls_with_params.append(resp.url)
        for p in url_params:
            if p not in param_seen:
                param_seen.add(p)
                param_names.append(p)

        body = resp.body[: max(0, int(max_bytes))] if int(max_bytes) > 0 else resp.body
        text = ""
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = ""

        if _looks_like_login_url(resp.url) and resp.url not in login_seen:
            login_seen.add(resp.url)
            login_pages.append(resp.url)
        if _looks_like_admin_url(resp.url) and resp.url not in admin_seen:
            admin_seen.add(resp.url)
            admin_panels.append(resp.url)

        if "html" in ctype or "xhtml" in ctype:
            parser = _LinkParser()
            try:
                parser.feed(text)
            except Exception:
                pass
            if parser.has_password_input and resp.url not in login_seen:
                login_seen.add(resp.url)
                login_pages.append(resp.url)
            for name, val in parser.hidden:
                k = f"{name}={val}" if val else name
                if k in hidden_seen:
                    continue
                hidden_seen.add(k)
                hidden_fields.append(k)
            for link in parser.links[:500]:
                raw = str(link).strip()
                if not raw:
                    continue
                full = _norm_url(urljoin(resp.url, raw))
                if _is_skipped(full) or not _is_http(full):
                    continue
                if not allow_external and not _same_host(full, host):
                    if full not in ext_seen and len(external_links) < 120:
                        ext_seen.add(full)
                        external_links.append(full)
                    continue
                if depth + 1 <= int(max_depth):
                    await q.put((full, depth + 1))
                s = urlsplit(full)
                if not s.path:
                    continue
                ep = _norm_url(urlunsplit((s.scheme, s.netloc, s.path, "", "")))
                if ep not in ep_seen and not is_noise_url(ep):
                    ep_seen.add(ep)
                    endpoints.append(ep)

        html_params = _extract_params_from_html(text)
        for p in html_params:
            if p not in param_seen:
                param_seen.add(p)
                param_names.append(p)

    worker_n = max(1, min(10, 1 + int(max_pages) // 25))

    async def worker() -> None:
        while True:
            try:
                url, depth = await asyncio.wait_for(q.get(), timeout=0.25)
            except Exception:
                return
            try:
                await handle_url(url, depth)
            finally:
                try:
                    q.task_done()
                except Exception:
                    pass

    tasks = [asyncio.create_task(worker()) for _ in range(worker_n)]
    try:
        await q.join()
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    auth_params = [p for p in param_names if str(p).lower() in set(AUTH_PARAM_HINTS)]
    return {
        "pages_ok": pages_ok,
        "pages_err": pages_err,
        "endpoints": endpoints,
        "urls_with_params": urls_with_params,
        "param_names": param_names,
        "hidden_fields": hidden_fields,
        "login_pages": login_pages,
        "admin_panels": admin_panels,
        "auth_params": auth_params,
        "external_links": external_links,
    }
