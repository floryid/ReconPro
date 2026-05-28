from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Sequence
from urllib.parse import urljoin

from core.http_client import HttpClient


DEFAULT_PATHS = [
    "wp-login.php",
    "wp-admin/",
    "xmlrpc.php",
    "wp-json/",
    "admin/",
    "administrator/",
    "login",
    "signin",
    "user/login",
    "phpmyadmin/",
    "pma/",
    "adminer.php",
    "cpanel",
    "plesk",
    "server-status",
]

EXTENDED_PATHS = [
    ".env",
    ".git/HEAD",
    "backup.zip",
    "backup.tar.gz",
    "db.sql",
    "phpinfo.php",
    "wp-config.php",
    "wp-config.php~",
    "wp-content/uploads/",
    "server-info",
    "sitemap.xml",
    "robots.txt",
]


def _present(status: int) -> bool:
    return int(status) in {200, 301, 302, 303, 307, 308, 401, 403, 405}


async def quick_path_checks(*, base_url: str, client: HttpClient, paths: Sequence[str] | None = None, extended: bool = False) -> Dict[str, Any]:
    base = str(base_url).rstrip("/") + "/"
    out: List[Dict[str, Any]] = []
    sig: List[str] = []
    used = list(paths) if paths else list(DEFAULT_PATHS)
    if bool(extended):
        used = used + list(EXTENDED_PATHS)

    timeout_s = 6.0
    sem = asyncio.Semaphore(10)
    results: List[Dict[str, Any]] = []

    async def one(idx: int, p: str) -> None:
        pp = str(p).lstrip("/")
        if not pp:
            return
        url = urljoin(base, pp)
        async with sem:
            try:
                r = await asyncio.wait_for(client.fetch(url), timeout=timeout_s)
                item = {
                    "i": int(idx),
                    "path": "/" + pp,
                    "url": url,
                    "final_url": r.url,
                    "status": int(r.status),
                    "content_type": r.header("content-type"),
                }
            except Exception as e:
                item = {"i": int(idx), "path": "/" + pp, "url": url, "error": f"{type(e).__name__}: {e}"}
        results.append(item)

    tasks = [asyncio.create_task(one(i, p)) for i, p in enumerate(used[:40])]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    results.sort(key=lambda x: int(x.get("i") or 0))
    for item in results:
        item.pop("i", None)
        out.append(item)
        st = int(item.get("status") or 0)
        if _present(st):
            low = str(item.get("path") or "").lower()
            if "wp-login" in low:
                sig.append("wp-login.php reachable")
            elif low.startswith("/wp-admin"):
                sig.append("wp-admin reachable")
            elif "xmlrpc" in low:
                sig.append("xmlrpc.php reachable")
            elif low.startswith("/admin") or "/administrator" in low:
                sig.append("admin panel path reachable")
            elif "phpmyadmin" in low or low.startswith("/pma"):
                sig.append("phpMyAdmin path reachable")
            elif "adminer" in low:
                sig.append("Adminer path reachable")
            elif "cpanel" in low or "plesk" in low:
                sig.append("hosting panel path reachable")
            elif "server-status" in low:
                sig.append("server-status reachable")

    uniq: List[str] = []
    seen = set()
    for s in sig:
        if s in seen:
            continue
        seen.add(s)
        uniq.append(s)

    found = [x for x in out if isinstance(x, dict) and isinstance(x.get("status"), int) and _present(int(x.get("status") or 0))]
    return {"found": found, "checks": out, "signals": uniq}
