from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
from urllib.parse import urljoin

from core.http_client import HttpClient


async def _try_fetch(client: HttpClient, url: str) -> Dict[str, Any]:
    try:
        r = await asyncio.wait_for(client.fetch(url), timeout=6.0)
    except Exception as e:
        return {"url": url, "error": f"{type(e).__name__}: {e}"}
    return {
        "url": url,
        "final_url": r.url,
        "status": int(r.status),
        "content_type": r.header("content-type"),
    }


def _present(status: Optional[int]) -> bool:
    if status is None:
        return False
    return int(status) in {200, 301, 302, 303, 307, 308, 401, 403, 405}


async def wp_quick_checks(*, base_url: str, client: HttpClient) -> Dict[str, Any]:
    base = str(base_url).rstrip("/") + "/"

    login = await _try_fetch(client, urljoin(base, "wp-login.php"))
    xmlrpc = await _try_fetch(client, urljoin(base, "xmlrpc.php"))
    wpjson = await _try_fetch(client, urljoin(base, "wp-json/"))

    out: Dict[str, Any] = {
        "wp_login": login,
        "xmlrpc": xmlrpc,
        "wp_json": wpjson,
        "signals": [],
    }

    sig = out["signals"]
    if _present(login.get("status")):
        sig.append("wp-login.php reachable")
    if _present(xmlrpc.get("status")):
        sig.append("xmlrpc.php reachable")
    if int(xmlrpc.get("status") or 0) == 405:
        sig.append("xmlrpc.php method not allowed (endpoint exists)")
    if _present(wpjson.get("status")):
        sig.append("wp-json reachable (REST API)")
    return out
