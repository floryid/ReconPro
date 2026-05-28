from __future__ import annotations

import re
from typing import Dict, List


def fingerprint(*, headers: Dict[str, str], body_text: str) -> List[str]:
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    b = (body_text or "")[:300000]
    tech: List[str] = []

    server = str(h.get("server", "")).lower()
    if "nginx" in server:
        tech.append("Nginx")
    if "apache" in server:
        tech.append("Apache")
    if "cloudflare" in server or h.get("cf-ray"):
        tech.append("Cloudflare")
    if "iis" in server:
        tech.append("Microsoft IIS")

    xpow = str(h.get("x-powered-by", "")).lower()
    if "php" in xpow or "php" in server:
        tech.append("PHP")
    if "express" in xpow:
        tech.append("Express")
    if "asp.net" in xpow or "aspnet" in xpow or "asp.net" in str(h.get("x-aspnet-version", "")).lower():
        tech.append("ASP.NET")

    cookies = str(h.get("set-cookie", "")).lower()
    if "laravel_session" in cookies or "xsrf-token" in cookies:
        tech.append("Laravel")
    if "wordpress" in cookies:
        tech.append("WordPress")

    if re.search(r"/wp-content/|/wp-includes/|wp-emoji-release", b, re.IGNORECASE):
        tech.append("WordPress")
    if re.search(r"content=[\"']Joomla!", b, re.IGNORECASE):
        tech.append("Joomla")
    if re.search(r"Drupal\\.settings|drupalSettings", b, re.IGNORECASE):
        tech.append("Drupal")

    if re.search(r"__NEXT_DATA__", b):
        tech.append("Next.js")
    if re.search(r"data-reactroot|react\\.production\\.min\\.js|__REACT_DEVTOOLS_GLOBAL_HOOK__", b, re.IGNORECASE):
        tech.append("React")
    if re.search(r"angular\\.min\\.js|ng-version", b, re.IGNORECASE):
        tech.append("Angular")
    if re.search(r"vue(?:\\.runtime)?\\.min\\.js|data-v-", b, re.IGNORECASE):
        tech.append("Vue.js")

    uniq: List[str] = []
    seen = set()
    for t in tech:
        if t in seen:
            continue
        seen.add(t)
        uniq.append(t)
    return uniq
