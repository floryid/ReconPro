from __future__ import annotations

import re
from typing import Dict, List, Tuple


def detect_waf(headers: Dict[str, str], body_text: str) -> Tuple[str, List[str]]:
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    b = (body_text or "")[:20000]
    sigs: List[str] = []

    def has_header(name: str) -> bool:
        return bool(h.get(name.lower(), "").strip())

    def h_contains(name: str, needle: str) -> bool:
        return needle.lower() in str(h.get(name.lower(), "")).lower()

    if has_header("cf-ray") or h_contains("server", "cloudflare") or h_contains("cf-cache-status", ""):
        if has_header("cf-ray"):
            sigs.append("header:cf-ray")
        if h_contains("server", "cloudflare"):
            sigs.append("server:cloudflare")
        return "Cloudflare", sigs

    if has_header("x-akamai-transformed") or h_contains("server", "akamai") or h_contains("x-cache", "akamai"):
        if has_header("x-akamai-transformed"):
            sigs.append("header:x-akamai-transformed")
        if h_contains("x-cache", "akamai"):
            sigs.append("header:x-cache:akamai")
        return "Akamai", sigs

    if h_contains("server", "imperva") or has_header("x-iinfo") or "incapsula" in b.lower():
        if has_header("x-iinfo"):
            sigs.append("header:x-iinfo")
        if "incapsula" in b.lower():
            sigs.append("body:incapsula")
        return "Imperva/Incapsula", sigs

    if has_header("x-amzn-requestid") or h_contains("server", "awselb") or h_contains("x-amzn-trace-id", ""):
        if has_header("x-amzn-trace-id"):
            sigs.append("header:x-amzn-trace-id")
        return "AWS (WAF/ELB)", sigs

    if h_contains("server", "f5") or has_header("x-waf-event"):
        if h_contains("server", "f5"):
            sigs.append("server:f5")
        if has_header("x-waf-event"):
            sigs.append("header:x-waf-event")
        return "F5 (ASM/BigIP)", sigs

    rx = [
        (r"access denied", "body:access denied"),
        (r"request (?:was )?blocked", "body:blocked"),
        (r"web application firewall", "body:waf"),
        (r"malicious request", "body:malicious request"),
    ]
    for pat, label in rx:
        if re.search(pat, b, re.IGNORECASE):
            sigs.append(label)

    if sigs:
        return "Generic WAF", sigs
    return "", []
