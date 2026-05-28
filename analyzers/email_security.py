from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


def extract_spf(txt_records: List[str]) -> str:
    for t in txt_records or []:
        if "v=spf1" in str(t).lower():
            return str(t).strip()
    return ""


def extract_dmarc_policy(txt_records: List[str]) -> str:
    for t in txt_records or []:
        s = str(t).strip()
        if "v=dmarc1" not in s.lower():
            continue
        m = re.search(r"(?:^|;)\s*p\s*=\s*([a-zA-Z0-9_-]+)", s, re.IGNORECASE)
        if m:
            return m.group(1).lower()
        return ""
    return ""


def extract_dmarc_rua(txt_records: List[str]) -> List[str]:
    out: List[str] = []
    for t in txt_records or []:
        s = str(t).strip()
        if "v=dmarc1" not in s.lower():
            continue
        m = re.search(r"(?:^|;)\s*rua\s*=\s*([^;]+)", s, re.IGNORECASE)
        if not m:
            continue
        for part in m.group(1).split(","):
            p = part.strip()
            if p:
                out.append(p)
    return out


def analyze_email_security(*, domain: str, txt_root: List[str], txt_dmarc: List[str]) -> Dict[str, str | List[str]]:
    spf = extract_spf(txt_root)
    dmarc_policy = extract_dmarc_policy(txt_dmarc)
    rua = extract_dmarc_rua(txt_dmarc)
    out: Dict[str, str | List[str]] = {}
    out["domain"] = str(domain)
    out["spf"] = spf or ""
    out["dmarc_policy"] = dmarc_policy or ""
    out["dmarc_rua"] = rua
    return out
