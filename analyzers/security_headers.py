from __future__ import annotations

from typing import Dict

from config import SECURITY_HEADERS


def audit_security_headers(*, headers: Dict[str, str], is_https: bool) -> Dict[str, bool]:
    h = {str(k).lower(): str(v).strip() for k, v in (headers or {}).items()}
    out: Dict[str, bool] = {}
    for name in SECURITY_HEADERS:
        key = name.lower()
        present = bool(h.get(key, ""))
        if name == "Strict-Transport-Security" and not is_https:
            out[name] = present
        else:
            out[name] = present
    return out
