from __future__ import annotations

from typing import Dict, List, Sequence


def _parse_attrs(cookie: str) -> Dict[str, str]:
    parts = [p.strip() for p in str(cookie or "").split(";") if p.strip()]
    out: Dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k.strip().lower()] = v.strip()
        else:
            out[p.strip().lower()] = ""
    return out


def _cookie_name(cookie: str) -> str:
    first = str(cookie or "").split(";", 1)[0]
    if "=" in first:
        return first.split("=", 1)[0].strip()[:80]
    return first.strip()[:80]


def audit_cookies(*, set_cookies: Sequence[str], is_https: bool) -> Dict[str, object]:
    cookies = [str(c) for c in (set_cookies or []) if str(c).strip()]
    issues: List[str] = []
    missing_secure = 0
    missing_httponly = 0
    missing_samesite = 0

    for c in cookies[:80]:
        name = _cookie_name(c)
        attrs = _parse_attrs(c)

        has_secure = "secure" in attrs
        has_httponly = "httponly" in attrs
        ss = attrs.get("samesite", "")
        has_samesite = bool(ss)

        if is_https and not has_secure:
            missing_secure += 1
            issues.append(f"Cookie {name}: missing Secure")
        if not has_httponly:
            missing_httponly += 1
            issues.append(f"Cookie {name}: missing HttpOnly")
        if not has_samesite:
            missing_samesite += 1
            issues.append(f"Cookie {name}: missing SameSite")
        else:
            ssv = str(ss).lower()
            if ssv not in {"lax", "strict", "none"}:
                issues.append(f"Cookie {name}: invalid SameSite={ss}")
            if ssv == "none" and is_https and not has_secure:
                issues.append(f"Cookie {name}: SameSite=None without Secure")

    return {
        "total": len(cookies),
        "missing_secure": missing_secure,
        "missing_httponly": missing_httponly,
        "missing_samesite": missing_samesite,
        "issues": issues[:120],
    }

