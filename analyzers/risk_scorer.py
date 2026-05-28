from __future__ import annotations

import re
from typing import Any, Dict, List


def _has_version(server_header: str) -> bool:
    s = str(server_header or "")
    return bool(re.search(r"\b\d+\.\d+", s))


def risk_score(findings: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    notes: List[str] = []

    dmarc = str(findings.get("dmarc_policy") or "").lower().strip()
    if dmarc == "none":
        score += 20
        notes.append("DMARC policy p=none (rentan spoofing)")
    elif dmarc == "":
        score += 10
        notes.append("DMARC tidak terdeteksi")

    single_ip = bool(findings.get("single_ip"))
    if single_ip:
        score += 15
        notes.append("Single point of failure (semua layanan pada 1 IP)")

    auth_params = findings.get("auth_params") or []
    if isinstance(auth_params, list) and auth_params:
        score += 30
        notes.append("Parameter autentikasi terdeteksi di URL/HTML")

    server = str(findings.get("server_header") or "").strip()
    if server and _has_version(server):
        score += 10
        notes.append("Versi server terekspos pada header Server")

    missing_headers = findings.get("missing_security_headers") or []
    if isinstance(missing_headers, list) and missing_headers:
        miss = [str(h) for h in missing_headers if str(h).strip()]
        score += min(22, 4 * len(miss))
        notes.append("Security headers penting hilang: " + ", ".join(miss[:8]))

    admin_panels = findings.get("admin_panels") or []
    if isinstance(admin_panels, list) and admin_panels:
        score += 10
        notes.append("Admin panel terdeteksi")

    open_ports = findings.get("open_ports") or []
    ports = []
    if isinstance(open_ports, list):
        for p in open_ports:
            try:
                ports.append(int(p))
            except Exception:
                continue

    high_ports = [p for p in ports if p in {22, 3389, 2375, 3306, 5432, 6379, 27017}]
    if 3306 in ports:
        score += 35
        notes.append("MySQL (3306) terdeteksi terbuka")
    if 2375 in ports:
        score += 35
        notes.append("Docker API (2375) terdeteksi terbuka")
    if 3389 in ports:
        score += 25
        notes.append("RDP (3389) terdeteksi terbuka")
    if 22 in ports:
        score += 18
        notes.append("SSH (22) terdeteksi terbuka")
    if any(p in ports for p in {5432, 6379, 27017}):
        score += 20
        notes.append("Port database umum terdeteksi terbuka")
    if high_ports and all("terdeteksi terbuka" not in n for n in notes if "Port" in n):
        notes.append("Port manajemen/database umum terdeteksi terbuka")

    if bool(findings.get("port_scan_inconclusive")):
        notes.append("Port scan tidak konklusif (banyak timeout). Bisa jadi port terbuka tidak terdeteksi dari jaringan ini")

    weak_tls = findings.get("tls_weak_protocols") or []
    if isinstance(weak_tls, list) and weak_tls:
        score += min(18, 9 * len(set(str(x) for x in weak_tls if str(x).strip())))
        notes.append("TLS lemah terdeteksi: " + ", ".join(sorted(set(str(x) for x in weak_tls if str(x).strip()))[:4]))

    cert_days = findings.get("cert_min_days")
    try:
        if cert_days is not None:
            d = int(cert_days)
            if d <= 7:
                score += 14
                notes.append(f"Sertifikat TLS hampir kadaluarsa ({d} hari)")
            elif d <= 21:
                score += 8
                notes.append(f"Sertifikat TLS akan kadaluarsa ({d} hari)")
    except Exception:
        pass

    cookie_issues = findings.get("cookie_issues") or {}
    if isinstance(cookie_issues, dict):
        ms = int(cookie_issues.get("missing_secure") or 0)
        mh = int(cookie_issues.get("missing_httponly") or 0)
        mss = int(cookie_issues.get("missing_samesite") or 0)
        if mh > 0 or mss > 0 or ms > 0:
            score += min(18, 3 * (ms + mh + mss))
            notes.append(f"Cookie flags lemah (Secure:{ms}, HttpOnly:{mh}, SameSite:{mss})")

    wp = findings.get("wordpress") or {}
    if isinstance(wp, dict):
        if bool(wp.get("xmlrpc_reachable")):
            score += 10
            notes.append("WordPress xmlrpc.php reachable (sering jadi surface bruteforce/abuse)")
        if bool(wp.get("wp_login_reachable")):
            score += 6
            notes.append("WordPress wp-login.php reachable")

    score = max(0, min(int(score), 100))
    if score >= 70:
        posture = "HIGH RISK"
    elif score >= 40:
        posture = "MEDIUM RISK"
    else:
        posture = "LOW RISK"

    return {"score": score, "posture": posture, "notes": notes}
