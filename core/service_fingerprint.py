from __future__ import annotations

import asyncio
import ssl
from typing import Any, Dict, List, Optional, Sequence, Tuple


TLS_PORTS = {443, 465, 993, 995, 8443, 9443}


def _printable(b: bytes) -> str:
    if not b:
        return ""
    s = b.decode("utf-8", errors="replace")
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = "".join(ch if 32 <= ord(ch) <= 126 else " " for ch in s)
    s = " ".join(s.split())
    return s[:240]


def _mysql_version(handshake: bytes) -> str:
    if not handshake or len(handshake) < 6:
        return ""
    if handshake[0] != 0x0A:
        return ""
    try:
        rest = handshake[1:]
        end = rest.find(b"\x00")
        if end <= 0:
            return ""
        return rest[:end].decode("ascii", errors="replace")[:80]
    except Exception:
        return ""


def _cert_summary(cert: Dict[str, Any]) -> Dict[str, str]:
    def dn(parts: Any) -> str:
        if not isinstance(parts, (list, tuple)):
            return ""
        flat: List[str] = []
        for rdn in parts:
            if not isinstance(rdn, (list, tuple)):
                continue
            for kv in rdn:
                if not isinstance(kv, (list, tuple)) or len(kv) != 2:
                    continue
                k, v = kv
                if k and v:
                    flat.append(f"{k}={v}")
        return ", ".join(flat)[:220]

    out: Dict[str, str] = {}
    if isinstance(cert, dict):
        out["subject"] = dn(cert.get("subject"))
        out["issuer"] = dn(cert.get("issuer"))
        out["notAfter"] = str(cert.get("notAfter") or "")
        sans = cert.get("subjectAltName")
        if isinstance(sans, list):
            names = [str(v) for (t, v) in sans if str(t) == "DNS" and str(v)]
            out["san"] = ", ".join(names[:25])
    return {k: v for k, v in out.items() if v}


async def _probe_plain(ip: str, port: int, *, timeout_s: float) -> Dict[str, Any]:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, int(port)), timeout=float(timeout_s))
    try:
        data = b""
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=float(timeout_s))
        except Exception:
            data = b""

        banner = _printable(data)
        svc = ""

        if int(port) == 22 and (banner.startswith("SSH-") or "ssh" in banner.lower()):
            svc = "SSH"
        elif int(port) == 21 and ("ftp" in banner.lower() or banner):
            svc = "FTP"
        elif int(port) in {25, 587} and ("smtp" in banner.lower() or banner.startswith("220")):
            svc = "SMTP"
        elif int(port) == 110 and (banner.startswith("+OK") or "pop" in banner.lower()):
            svc = "POP3"
        elif int(port) == 143 and (banner.startswith("* OK") or "imap" in banner.lower()):
            svc = "IMAP"
        elif int(port) == 3306:
            ver = _mysql_version(data)
            if ver:
                svc = "MySQL"
                banner = f"MySQL {ver}"
            elif data:
                svc = "MySQL?"

        if not svc and banner:
            svc = "Unknown"

        return {"port": int(port), "service": svc, "banner": banner}
    finally:
        try:
            writer.close()
            if hasattr(writer, "wait_closed"):
                await writer.wait_closed()
        except Exception:
            pass


async def _probe_tls(ip: str, port: int, *, timeout_s: float, sni: Optional[str]) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, int(port), ssl=ctx, server_hostname=str(sni) if sni else None),
        timeout=float(timeout_s),
    )
    try:
        sslobj = writer.get_extra_info("ssl_object")
        cert: Dict[str, Any] = {}
        proto = ""
        cipher = ""
        if sslobj:
            try:
                cert = sslobj.getpeercert() or {}
            except Exception:
                cert = {}
            try:
                proto = str(sslobj.version() or "")
            except Exception:
                proto = ""
            try:
                c = sslobj.cipher()
                if isinstance(c, tuple) and c:
                    cipher = str(c[0] or "")
            except Exception:
                cipher = ""

        return {
            "port": int(port),
            "service": "TLS",
            "tls": {k: v for k, v in {"protocol": proto, "cipher": cipher, **_cert_summary(cert)}.items() if v},
        }
    finally:
        try:
            writer.close()
            if hasattr(writer, "wait_closed"):
                await writer.wait_closed()
        except Exception:
            pass


async def probe_services(
    ip: str,
    ports: Sequence[int],
    *,
    timeout_s: float,
    concurrency: int = 120,
    sni: Optional[str] = None,
) -> List[Dict[str, Any]]:
    sem = asyncio.Semaphore(max(1, int(concurrency)))
    out: List[Dict[str, Any]] = []

    async def one(p: int) -> None:
        async with sem:
            try:
                if int(p) in TLS_PORTS:
                    r = await _probe_tls(ip, int(p), timeout_s=timeout_s, sni=sni)
                else:
                    r = await _probe_plain(ip, int(p), timeout_s=timeout_s)
                if r:
                    out.append(r)
            except Exception:
                return

    tasks = [asyncio.create_task(one(int(p))) for p in ports]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    out.sort(key=lambda x: int(x.get("port") or 0))
    return out

