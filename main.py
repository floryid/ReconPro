from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import sys
import threading
import time
import webbrowser
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from analyzers.cookie_audit import audit_cookies
from analyzers.email_security import analyze_email_security
from analyzers.panel_checks import quick_path_checks
from analyzers.risk_scorer import risk_score
from analyzers.security_headers import audit_security_headers
from analyzers.tech_fingerprint import fingerprint
from analyzers.wordpress_checks import wp_quick_checks
from config import Defaults, TOP_PORTS
from core.cache import Cache
from core.crawler import crawl
from core.dns_resolver import dns_email_security, dns_lookup_all, resolve_ips_socket
from core.http_client import HttpClient
from core.port_scanner import parse_ports, scan_tcp_ports
from core.rdap import rdap_lookup_ip
from core.service_fingerprint import probe_services
from core.sitemap import discover_urls_from_sitemaps
from core.subdomains import enumerate_subdomains, resolve_subdomains
from core.waf_detector import detect_waf
from utils.logger import safe_exc, setup_logging
from utils.reporter import utc_now_iso, write_report

_HUD_ACTIVE = None


def _parse_headers(header_args: List[str], cookie: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in header_args or []:
        s = str(raw).strip()
        if not s or ":" not in s:
            continue
        k, v = s.split(":", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        out[k] = v
    if cookie:
        out["Cookie"] = str(cookie).strip()
    return out


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(str(s).strip().strip("[]"))
        return True
    except Exception:
        return False


def _is_https(url: str) -> bool:
    try:
        return urlsplit(url).scheme.lower() == "https"
    except Exception:
        return False


def _pick_progress():
    if os.environ.get("RECONSCANPRO_TQDM", "").strip() == "1":
        try:
            from tqdm import tqdm

            return tqdm
        except Exception:
            return None
    if _ansi_ok_stream(sys.stderr):
        return None
    try:
        from tqdm import tqdm

        return tqdm
    except Exception:
        return None


def _title_from_html(text: str) -> str:
    t = str(text or "")
    i = t.lower().find("<title")
    if i < 0:
        return ""
    j = t.lower().find("</title>", i)
    if j < 0:
        return ""
    seg = t[i:j]
    k = seg.lower().find(">")
    if k < 0:
        return ""
    return " ".join(seg[k + 1 :].replace("\r", " ").replace("\n", " ").split())[:140]


def _parse_cert_notafter(s: str) -> Optional[datetime]:
    v = str(s or "").strip()
    if not v:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            dt = datetime.strptime(v, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def _enable_windows_ansi() -> None:
    try:
        if os.name != "nt":
            return
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        if handle == 0 or handle == -1:
            return
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return
        new_mode = ctypes.c_uint32(mode.value | 0x0004)
        kernel32.SetConsoleMode(handle, new_mode)
    except Exception:
        return


def _ansi_ok_stream(stream) -> bool:
    if os.environ.get("RECONSCANPRO_NO_COLOR", "").strip() == "1":
        return False
    if os.environ.get("RECONSCANPRO_FORCE_COLOR", "").strip() == "1":
        return True
    try:
        if not getattr(stream, "isatty", lambda: False)():
            return False
    except Exception:
        return False
    if os.name != "nt":
        return True
    if os.environ.get("WT_SESSION"):
        return True
    if os.environ.get("TERM"):
        return True
    return True


_ANSI = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
}


def _c(text: str, color: str) -> str:
    if not (_ansi_ok_stream(sys.stdout) or _ansi_ok_stream(sys.stderr)):
        return str(text)
    return f"{_ANSI.get(color,'')}{text}{_ANSI['reset']}"


def _tag(label: str, color: str) -> str:
    return f"{_c('[', 'dim')}{_c(label, color)}{_c(']', 'dim')}"


def _risk_color(posture: str, score: int) -> str:
    p = str(posture or "").upper()
    if "HIGH" in p or score >= 70:
        return "red"
    if "MEDIUM" in p or score >= 40:
        return "yellow"
    return "green"


def _port_style(p: int) -> str:
    critical = {3389, 23}
    warn = {22, 21, 445, 5900, 6379, 9200, 9300, 27017, 11211, 1433, 1521, 3306, 5432, 5000, 8080, 8443}
    web = {80, 443, 8000, 8080, 8443, 8888}
    try:
        pp = int(p)
    except Exception:
        return "cyan"
    if pp in critical:
        return "red"
    if pp in warn:
        return "yellow"
    if pp in web:
        return "green"
    return "cyan"


def _fmt_ports(ports: Any) -> str:
    if not isinstance(ports, list) or not ports:
        return _c("-", "dim")
    out = []
    for x in ports[:60]:
        try:
            p = int(x)
        except Exception:
            continue
        out.append(_c(str(p), _port_style(p)))
    return ", ".join(out) if out else _c("-", "dim")


class _Spinner:
    def __init__(self, text: str, *, enabled: bool = True) -> None:
        self.text = str(text)
        self.enabled = bool(enabled) and os.environ.get("RECONSCANPRO_NO_ANIM", "").strip() != "1"
        if os.environ.get("RECONSCANPRO_FORCE_ANIM", "").strip() == "1":
            self.enabled = True
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None
        self._t0 = 0.0

    def __enter__(self) -> "_Spinner":
        if not self.enabled or not _ansi_ok_stream(sys.stderr):
            return self
        self._t0 = time.monotonic()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def stop(self) -> None:
        if not self.enabled or not _ansi_ok_stream(sys.stderr):
            return
        self._stop.set()
        try:
            if self._t:
                self._t.join(timeout=0.6)
        except Exception:
            pass
        try:
            sys.stderr.write("\r" + (" " * 140) + "\r")
            sys.stderr.flush()
        except Exception:
            pass

    def _run(self) -> None:
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        colors = ["cyan", "magenta", "green", "yellow"]
        i = 0
        while not self._stop.is_set():
            idx = i % len(frames)
            ch = frames[idx]
            col = colors[(i // 2) % len(colors)]
            i += 1
            elapsed = 0.0
            try:
                if self._t0:
                    elapsed = max(0.0, time.monotonic() - self._t0)
            except Exception:
                elapsed = 0.0
            try:
                tag = _tag("SCAN", col)
                bar = _c("▌", col) + _c("▌", "dim")
                t = f"{elapsed:0.1f}s"
                sys.stderr.write("\r" + f"{tag} {bar} " + _c(ch, col) + " " + _c(self.text, "dim") + " " + _c(t, "dim"))
                sys.stderr.flush()
            except Exception:
                return
            time.sleep(0.09)


class _Progress:
    def __init__(self, label: str, total: int) -> None:
        self.label = str(label)
        self.total = max(1, int(total))
        self.n = 0
        self._enabled = _ansi_ok_stream(sys.stderr) and os.environ.get("RECONSCANPRO_NO_ANIM", "").strip() != "1"
        if os.environ.get("RECONSCANPRO_FORCE_ANIM", "").strip() == "1":
            self._enabled = True
        self._t0 = time.monotonic()

    def update(self, inc: int = 1) -> None:
        self.n = min(self.total, self.n + max(0, int(inc)))
        if not self._enabled:
            return
        try:
            pct = int((self.n * 100) // max(1, self.total))
            w = 22
            fill = int((pct * w) // 100)
            bar = _c("█" * fill, "cyan") + _c("░" * (w - fill), "dim")
            elapsed = max(0.0, time.monotonic() - self._t0)
            msg = f"{_tag('SCAN', 'cyan')} {_c(self.label, 'dim')} {bar} {_c(str(pct)+'%', 'magenta')} {_c(f'{self.n}/{self.total}', 'dim')} {_c(f'{elapsed:0.1f}s', 'dim')}"
            sys.stderr.write("\r" + msg[:120])
            sys.stderr.flush()
        except Exception:
            return

    def done(self) -> None:
        if not self._enabled:
            return
        try:
            sys.stderr.write("\r" + (" " * 160) + "\r")
            sys.stderr.flush()
        except Exception:
            return


class _HUD:
    def __init__(self, target: str) -> None:
        self.target = str(target or "").strip()
        self._phase = "INIT"
        self._detail = ""
        self._n = 0
        self._total = 0
        self._t0 = 0.0
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None
        self._enabled = (
            _ansi_ok_stream(sys.stderr)
            and os.environ.get("RECONSCANPRO_NO_ANIM", "").strip() != "1"
            and os.environ.get("RECONSCANPRO_TQDM", "").strip() != "1"
        )
        if os.environ.get("RECONSCANPRO_FORCE_ANIM", "").strip() == "1":
            self._enabled = True

    def start(self) -> None:
        if not self._enabled:
            return
        self._t0 = time.monotonic()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def stop(self) -> None:
        if not self._enabled:
            return
        self._stop.set()
        try:
            if self._t:
                self._t.join(timeout=0.6)
        except Exception:
            pass
        try:
            sys.stderr.write("\r" + (" " * 200) + "\r")
            sys.stderr.flush()
        except Exception:
            pass

    def phase(self, name: str, detail: str = "") -> None:
        self._phase = str(name or "").strip() or "SCAN"
        self._detail = str(detail or "").strip()
        self._n = 0
        self._total = 0

    def progress(self, n: int, total: int, detail: str = "") -> None:
        self._n = max(0, int(n))
        self._total = max(0, int(total))
        if detail:
            self._detail = str(detail).strip()

    def _run(self) -> None:
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        cols = ["cyan", "magenta", "green", "yellow"]
        i = 0
        while not self._stop.is_set():
            ch = frames[i % len(frames)]
            col = cols[(i // 2) % len(cols)]
            i += 1
            elapsed = 0.0
            try:
                if self._t0:
                    elapsed = max(0.0, time.monotonic() - self._t0)
            except Exception:
                elapsed = 0.0

            w = 22
            pct = 0
            if self._total > 0:
                pct = int((min(self._n, self._total) * 100) // max(1, self._total))
            fill = int((pct * w) // 100) if self._total > 0 else (i % (w + 1))
            bar = _c("█" * fill, col) + _c("░" * (w - fill), "dim")

            left = f"{_tag('SCAN', col)} {_c(self.target, 'dim')}"
            mid = f"{_c(self._phase, 'bold')} {_c(ch, col)}"
            right = ""
            if self._total > 0:
                right = f"{_c(str(pct)+'%', 'magenta')} {_c(f'{self._n}/{self._total}', 'dim')}"
            msg = f"{left}  {mid}  {bar}  {right} {_c(self._detail, 'dim')} {_c(f'{elapsed:0.1f}s', 'dim')}"

            try:
                width = 120
                try:
                    import shutil

                    width = max(80, int(shutil.get_terminal_size((120, 20)).columns))
                except Exception:
                    width = 120
                sys.stderr.write("\r" + msg[: max(0, width - 1)].ljust(max(0, width - 1)))
                sys.stderr.flush()
            except Exception:
                return
            time.sleep(0.085)


def _hud() -> Optional[_HUD]:
    return _HUD_ACTIVE


def _derive_hosts_from_dns(domain: str, dns_all: Dict[str, Any], dns_extra: Dict[str, Any]) -> List[str]:
    dom = str(domain or "").strip().lower().strip(".")
    if not dom:
        return []

    out: List[str] = []
    seen = set()

    def add_host(v: Any) -> None:
        s_raw = str(v or "").strip()
        if not s_raw:
            return
        if any(ch.isspace() for ch in s_raw):
            for tok in s_raw.replace("\t", " ").split(" "):
                t = tok.strip()
                if t:
                    add_host(t)
            return
        s = s_raw.lower().strip(".")
        if not s:
            return
        if s == dom:
            return
        if not s.endswith("." + dom):
            return
        if s not in seen:
            seen.add(s)
            out.append(s)

    def walk(obj: Any) -> None:
        if obj is None:
            return
        if isinstance(obj, list):
            for it in obj:
                walk(it)
            return
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
            return
        add_host(obj)

    for k in ["NS", "MX", "CNAME", "SOA"]:
        walk((dns_all or {}).get(k))
    for k in ["MTA-STS", "TLS-RPT"]:
        walk((dns_extra or {}).get(k))
    return out


async def _scan_web_target(
    url: str,
    *,
    client: HttpClient,
    do_crawl: bool,
    crawl_pages: int,
    crawl_depth: int,
    crawl_bytes: int,
    do_wp_checks: bool,
    do_panel_checks: bool,
    do_dir_checks: bool,
    do_sitemap: bool,
    sitemap_url_limit: int,
    allow_external: bool,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"url": url}
    base_for_checks = str(url).strip()
    try:
        resp = await client.fetch(url)

        headers = resp.headers
        body = resp.body
        text = ""
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = ""

        title = _title_from_html(text)
        waf_vendor, waf_sigs = detect_waf(headers, text)
        sec = audit_security_headers(headers=headers, is_https=_is_https(resp.url))
        tech = fingerprint(headers=headers, body_text=text)
        cookies = audit_cookies(set_cookies=resp.set_cookies, is_https=_is_https(resp.url))

        base_for_checks = str(resp.url).strip() or base_for_checks
        out["final_url"] = resp.url
        out["status"] = int(resp.status)
        out["title"] = title
        out["headers"] = headers
        out["server"] = str(headers.get("server", "")).strip()
        out["waf"] = {"vendor": waf_vendor, "signals": waf_sigs[:8]} if waf_vendor else {}
        out["security_headers"] = sec
        out["tech"] = tech
        out["cookies"] = cookies
    except Exception as e:
        out["error"] = safe_exc(e)

    extra_login: List[str] = []
    extra_admin: List[str] = []

    seed_urls: List[str] = []
    if do_sitemap:
        try:
            sm = await discover_urls_from_sitemaps(base_url=base_for_checks, client=client, limit_urls=int(sitemap_url_limit))
            out["sitemap"] = {k: v for k, v in sm.items() if k in {"robots_url", "sitemaps", "url_count"}}
            seed_urls = list(sm.get("urls") or [])
        except Exception as e:
            out["sitemap"] = {"error": safe_exc(e)}

    if do_wp_checks:
        try:
            wp = await wp_quick_checks(base_url=base_for_checks, client=client)
            out["wordpress"] = wp
            if isinstance(wp, dict):
                wl = wp.get("wp_login") or {}
                if isinstance(wl, dict):
                    u = str(wl.get("final_url") or wl.get("url") or "").strip()
                    st = int(wl.get("status") or 0)
                    if u and st in {200, 301, 302, 303, 307, 308, 401, 403}:
                        extra_login.append(u)
        except Exception as e:
            out["wordpress"] = {"error": safe_exc(e)}

    if do_panel_checks:
        try:
            pc = await quick_path_checks(base_url=base_for_checks, client=client, extended=bool(do_dir_checks))
            out["panel_checks"] = pc
            if isinstance(pc, dict):
                found = pc.get("found") or []
                if isinstance(found, list):
                    for it in found[:60]:
                        if not isinstance(it, dict):
                            continue
                        pth = str(it.get("path") or "").lower()
                        u = str(it.get("final_url") or it.get("url") or "").strip()
                        st = int(it.get("status") or 0)
                        if not u or st not in {200, 301, 302, 303, 307, 308, 401, 403, 405}:
                            continue
                        if any(x in pth for x in ["login", "signin", "wp-login"]):
                            extra_login.append(u)
                        if any(x in pth for x in ["admin", "wp-admin", "phpmyadmin", "adminer", "cpanel", "plesk", "server-status"]):
                            extra_admin.append(u)
        except Exception as e:
            out["panel_checks"] = {"error": safe_exc(e)}

    if do_crawl:
        try:
            same_host = urlsplit(base_for_checks).netloc
        except Exception:
            same_host = None
        before_login = list(out.get("login_pages") or []) if isinstance(out.get("login_pages"), list) else []
        before_admin = list(out.get("admin_panels") or []) if isinstance(out.get("admin_panels"), list) else []
        c = await crawl(
            base_for_checks,
            client=client,
            max_pages=int(crawl_pages),
            max_depth=int(crawl_depth),
            max_bytes=int(crawl_bytes),
            same_host=same_host,
            allow_external=bool(allow_external),
            seed_urls=seed_urls,
        )
        out.update(c)
        if before_login and isinstance(out.get("login_pages"), list):
            out["login_pages"] = before_login + [x for x in out["login_pages"] if x not in before_login]
        if before_admin and isinstance(out.get("admin_panels"), list):
            out["admin_panels"] = before_admin + [x for x in out["admin_panels"] if x not in before_admin]

    if extra_login:
        cur = list(out.get("login_pages") or []) if isinstance(out.get("login_pages"), list) else []
        for u in extra_login:
            uu = str(u).strip()
            if uu and uu not in cur:
                cur.append(uu)
        out["login_pages"] = cur

    if extra_admin:
        cur = list(out.get("admin_panels") or []) if isinstance(out.get("admin_panels"), list) else []
        for u in extra_admin:
            uu = str(u).strip()
            if uu and uu not in cur:
                cur.append(uu)
        out["admin_panels"] = cur

    return out


async def run_scan(args: argparse.Namespace) -> Dict[str, Any]:
    d = Defaults()
    logger = setup_logging(logfile=str(args.log), level=20)

    target = str(args.target).strip()
    hud_ui = _hud()
    if hud_ui:
        hud_ui.phase("INIT", "preparing...")
    timeout_s = float(args.timeout if args.timeout is not None else d.timeout_s)
    delay_s = float(args.delay if args.delay is not None else d.delay_s)
    concurrency = int(args.concurrency if args.concurrency is not None else d.concurrency)
    deep_on = bool(getattr(args, "deep", False))
    full_on = bool(getattr(args, "full", False)) or deep_on

    cache = Cache(path=str(args.cache)) if args.cache else None
    ttl_s = int(args.cache_ttl if args.cache_ttl is not None else d.cache_ttl_s)

    report: Dict[str, Any] = {"generated_at": utc_now_iso(), "target": target}

    assets: Dict[str, Dict[str, Any]] = {}
    domain = target if not _looks_like_ip(target) else ""
    root_ips: List[str] = []

    if domain:
        if hud_ui:
            hud_ui.phase("DNS", "lookup records")
        with _Spinner("dns lookup..."):
            dns_all = dns_lookup_all(domain, timeout_s=timeout_s, cache=cache, ttl_s=ttl_s)
            dns_extra = dns_email_security(domain, timeout_s=timeout_s, cache=cache, ttl_s=ttl_s)
        report["dns"] = dns_all
        report["dns_extra"] = dns_extra
        derived_hosts = _derive_hosts_from_dns(domain, dns_all if isinstance(dns_all, dict) else {}, dns_extra if isinstance(dns_extra, dict) else {})
        report["dns_derived_hosts"] = derived_hosts

        txt_root = dns_all.get("TXT") or []
        txt_dmarc = dns_extra.get("DMARC") or []
        report["email_security"] = analyze_email_security(domain=domain, txt_root=txt_root, txt_dmarc=txt_dmarc)

        if hud_ui:
            hud_ui.phase("DNS", "resolve ip")
        with _Spinner("resolve ip..."):
            root_ips = resolve_ips_socket(domain)
        report["resolved_ips"] = root_ips

    else:
        root_ips = [target.strip().strip("[]")]
        report["resolved_ips"] = root_ips

    subdomain_block: Dict[str, Any] = {}
    all_subs: List[str] = []
    if domain and (bool(args.subdomains) or full_on):
        sources = [s.strip() for s in str(args.sub_sources or "crtsh,certspotter").split(",") if s.strip()]
        if hud_ui:
            hud_ui.phase("SUB", "enumerating")
        with _Spinner("subdomain enum..."):
            by_src, sub_errors = enumerate_subdomains(
                domain,
                timeout_s=timeout_s,
                limit=int(args.sub_limit),
                sources=sources,
                brute=bool(args.sub_brute),
                cache=cache,
                ttl_s=ttl_s,
            )
        subdomain_block["sources"] = by_src
        if isinstance(sub_errors, dict) and sub_errors:
            subdomain_block["errors"] = sub_errors
        merged = set()
        for lst in by_src.values():
            if not isinstance(lst, list):
                continue
            for s in lst:
                merged.add(str(s).lower().strip("."))
        all_subs = sorted(merged)
        derived_hosts = report.get("dns_derived_hosts") or []
        if isinstance(derived_hosts, list) and derived_hosts:
            subdomain_block["derived"] = derived_hosts
            for h in derived_hosts:
                merged.add(str(h).lower().strip("."))
            all_subs = sorted(merged)
        subdomain_block["all"] = all_subs

        if bool(args.sub_resolve):
            if hud_ui:
                hud_ui.phase("SUB", "resolving")
            with _Spinner("subdomain resolve..."):
                resolved = resolve_subdomains(all_subs[: int(args.sub_resolve)], workers=int(args.workers))
                subdomain_block["resolved"] = resolved
    if not subdomain_block:
        derived_hosts = report.get("dns_derived_hosts") or []
        if isinstance(derived_hosts, list) and derived_hosts:
            subdomain_block = {"derived": derived_hosts, "all": list(derived_hosts)}
    report["subdomains"] = subdomain_block if subdomain_block else {}

    for ip in root_ips:
        assets.setdefault(ip, {"ip": ip, "hosts": []})
        if domain and domain not in assets[ip]["hosts"]:
            assets[ip]["hosts"].append(domain)

    resolved_map = (subdomain_block.get("resolved") or {}) if isinstance(subdomain_block, dict) else {}
    if isinstance(resolved_map, dict):
        for host, ips in resolved_map.items():
            if not isinstance(ips, list):
                continue
            for ip in ips:
                assets.setdefault(str(ip), {"ip": str(ip), "hosts": []})
                if str(host) not in assets[str(ip)]["hosts"]:
                    assets[str(ip)]["hosts"].append(str(host))

    ports_enabled = bool(args.ports) or full_on
    ports_list: List[int] = []
    if ports_enabled:
        if deep_on and not args.ports:
            args.ports = "top"
        if args.ports == "top" or args.ports is True or args.ports is None:
            ports_list = list(TOP_PORTS)
        else:
            ports_list = parse_ports(str(args.ports))
        if not ports_list:
            ports_list = list(TOP_PORTS)

    ip_list = list(assets.keys())
    if ports_enabled and ip_list:
        if hud_ui:
            hud_ui.phase("PORTS", f"{len(ip_list)} ips / {len(ports_list)} ports")
        awaitables = []
        for ip in ip_list:
            assets[ip]["ports_scanned"] = int(len(ports_list))
            assets[ip]["port_timeout_s"] = float(args.port_timeout)
            awaitables.append(
                scan_tcp_ports(
                    ip,
                    ports_list,
                    timeout_s=float(args.port_timeout),
                    concurrency=int(args.port_concurrency),
                )
            )
        with _Spinner("port scan..."):
            results = await asyncio.gather(*awaitables, return_exceptions=True)
        for ip, res in zip(ip_list, results):
            if isinstance(res, Exception):
                assets[ip]["ports"] = []
                assets[ip]["port_error"] = safe_exc(res)
            else:
                if isinstance(res, dict):
                    assets[ip]["port_scan"] = res
                    assets[ip]["ports"] = list(res.get("open_ports") or [])
                else:
                    assets[ip]["ports"] = list(res)

    service_probe_enabled = bool(getattr(args, "service_probe", False)) or full_on
    if service_probe_enabled and ports_enabled and ip_list:
        if hud_ui:
            hud_ui.phase("SERVICES", "fingerprinting")
        svc_timeout = float(getattr(args, "service_timeout", 2.0))
        svc_conc = int(getattr(args, "service_concurrency", 160))
        awaitables = []
        for ip in ip_list:
            ports = assets.get(ip, {}).get("ports") or []
            if not isinstance(ports, list) or not ports:
                awaitables.append(asyncio.sleep(0, result=[]))
                continue
            sni = ""
            hosts = assets.get(ip, {}).get("hosts") or []
            if isinstance(hosts, list):
                for h in hosts:
                    hh = str(h)
                    if hh and not _looks_like_ip(hh):
                        sni = hh
                        break
            awaitables.append(probe_services(ip, [int(p) for p in ports], timeout_s=svc_timeout, concurrency=svc_conc, sni=sni or None))
        with _Spinner("service probe..."):
            results = await asyncio.gather(*awaitables, return_exceptions=True)
        for ip, res in zip(ip_list, results):
            if isinstance(res, Exception):
                assets[ip]["services"] = []
                assets[ip]["service_error"] = safe_exc(res)
            else:
                assets[ip]["services"] = list(res)

    rdap_enabled = bool(args.rdap) or full_on
    if rdap_enabled:
        rdap_block: Dict[str, Any] = {}
        if hud_ui:
            hud_ui.phase("RDAP", "lookup")
        with _Spinner("rdap lookup..."):
            for ip in ip_list[: max(1, int(args.rdap_limit))]:
                url, data = rdap_lookup_ip(ip, timeout_s=timeout_s, cache=cache, ttl_s=ttl_s)
                if data:
                    rdap_block[ip] = {"url": url or "", "data": data}
        report["rdap"] = rdap_block

    report["assets"] = [assets[k] for k in sorted(assets.keys())]

    if deep_on:
        args.crawl = True
        args.wp_checks = True
        args.panel_checks = True
        args.service_probe = True
        args.sitemap = True
        args.sub_brute = True
        args.web_from_ports = True
        args.dir_checks = True
    web_enabled = bool(args.web) or full_on or bool(args.crawl)
    web_block: Dict[str, Any] = {"targets": {}, "meta": {"enabled": bool(web_enabled)}}

    if web_enabled:
        if hud_ui:
            hud_ui.phase("WEB", "building targets")
        extra_headers = _parse_headers(list(getattr(args, "header", []) or []), str(getattr(args, "cookie", "") or ""))
        client = HttpClient(
            timeout_s=timeout_s,
            delay_s=delay_s,
            retries=int(args.retries),
            insecure=bool(getattr(args, "insecure", False)),
            headers=extra_headers,
        )
        urls: List[str] = []
        hosts: List[str] = []
        if domain:
            hosts.append(domain)
        derived_hosts = report.get("dns_derived_hosts") or []
        if isinstance(derived_hosts, list) and derived_hosts:
            hosts.extend([str(x) for x in derived_hosts[:80] if str(x).strip()])
        if isinstance(resolved_map, dict):
            lim = int(args.web_hosts_limit)
            if deep_on:
                lim = max(lim, 300)
            hosts.extend(sorted(resolved_map.keys())[:lim])

        seen_u = set()
        for host in hosts:
            for scheme in ("https", "http"):
                u = f"{scheme}://{host}/"
                if u in seen_u:
                    continue
                seen_u.add(u)
                urls.append(u)

        if bool(getattr(args, "web_from_ports", False)):
            web_http_ports = {80, 8000, 8080, 8888, 3000, 5000}
            web_https_ports = {443, 8443, 9443}
            for ip in ip_list[:200]:
                ports = assets.get(ip, {}).get("ports") or []
                if not isinstance(ports, list) or not ports:
                    continue
                hostnames = assets.get(ip, {}).get("hosts") or []
                host_candidates = [str(x) for x in hostnames if str(x) and not _looks_like_ip(str(x))]
                host = host_candidates[0] if host_candidates else ""
                for p in ports[:120]:
                    try:
                        pp = int(p)
                    except Exception:
                        continue
                    if pp in web_http_ports and pp != 80:
                        if host:
                            u = f"http://{host}:{pp}/"
                            if u not in seen_u:
                                seen_u.add(u)
                                urls.append(u)
                        u = f"http://{ip}:{pp}/"
                        if u not in seen_u:
                            seen_u.add(u)
                            urls.append(u)
                    if pp in web_https_ports and pp != 443:
                        if host:
                            u = f"https://{host}:{pp}/"
                            if u not in seen_u:
                                seen_u.add(u)
                                urls.append(u)
                if deep_on:
                    if 80 in [int(x) for x in ports if str(x).isdigit()]:
                        u = f"http://{ip}/"
                        if u not in seen_u:
                            seen_u.add(u)
                            urls.append(u)
                    if 443 in [int(x) for x in ports if str(x).isdigit()]:
                        u = f"https://{ip}/"
                        if u not in seen_u:
                            seen_u.add(u)
                            urls.append(u)

        tqdm = _pick_progress()
        pbar = tqdm(total=len(urls), desc="web", unit="url") if tqdm else None
        prog = _Progress("web", len(urls)) if (not pbar and _ansi_ok_stream(sys.stderr)) else None
        if hud_ui and not pbar:
            hud_ui.phase("WEB", "scanning")
            hud_ui.progress(0, len(urls), "requests")
        try:
            web_block["meta"]["url_count"] = int(len(urls))
        except Exception:
            pass
        sem = asyncio.Semaphore(max(1, concurrency))

        async def worker(u: str) -> Tuple[str, Dict[str, Any]]:
            async with sem:
                data = await _scan_web_target(
                    u,
                    client=client,
                    do_crawl=bool(args.crawl) or full_on,
                    crawl_pages=int(max(int(args.crawl_pages), 120 if deep_on else int(args.crawl_pages))),
                    crawl_depth=int(max(int(args.crawl_depth), 4 if deep_on else int(args.crawl_depth))),
                    crawl_bytes=int(max(int(args.crawl_bytes), 500_000 if deep_on else int(args.crawl_bytes))),
                    do_wp_checks=bool(getattr(args, "wp_checks", False)) or full_on,
                    do_panel_checks=bool(getattr(args, "panel_checks", False)) or full_on,
                    do_dir_checks=bool(getattr(args, "dir_checks", False)) or deep_on,
                    do_sitemap=bool(getattr(args, "sitemap", False)) or full_on,
                    sitemap_url_limit=int(max(int(getattr(args, "sitemap_url_limit", 1200)), 2500 if deep_on else int(getattr(args, "sitemap_url_limit", 1200)))),
                    allow_external=bool(getattr(args, "allow_external", False)),
                )
                return u, data

        tasks = [asyncio.create_task(worker(u)) for u in urls]
        for coro in asyncio.as_completed(tasks):
            u, data = await coro
            web_block["targets"][u] = data
            if pbar:
                try:
                    pbar.update(1)
                except Exception:
                    pass
            if prog:
                prog.update(1)
            if hud_ui and not pbar:
                hud_ui.progress(len(web_block["targets"]), len(urls), "requests")
        if pbar:
            try:
                pbar.close()
            except Exception:
                pass
        if prog:
            prog.done()

    if not web_enabled:
        web_block = {"meta": {"enabled": False, "reason": "web disabled (gunakan --full / --deep / --web)"}}
    report["web"] = web_block

    findings: Dict[str, Any] = {}
    email = report.get("email_security") or {}
    if isinstance(email, dict):
        findings["dmarc_policy"] = str(email.get("dmarc_policy") or "")
    findings["single_ip"] = len(set(root_ips)) == 1 and bool(root_ips)

    auth_params_all: List[str] = []
    admin_all: List[str] = []
    missing_headers_all: List[str] = []
    server_header = ""
    open_ports_all: List[int] = []
    cookie_agg = {"missing_secure": 0, "missing_httponly": 0, "missing_samesite": 0, "total": 0}
    wp_flags = {"wp_login_reachable": False, "xmlrpc_reachable": False, "wp_json_reachable": False}
    port_scan_inconclusive = False
    tls_weak: List[str] = []
    tls_protocols: List[str] = []
    cert_min_days: Optional[int] = None

    for a in report.get("assets") or []:
        if isinstance(a, dict):
            for p in a.get("ports") or []:
                try:
                    open_ports_all.append(int(p))
                except Exception:
                    pass
            for svc in a.get("services") or []:
                if not isinstance(svc, dict):
                    continue
                if str(svc.get("service") or "") != "TLS":
                    continue
                tls = svc.get("tls") or {}
                if not isinstance(tls, dict):
                    continue
                proto = str(tls.get("protocol") or "").strip()
                if proto and proto not in tls_protocols:
                    tls_protocols.append(proto)
                if proto in {"TLSv1", "TLSv1.0", "TLSv1.1"} and proto not in tls_weak:
                    tls_weak.append(proto)
                na = _parse_cert_notafter(str(tls.get("notAfter") or ""))
                if na:
                    days = int((na - datetime.now(timezone.utc)).total_seconds() // 86400)
                    if cert_min_days is None or days < cert_min_days:
                        cert_min_days = days
            ps = a.get("port_scan") or {}
            if isinstance(ps, dict):
                attempted = int(ps.get("attempted") or 0)
                errs = ps.get("errors") or {}
                openp = ps.get("open_ports") or []
                if attempted > 0 and isinstance(errs, dict) and (not isinstance(openp, list) or len(openp) == 0):
                    other = 0
                    for k, v in errs.items():
                        if str(k) == "timeout":
                            continue
                        try:
                            other += int(v)
                        except Exception:
                            continue
                    tout = 0
                    try:
                        tout = int(errs.get("timeout") or 0)
                    except Exception:
                        tout = 0
                    if (tout + other) >= max(3, int(attempted * 0.8)):
                        port_scan_inconclusive = True

    web_targets = (report.get("web") or {}).get("targets") if isinstance(report.get("web"), dict) else {}
    if isinstance(web_targets, dict):
        for _, w in web_targets.items():
            if not isinstance(w, dict):
                continue
            if not server_header:
                server_header = str(w.get("server") or "").strip()
            for p in w.get("auth_params") or []:
                if str(p) not in auth_params_all:
                    auth_params_all.append(str(p))
            for ap in w.get("admin_panels") or []:
                if str(ap) not in admin_all:
                    admin_all.append(str(ap))
            sec = w.get("security_headers") or {}
            if isinstance(sec, dict):
                for k, v in sec.items():
                    if v is False and str(k) not in missing_headers_all:
                        missing_headers_all.append(str(k))

            ck = w.get("cookies") or {}
            if isinstance(ck, dict):
                for k in ["missing_secure", "missing_httponly", "missing_samesite", "total"]:
                    try:
                        cookie_agg[k] = max(int(cookie_agg.get(k) or 0), int(ck.get(k) or 0))
                    except Exception:
                        continue

            wp = w.get("wordpress") or {}
            if isinstance(wp, dict):
                login = wp.get("wp_login") or {}
                xmlrpc = wp.get("xmlrpc") or {}
                wpjson = wp.get("wp_json") or {}
                try:
                    wp_flags["wp_login_reachable"] = wp_flags["wp_login_reachable"] or int(login.get("status") or 0) in {200, 301, 302, 303, 307, 308, 401, 403}
                except Exception:
                    pass
                try:
                    wp_flags["xmlrpc_reachable"] = wp_flags["xmlrpc_reachable"] or int(xmlrpc.get("status") or 0) in {200, 301, 302, 303, 307, 308, 401, 403, 405}
                except Exception:
                    pass
                try:
                    wp_flags["wp_json_reachable"] = wp_flags["wp_json_reachable"] or int(wpjson.get("status") or 0) in {200, 301, 302, 303, 307, 308, 401, 403}
                except Exception:
                    pass

            pc = w.get("panel_checks") or {}
            if isinstance(pc, dict):
                found = pc.get("found") or []
                if isinstance(found, list):
                    for it in found[:50]:
                        if not isinstance(it, dict):
                            continue
                        path = str(it.get("path") or "").strip()
                        url = str(it.get("final_url") or it.get("url") or "").strip()
                        if path and path not in admin_all and any(x in path.lower() for x in ["admin", "wp-admin", "wp-login", "cpanel", "plesk", "phpmyadmin", "adminer", "server-status"]):
                            admin_all.append(path)
                        if url and url not in admin_all and any(x in url.lower() for x in ["admin", "wp-admin", "wp-login", "cpanel", "plesk", "phpmyadmin", "adminer", "server-status"]):
                            admin_all.append(url)

    findings["auth_params"] = auth_params_all
    findings["admin_panels"] = admin_all
    findings["missing_security_headers"] = missing_headers_all
    findings["server_header"] = server_header
    findings["open_ports"] = sorted(set(open_ports_all))
    findings["cookie_issues"] = cookie_agg
    findings["wordpress"] = wp_flags
    findings["port_scan_inconclusive"] = port_scan_inconclusive
    findings["tls_protocols"] = tls_protocols
    findings["tls_weak_protocols"] = tls_weak
    if cert_min_days is not None:
        findings["cert_min_days"] = int(cert_min_days)

    if hud_ui:
        hud_ui.phase("RISK", "scoring")
    report["risk"] = risk_score(findings)
    return report


def build_arg_parser() -> argparse.ArgumentParser:
    d = Defaults()

    class _Fmt(argparse.RawDescriptionHelpFormatter):
        pass

    p = argparse.ArgumentParser(
        prog="ReconScanPro",
        formatter_class=_Fmt,
        description=(
            "ReconScanPro - Reconnaissance & Security Posture Scanner\n"
            "\n"
            "Fokus: enumerasi aset + port + web metadata + DNS/email security + risk summary.\n"
            "Bukan exploit tool. Gunakan hanya pada target yang kamu punya izin.\n"
            "\n"
            "Output utama:\n"
            "- Console summary\n"
            "- Export report: --export html / --export json\n"
        ),
        epilog=(
            "CONTOH PEMAKAIAN\n"
            "\n"
            "1) Scan cepat (DNS + port scan TOP PORTS)\n"
            "   python app.py intracopenta.com --ports top\n"
            "\n"
            "2) Recon standar (umumnya cukup untuk baseline)\n"
            "   python app.py intracopenta.com --full --export html\n"
            "\n"
            "3) Deep preset (lebih agresif, lebih lama)\n"
            "   python app.py intracopenta.com --deep --export html\n"
            "\n"
            "4) Web scan dari port yang terbuka (mis. 8080/8443)\n"
            "   python app.py intracopenta.com --full --web --web-from-ports --export html\n"
            "\n"
            "5) Subdomain enumeration + resolve\n"
            "   python app.py intracopenta.com --subdomains --sub-resolve 200 --sub-brute --export html\n"
            "\n"
            "6) Port custom + service probe (fingerprint)\n"
            "   python app.py intracopenta.com --ports 80,443,8080,3389 --service-probe --export html\n"
            "\n"
            "7) Crawl + sitemap seeds (endpoint discovery)\n"
            "   python app.py intracopenta.com --web --crawl --sitemap --export html\n"
            "\n"
            "8) Authenticated scan (gunakan hanya jika punya izin)\n"
            "   python app.py intracopenta.com --full --cookie \"session=...\" --header \"Authorization: Bearer ...\" --export html\n"
        ),
    )
    p.add_argument("target", help="Domain atau IP target")

    p.add_argument("--full", action="store_true", help="Aktifkan modul utama (dns + subdomains + rdap + ports + web + crawl + report)")
    p.add_argument("--deep", action="store_true", help="Preset lebih agresif/komplit (crawl lebih dalam + sitemap + probes). Gunakan hanya jika punya izin")

    p.add_argument("--timeout", type=float, default=d.timeout_s, help="Timeout HTTP/DNS (detik)")
    p.add_argument("--delay", type=float, default=d.delay_s, help="Delay antar request HTTP (detik)")
    p.add_argument("--concurrency", type=int, default=d.concurrency, help="Concurrency untuk web scan")
    p.add_argument("--retries", type=int, default=2, help="Retry untuk HTTP")
    p.add_argument("--insecure", action="store_true", help="Lewati verifikasi TLS (berguna jika cert bermasalah)")
    p.add_argument("--cookie", default="", help="Cookie header untuk akses terautentikasi (jangan commit ke GitHub)")
    p.add_argument("--header", action="append", default=[], help="Header tambahan (ulang) format: 'Key: Value' (jangan commit ke GitHub)")

    p.add_argument("--cache", default="cache.sqlite", help="Path cache SQLite")
    p.add_argument("--cache-ttl", type=int, default=d.cache_ttl_s, help="TTL cache (detik)")

    p.add_argument("--subdomains", action="store_true", help="Aktifkan enumerasi subdomain")
    p.add_argument("--sub-sources", default="crtsh,certspotter", help="Sumber subdomain: crtsh, certspotter, virustotal, securitytrails")
    p.add_argument("--sub-limit", type=int, default=400, help="Batas hasil per sumber")
    p.add_argument("--sub-brute", action="store_true", help="Bruteforce wordlist kecil (tanpa wordlist eksternal)")
    p.add_argument("--sub-resolve", type=int, default=120, help="Resolve subdomain ke IP (0 untuk skip)")
    p.add_argument("--workers", type=int, default=60, help="Thread untuk resolve subdomain")

    p.add_argument("--rdap", action="store_true", help="Aktifkan RDAP lookup untuk IP")
    p.add_argument("--rdap-limit", type=int, default=8, help="Batas jumlah IP untuk RDAP")

    p.add_argument("--ports", nargs="?", const="top", default=None, help="Scan port TCP. Value: top atau '80,443,8080' atau '1-1024'")
    p.add_argument("--port-timeout", type=float, default=d.port_timeout_s, help="Timeout connect per port")
    p.add_argument("--port-concurrency", type=int, default=300, help="Concurrency port scan per IP")
    p.add_argument("--service-probe", action="store_true", help="Ambil banner/cert ringan untuk port yang terbuka (meningkatkan akurasi temuan)")
    p.add_argument("--service-timeout", type=float, default=2.0, help="Timeout banner/cert per port (detik)")
    p.add_argument("--service-concurrency", type=int, default=160, help="Concurrency service probe per IP")

    p.add_argument("--web", action="store_true", help="Aktifkan web probe (status, headers, WAF, security headers)")
    p.add_argument("--web-hosts-limit", type=int, default=120, help="Batas host untuk web scan (root + resolved subs)")

    p.add_argument("--crawl", action="store_true", help="Crawl ringan same-host (GET saja) untuk kumpulkan endpoint/params/login/admin")
    p.add_argument("--allow-external", action="store_true", help="Saat crawl, izinkan mengikuti link external (default: tidak)")
    p.add_argument("--crawl-pages", type=int, default=d.crawl_pages, help="Batas halaman crawl")
    p.add_argument("--crawl-depth", type=int, default=d.crawl_depth, help="Kedalaman crawl")
    p.add_argument("--crawl-bytes", type=int, default=d.crawl_bytes, help="Batas byte per halaman")
    p.add_argument("--wp-checks", action="store_true", help="Quick checks WordPress (wp-login/wp-json/xmlrpc)")
    p.add_argument("--panel-checks", action="store_true", help="Quick checks path admin panel/login umum (tanpa crawl)")
    p.add_argument("--dir-checks", action="store_true", help="Extended path checks (opsional, hanya jika punya izin)")
    p.add_argument("--sitemap", action="store_true", help="Ambil URL dari robots.txt/sitemap.xml sebagai seed crawl")
    p.add_argument("--sitemap-url-limit", type=int, default=1200, help="Batas URL dari sitemap untuk dijadikan seed crawl")
    p.add_argument("--web-from-ports", action="store_true", help="Tambahkan web target dari port web yang terbuka (mis. :8080, :8443)")

    p.add_argument("--export", choices=["json", "html"], default=None, help="Export report ke JSON/HTML")
    p.add_argument("--export-path", default=None, help="Path output export (default: report.json/report.html)")
    p.add_argument("--interactive", action="store_true", help="Mode interaktif sederhana setelah scan")

    p.add_argument("--log", default="scan_log.txt", help="File log")
    return p


def _print_summary(report: Dict[str, Any]) -> None:
    target = str(report.get("target") or "")
    risk = report.get("risk") or {}
    score = int((risk.get("score") or 0) if isinstance(risk, dict) else 0)
    posture = str((risk.get("posture") or "") if isinstance(risk, dict) else "")
    notes = (risk.get("notes") or []) if isinstance(risk, dict) else []

    print("")
    print(f"{_tag('TARGET', 'cyan')} {target}")
    print(f"{_tag('RISK', _risk_color(posture, score))} {_c(posture, _risk_color(posture, score))} {_c(f'(Score: {score}/100)', 'dim')}")
    if isinstance(notes, list) and notes:
        print(f"{_tag('NOTES', 'magenta')}")
        for n in notes[:30]:
            s = str(n).strip()
            if s:
                print(f" {_c('-', 'cyan')} {s}")

    assets = report.get("assets") or []
    if isinstance(assets, list) and assets:
        print("")
        print(f"{_tag('ASSETS', 'cyan')}")
        for a in assets[:50]:
            if not isinstance(a, dict):
                continue
            ip = a.get("ip")
            hosts = a.get("hosts") or []
            ports = a.get("ports") or []
            ps = a.get("port_scan") or {}
            scanned = a.get("ports_scanned")
            perr = ""
            if isinstance(ps, dict):
                scanned = scanned if scanned is not None else ps.get("attempted")
                errs = ps.get("errors") or {}
                if isinstance(errs, dict) and errs:
                    tops = []
                    for k, v in list(errs.items())[:6]:
                        tops.append(f"{k}:{v}")
                    perr = ", ".join(tops)
            h = ", ".join(str(x) for x in hosts[:8])
            p = _fmt_ports(ports)
            extra = ""
            raw_ports_empty = not (isinstance(ports, list) and len(ports) > 0)
            if scanned is not None and raw_ports_empty:
                extra = f" | scanned:{scanned}"
                if perr:
                    extra += f" | errs:{perr}"
            print(f" {_c('-', 'cyan')} {_c(str(ip), 'cyan')} {_c('|', 'dim')} hosts: {h or '-'} {_c('|', 'dim')} ports: {p}{_c(extra, 'dim') if extra else ''}")

    web = report.get("web") or {}
    targets = web.get("targets") if isinstance(web, dict) else {}
    if isinstance(targets, dict) and targets:
        print("")
        print(f"{_tag('WEB', 'cyan')}")
        for u, w in list(targets.items())[:40]:
            if not isinstance(w, dict):
                continue
            st = w.get("status")
            title = w.get("title") or ""
            err = w.get("error") or ""
            waf = ((w.get("waf") or {}) or {}).get("vendor") if isinstance(w.get("waf"), dict) else ""
            lp = w.get("login_pages") or []
            ap = w.get("admin_panels") or []
            if err:
                print(f" {_c('-', 'cyan')} {u} {_c('|', 'dim')} {_c('error', 'red')}: {err}")
                continue
            stc = "green" if int(st or 0) in {200, 301, 302, 303, 307, 308} else "yellow"
            print(f" {_c('-', 'cyan')} {u} {_c('|', 'dim')} {_c(str(st), stc)} {_c('|', 'dim')} {title}")
            if waf:
                print(f"   {_c('waf', 'magenta')}: {waf}")
            if isinstance(lp, list) and lp:
                print(f"   {_c('login', 'cyan')}: {lp[0]}")
            if isinstance(ap, list) and ap:
                print(f"   {_c('admin', 'yellow')}: {ap[0]}")


def main() -> int:
    _enable_windows_ansi()
    p = build_arg_parser()
    args = p.parse_args()

    global _HUD_ACTIVE
    hud = _HUD(str(getattr(args, "target", "") or ""))
    _HUD_ACTIVE = hud
    hud.start()
    try:
        report: Dict[str, Any] = asyncio.run(run_scan(args))
    finally:
        try:
            hud.stop()
        finally:
            _HUD_ACTIVE = None
    _print_summary(report)

    out = write_report(report=report, export=args.export, export_path=args.export_path)
    if out:
        print("")
        print(f"{_tag('EXPORT', 'magenta')} {_c(str(out), 'cyan')}")
    if bool(getattr(args, "interactive", False)):
        login_url = ""
        web_targets = (report.get("web") or {}).get("targets") if isinstance(report.get("web"), dict) else {}
        if isinstance(web_targets, dict):
            for _, w in web_targets.items():
                if not isinstance(w, dict):
                    continue
                lp = w.get("login_pages") or []
                if isinstance(lp, list) and lp:
                    login_url = str(lp[0])
                    break
        candidate = login_url or out or ""
        if candidate:
            ans = input(f"Open in browser? {candidate} (y/n): ").strip().lower()
            if ans == "y":
                try:
                    webbrowser.open(candidate)
                except Exception:
                    pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
