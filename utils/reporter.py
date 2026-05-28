from __future__ import annotations

import copy
import json
import os
import re
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: str, data: Dict[str, Any]) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    try:
        os.replace(tmp, path)
    except Exception:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
                f.write("\n")
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
    return path


def _risk_color(score: int) -> str:
    s = int(score)
    if s >= 70:
        return "#ef4444"
    if s >= 40:
        return "#f59e0b"
    return "#22c55e"


def write_html(path: str, report: Dict[str, Any]) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)

    title = escape(str(report.get("target") or "Recon Report"))
    score = int(((report.get("risk") or {}) or {}).get("score") or 0)
    posture = escape(str(((report.get("risk") or {}) or {}).get("posture") or "UNKNOWN"))
    notes = (report.get("risk") or {}).get("notes") or []

    def li(items: Any) -> str:
        if not isinstance(items, list):
            return ""
        return "".join(f"<li>{escape(str(x))}</li>" for x in items if str(x).strip())

    notes_html = li(notes)
    if not notes_html:
        notes_html = "<li class='muted'>No notes</li>"

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{
      --bg0: #05070b;
      --bg1: #070b12;
      --card: rgba(11, 16, 28, 0.8);
      --card2: rgba(10, 14, 24, 0.6);
      --border: rgba(148, 163, 184, 0.16);
      --text: #e2e8f0;
      --muted: rgba(226, 232, 240, 0.68);
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      --accent: #00ffd5;
      --accent2: #8b5cf6;
      --good: #22c55e;
      --warn: #f59e0b;
      --bad: #ef4444;
      --shadow: 0 12px 40px rgba(0,0,0,.35);
      --shadow2: 0 10px 30px rgba(0,0,0,.28);
    }}

    * {{ box-sizing: border-box; }}
    html, body {{ height: 100%; }}
    body {{
      margin: 0;
      color: var(--text);
      font-family: var(--sans);
      background:
        radial-gradient(1200px 600px at 10% 0%, rgba(0,255,213,0.09), transparent 55%),
        radial-gradient(900px 500px at 90% 10%, rgba(139,92,246,0.12), transparent 55%),
        radial-gradient(1000px 700px at 50% 100%, rgba(34,197,94,0.06), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      overflow-x: hidden;
    }}

    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}

    @keyframes scanlines {{
      0% {{ transform: translateY(-10%); opacity: 0.7; }}
      100% {{ transform: translateY(10%); opacity: 0.7; }}
    }}
    @keyframes sweep {{
      0% {{ transform: translateX(-30%); opacity: 0.0; }}
      20% {{ opacity: 0.7; }}
      50% {{ opacity: 0.25; }}
      100% {{ transform: translateX(30%); opacity: 0.0; }}
    }}
    @keyframes pulse {{
      0% {{ transform: scale(1); filter: saturate(1); }}
      50% {{ transform: scale(1.12); filter: saturate(1.15); }}
      100% {{ transform: scale(1); filter: saturate(1); }}
    }}

    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background:
        repeating-linear-gradient(
          180deg,
          rgba(226,232,240,0.025) 0px,
          rgba(226,232,240,0.025) 1px,
          rgba(0,0,0,0) 2px,
          rgba(0,0,0,0) 6px
        );
      opacity: 0.5;
      animation: scanlines 2.6s linear infinite;
      mix-blend-mode: overlay;
    }}
    body::after {{
      content: "";
      position: fixed;
      inset: -20%;
      pointer-events: none;
      background: linear-gradient(90deg, transparent, rgba(0,255,213,0.08), transparent);
      transform: translateX(-30%);
      animation: sweep 6.8s ease-in-out infinite;
      mix-blend-mode: screen;
    }}

    .wrap {{ max-width: 1180px; margin: 0 auto; padding: 28px 16px 44px; }}
    .top {{
      position: sticky;
      top: 0;
      z-index: 5;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      background: linear-gradient(180deg, rgba(5,7,11,0.92), rgba(5,7,11,0.55));
      border-bottom: 1px solid var(--border);
    }}
    .top::after {{
      content: "";
      position: absolute;
      left: 0;
      right: 0;
      bottom: -1px;
      height: 2px;
      background: linear-gradient(90deg, transparent, rgba(0,255,213,0.65), rgba(139,92,246,0.55), transparent);
      animation: sweep 5.2s ease-in-out infinite;
      opacity: 0.55;
      pointer-events: none;
    }}
    .top-inner {{ max-width: 1180px; margin: 0 auto; padding: 14px 16px; display: flex; gap: 14px; align-items: center; justify-content: space-between; }}
    .brand {{ display: flex; gap: 10px; align-items: baseline; }}
    .brand .name {{ font-family: var(--mono); letter-spacing: .08em; font-weight: 900; font-size: 13px; color: rgba(226,232,240,0.9); text-shadow: 0 0 18px rgba(0,255,213,0.12), 0 0 26px rgba(139,92,246,0.10); }}
    .brand .target {{ font-family: var(--mono); font-weight: 800; font-size: 14px; color: var(--text); }}
    .meta {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }}

    .badge {{
      display: inline-flex;
      gap: 8px;
      align-items: center;
      padding: 8px 12px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: rgba(11,16,28,0.7);
      box-shadow: var(--shadow2);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: .02em;
      white-space: nowrap;
    }}
    .dot {{ width: 8px; height: 8px; border-radius: 99px; background: {_risk_color(score)}; box-shadow: 0 0 0 6px rgba(255,255,255,0.03), 0 0 18px rgba(0,255,213,0.18); animation: pulse 1.4s ease-in-out infinite; }}
    .badge strong {{ font-weight: 800; }}
    .muted {{ color: var(--muted); }}

    .grid {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 14px;
      margin-top: 16px;
    }}
    @media (min-width: 980px) {{
      .grid {{
        grid-template-columns: 1.2fr 1fr;
        align-items: start;
      }}
    }}

    .card {{
      border: 1px solid var(--border);
      border-radius: 14px;
      background: linear-gradient(180deg, rgba(11,16,28,0.82), rgba(11,16,28,0.62));
      box-shadow: var(--shadow);
      overflow: hidden;
      transition: transform 140ms ease, border-color 140ms ease, box-shadow 140ms ease;
    }}
    .card:hover {{
      transform: translateY(-2px);
      border-color: rgba(0,255,213,0.22);
      box-shadow: 0 14px 44px rgba(0,0,0,.42);
    }}
    .card-h {{
      padding: 14px 16px;
      display: flex;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border);
      background: linear-gradient(90deg, rgba(0,255,213,0.08), rgba(139,92,246,0.08));
    }}
    .card-h h2 {{
      margin: 0;
      font-size: 14px;
      letter-spacing: .06em;
      text-transform: uppercase;
      font-family: var(--mono);
      font-weight: 900;
    }}
    .card-b {{ padding: 14px 16px 16px; }}

    .kpi {{
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }}
    @media (min-width: 720px) {{
      .kpi {{ grid-template-columns: repeat(4, minmax(0, 1fr)); }}
    }}
    .k {{
      border: 1px solid var(--border);
      border-radius: 12px;
      background: rgba(10, 14, 24, 0.62);
      padding: 10px 12px;
    }}
    .k .l {{ color: var(--muted); font-family: var(--mono); font-size: 11px; letter-spacing: .06em; text-transform: uppercase; }}
    .k .v {{ margin-top: 6px; font-family: var(--mono); font-weight: 900; font-size: 14px; }}

    .chips {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .chip {{
      display: inline-flex;
      align-items: center;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: rgba(10,14,24,0.55);
      font-family: var(--mono);
      font-size: 12px;
      color: rgba(226,232,240,0.92);
      max-width: 100%;
      transition: transform 120ms ease, border-color 120ms ease, background 120ms ease, box-shadow 120ms ease;
    }}
    .chip:hover {{
      transform: translateY(-1px);
      border-color: rgba(0,255,213,0.28);
      box-shadow: 0 0 0 1px rgba(0,255,213,0.12), 0 10px 28px rgba(0,0,0,0.25);
      background: rgba(10,14,24,0.72);
    }}
    .chip.good {{ border-color: rgba(34,197,94,0.35); color: rgba(167,243,208,0.95); }}
    .chip.bad {{ border-color: rgba(239,68,68,0.35); color: rgba(254,202,202,0.95); }}
    .chip.warn {{ border-color: rgba(245,158,11,0.35); color: rgba(253,230,138,0.95); }}
    .chip.accent {{ border-color: rgba(0,255,213,0.35); color: rgba(0,255,213,0.95); }}

    .code {{ font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }}
    .row {{ display: grid; grid-template-columns: 1fr; gap: 10px; }}
    @media (min-width: 980px) {{ .row {{ grid-template-columns: 1fr 1fr; }} }}

    details {{
      border: 1px solid var(--border);
      border-radius: 12px;
      background: rgba(10,14,24,0.55);
      padding: 10px 12px;
    }}
    summary {{
      cursor: pointer;
      font-family: var(--mono);
      font-weight: 800;
      letter-spacing: .04em;
      color: rgba(226,232,240,0.92);
    }}
    summary::-webkit-details-marker {{ display: none; }}
    details > .d {{ margin-top: 10px; }}

    .list {{ margin: 0; padding-left: 18px; }}
    .list li {{ margin: 6px 0; }}
  </style>
</head>
<body>
  <div class="top">
    <div class="top-inner">
      <div class="brand">
        <div class="name">RECONSCANPRO</div>
        <div class="target">{title}</div>
      </div>
      <div class="meta">
        <div class="badge"><span class="dot"></span><strong>{escape(posture)}</strong><span class="muted">{score}/100</span></div>
        <div class="badge"><span class="muted">generated</span><span class="code">{escape(str(report.get("generated_at") or ""))}</span></div>
      </div>
    </div>
  </div>

  <div class="wrap">
    <div class="grid">
      <div class="card">
        <div class="card-h"><h2>Risk Summary</h2></div>
        <div class="card-b">
          <ul class="list">{notes_html}</ul>
        </div>
      </div>
      <div class="card">
        <div class="card-h"><h2>Quick Stats</h2></div>
        <div class="card-b">
          { _kpi(report, score, posture) }
        </div>
      </div>
    </div>

    <div style="height: 10px"></div>

    <div class="card">
      <div class="card-h"><h2>Assets</h2></div>
      <div class="card-b">{ _assets_cards(report) }</div>
    </div>

    <div class="card">
      <div class="card-h"><h2>Subdomains</h2></div>
      <div class="card-b">{ _subdomains_section(report) }</div>
    </div>

    <div class="card">
      <div class="card-h"><h2>Web Findings</h2></div>
      <div class="card-b">{ _web_section(report) }</div>
    </div>

    <div class="card">
      <div class="card-h"><h2>DNS & Email Security</h2></div>
      <div class="card-b">{ _dns_section(report) }</div>
    </div>

    <div class="card">
      <div class="card-h"><h2>RDAP</h2></div>
      <div class="card-b">{ _rdap_section(report) }</div>
    </div>
  </div>
</body>
</html>"""

    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(html)
    try:
        os.replace(tmp, path)
    except Exception:
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
    return path


def _kpi(report: Dict[str, Any], score: int, posture: str) -> str:
    assets = report.get("assets") or []
    web = report.get("web") or {}
    web_targets = (web.get("targets") or {}) if isinstance(web, dict) else {}
    dns = report.get("dns") or {}
    subs = report.get("subdomains") or {}

    asset_count = len(assets) if isinstance(assets, list) else 0
    web_count = len(web_targets) if isinstance(web_targets, dict) else 0
    dns_ok = "yes" if isinstance(dns, dict) and bool(dns) else "no"
    sub_count = 0
    if isinstance(subs, dict):
        all_subs = subs.get("all") or []
        if isinstance(all_subs, list):
            sub_count = len(all_subs)

    return (
        "<div class='kpi'>"
        f"<div class='k'><div class='l'>Risk</div><div class='v'>{escape(str(posture))}</div></div>"
        f"<div class='k'><div class='l'>Score</div><div class='v'>{int(score)}/100</div></div>"
        f"<div class='k'><div class='l'>Assets</div><div class='v'>{asset_count}</div></div>"
        f"<div class='k'><div class='l'>Web Targets</div><div class='v'>{web_count}</div></div>"
        f"<div class='k'><div class='l'>DNS</div><div class='v'>{escape(dns_ok)}</div></div>"
        f"<div class='k'><div class='l'>Subdomains</div><div class='v'>{sub_count}</div></div>"
        "</div>"
    )


def _subdomains_section(report: Dict[str, Any]) -> str:
    subs = report.get("subdomains") or {}
    if not isinstance(subs, dict) or not subs:
        return "<div class='muted'>No subdomain data</div>"

    sources = subs.get("sources") or {}
    resolved = subs.get("resolved") or {}
    errors = subs.get("errors") or {}
    all_subs = subs.get("all") or []

    chips = []
    if isinstance(all_subs, list):
        chips.append(f"<span class='chip accent'>total: {len(all_subs)}</span>")
    if isinstance(sources, dict):
        for k, v in list(sources.items())[:10]:
            n = len(v) if isinstance(v, list) else 0
            chips.append(f"<span class='chip'>src:{escape(str(k))} {n}</span>")
    if isinstance(errors, dict) and errors:
        chips.append(f"<span class='chip bad'>errors: {len(errors)}</span>")

    err_lines = ""
    if isinstance(errors, dict) and errors:
        err_lines = "<details><summary>source errors</summary><div class='d'><ul class='list'>" + "".join(
            f"<li><span class='code'>{escape(str(k))}</span>: {escape(str(v))}</li>" for k, v in list(errors.items())[:20]
        ) + "</ul></div></details>"

    resolved_lines = ""
    if isinstance(resolved, dict) and resolved:
        rows = []
        for host, ips in list(resolved.items())[:120]:
            if not isinstance(ips, list):
                continue
            rows.append(f"<li><span class='code'>{escape(str(host))}</span> → {escape(', '.join(str(x) for x in ips[:8]) or '-')}</li>")
        resolved_lines = "<details><summary>resolved</summary><div class='d'><ul class='list'>" + "".join(rows) + "</ul></div></details>"

    sample = ""
    if isinstance(all_subs, list) and all_subs:
        sample = "<details><summary>all (sample)</summary><div class='d'><div class='chips'>" + "".join(
            f"<span class='chip'>{escape(str(s))}</span>" for s in all_subs[:120]
        ) + "</div></div></details>"

    return "<div class='chips'>" + "".join(chips) + "</div><div style='height:10px'></div>" + err_lines + resolved_lines + sample


def _assets_cards(report: Dict[str, Any]) -> str:
    assets = report.get("assets") or []
    if not isinstance(assets, list) or not assets:
        return "<div class='muted'>No assets</div>"

    def svc_str(s: Any) -> str:
        if not isinstance(s, dict):
            return ""
        port = str(s.get("port") or "")
        name = str(s.get("service") or "")
        banner = str(s.get("banner") or "")
        tls = s.get("tls") or {}
        if name == "TLS" and isinstance(tls, dict):
            proto = str(tls.get("protocol") or "").strip()
            subj = str(tls.get("subject") or "")
            san = str(tls.get("san") or "")
            hint = (subj or san).strip()
            hint = hint[:140]
            left = f"{port}/TLS"
            if proto:
                left += f" {proto}"
            return f"{left} {hint}".strip()
        if banner:
            return f"{port}/{name} {banner}".strip()
        if name:
            return f"{port}/{name}".strip()
        return str(port).strip()

    cards = []
    for a in assets[:120]:
        if not isinstance(a, dict):
            continue
        ip = escape(str(a.get("ip") or ""))
        hosts = a.get("hosts") or []
        ports = a.get("ports") or []
        services = a.get("services") or []
        ports_scanned = a.get("ports_scanned")
        port_timeout_s = a.get("port_timeout_s")
        port_error = a.get("port_error") or a.get("ports_error") or ""
        port_scan = a.get("port_scan") or {}
        port_chips = "".join(f"<span class='chip accent'>{escape(str(p))}</span>" for p in (ports[:100] if isinstance(ports, list) else []))
        host_chips = "".join(f"<span class='chip'>{escape(str(h))}</span>" for h in (hosts[:25] if isinstance(hosts, list) else []))
        svc_lines = [svc_str(s) for s in (services[:80] if isinstance(services, list) else [])]
        svc_lines = [x for x in svc_lines if x]

        svc_html = ""
        if svc_lines:
            svc_html = "<details><summary>services</summary><div class='d'><div class='chips'>" + "".join(
                f"<span class='chip'>{escape(x)}</span>" for x in svc_lines[:80]
            ) + "</div></div></details>"

        meta = ""
        if ports_scanned is not None:
            meta += f"<span class='chip'>scanned: {escape(str(ports_scanned))}</span>"
        if port_timeout_s is not None:
            meta += f"<span class='chip'>timeout: {escape(str(port_timeout_s))}s</span>"
        if port_error:
            meta += f"<span class='chip bad'>port error</span>"
        if isinstance(port_scan, dict) and port_scan:
            attempted = port_scan.get("attempted")
            err = port_scan.get("errors") or {}
            if attempted is not None and ports_scanned is None:
                meta += f"<span class='chip'>scanned: {escape(str(attempted))}</span>"
            if isinstance(err, dict) and err:
                meta += f"<span class='chip'>errs: {escape(str(len(err)))}</span>"

        port_scan_details = ""
        if isinstance(port_scan, dict) and port_scan:
            err = port_scan.get("errors") or {}
            lines = []
            if isinstance(err, dict) and err:
                items = []
                for k, v in err.items():
                    try:
                        items.append((int(v), str(k)))
                    except Exception:
                        items.append((0, str(k)))
                items.sort(reverse=True)
                for v, k in items[:10]:
                    lines.append(f"<span class='chip'>{escape(str(k))}: {escape(str(v))}</span>")
            if lines:
                port_scan_details = "<details><summary>port scan stats</summary><div class='d'><div class='chips'>" + "".join(lines) + "</div></div></details>"

        cards.append(
            "<div class='card' style='background: linear-gradient(180deg, rgba(10,14,24,0.62), rgba(10,14,24,0.45)); margin: 0 0 12px 0;'>"
            "<div class='card-h'>"
            f"<h2>IP <span class='code'>{ip}</span></h2>"
            "</div>"
            "<div class='card-b'>"
            f"<div class='chips'>{meta}</div>"
            f"<div class='row'><div><div class='muted' style='font-family: var(--mono); font-size: 12px; letter-spacing: .06em; text-transform: uppercase;'>hosts</div><div class='chips' style='margin-top: 8px'>{host_chips or '<span class=\"muted\">-</span>'}</div></div>"
            f"<div><div class='muted' style='font-family: var(--mono); font-size: 12px; letter-spacing: .06em; text-transform: uppercase;'>open ports</div><div class='chips' style='margin-top: 8px'>{port_chips or '<span class=\"muted\">-</span>'}</div></div></div>"
            f"<div style='margin-top: 10px'>{port_scan_details}</div>"
            f"<div style='margin-top: 10px'>{svc_html}</div>"
            "</div>"
            "</div>"
        )

    return "".join(cards) if cards else "<div class='muted'>No assets</div>"


def _assets_rows(report: Dict[str, Any]) -> str:
    assets = report.get("assets") or []
    if not isinstance(assets, list) or not assets:
        return "<tr><td colspan='4' class='muted'>No assets</td></tr>"

    rows = []

    def svc_str(s: Any) -> str:
        if not isinstance(s, dict):
            return ""
        port = str(s.get("port") or "")
        name = str(s.get("service") or "")
        banner = str(s.get("banner") or "")
        tls = s.get("tls") or {}
        if name == "TLS" and isinstance(tls, dict):
            subj = str(tls.get("subject") or "")
            san = str(tls.get("san") or "")
            hint = subj or san
            hint = hint[:120]
            return f"{port} TLS {hint}".strip()
        if banner:
            return f"{port} {name} {banner}".strip()
        return f"{port} {name}".strip()

    for a in assets:
        if not isinstance(a, dict):
            continue
        ip = escape(str(a.get("ip") or ""))
        hosts = a.get("hosts") or []
        ports = a.get("ports") or []
        services = a.get("services") or []
        host_html = "<br>".join(escape(str(h)) for h in hosts[:80])
        ports_html = ", ".join(escape(str(p)) for p in ports[:200])
        svc_html = "<br>".join(escape(svc_str(s)) for s in services[:60] if svc_str(s))
        rows.append(f"<tr><td><code>{ip}</code></td><td>{host_html}</td><td>{ports_html}</td><td>{svc_html}</td></tr>")
    return "\n".join(rows) if rows else "<tr><td colspan='4' class='muted'>No assets</td></tr>"


def _web_section(report: Dict[str, Any]) -> str:
    web = report.get("web") or {}
    if not isinstance(web, dict) or not web:
        return "<div class='muted'>No web scan</div>"

    meta = web.get("meta") or {}
    targets = web.get("targets") or {}
    if not isinstance(targets, dict) or not targets:
        reason = ""
        if isinstance(meta, dict):
            reason = str(meta.get("reason") or "").strip()
            if not reason and meta.get("enabled") is False:
                reason = "disabled"
        if reason:
            return f"<div class='muted'>No web targets ({escape(reason)})</div>"
        return "<div class='muted'>No web targets</div>"

    rows = []
    for url, w in targets.items():
        if not isinstance(w, dict):
            continue
        url_e = escape(str(url))
        status = escape(str(w.get("status") or ""))
        title = escape(str(w.get("title") or ""))
        err = escape(str(w.get("error") or ""))
        waf = escape(str(((w.get("waf") or {}) or {}).get("vendor") or ""))
        tech = w.get("tech") or []
        logins = w.get("login_pages") or []
        admins = w.get("admin_panels") or []
        eps = w.get("endpoints") or []
        external = w.get("external_links") or []
        params = w.get("param_names") or []
        sec = w.get("security_headers") or {}
        cookies = w.get("cookies") or {}
        wp = w.get("wordpress") or {}
        pc = w.get("panel_checks") or {}
        sm = w.get("sitemap") or {}

        sec_bad = [k for k, v in sec.items() if v is False]
        sec_ok = [k for k, v in sec.items() if v is True]
        cookie_issues = (cookies.get("issues") or []) if isinstance(cookies, dict) else []
        wp_signals = (wp.get("signals") or []) if isinstance(wp, dict) else []
        pc_found = (pc.get("found") or []) if isinstance(pc, dict) else []
        pc_signals = (pc.get("signals") or []) if isinstance(pc, dict) else []
        pc_checks = (pc.get("checks") or []) if isinstance(pc, dict) else []
        sm_count = int(sm.get("url_count") or 0) if isinstance(sm, dict) else 0
        sm_robots = str(sm.get("robots_url") or "") if isinstance(sm, dict) else ""
        sm_sitemaps = (sm.get("sitemaps") or []) if isinstance(sm, dict) else []

        sec_bad_chips = "".join(f"<span class='chip bad'>{escape(str(x))}</span>" for x in sec_bad[:20])
        sec_ok_chips = "".join(f"<span class='chip good'>{escape(str(x))}</span>" for x in sec_ok[:20])
        tech_chips = "".join(f"<span class='chip'>{escape(str(x))}</span>" for x in tech[:18]) if isinstance(tech, list) else ""
        login_chips = "".join(f"<span class='chip'>{escape(str(x))}</span>" for x in logins[:12]) if isinstance(logins, list) else ""
        admin_chips = "".join(f"<span class='chip warn'>{escape(str(x))}</span>" for x in admins[:12]) if isinstance(admins, list) else ""
        param_chips = "".join(f"<span class='chip'>{escape(str(x))}</span>" for x in params[:40]) if isinstance(params, list) else ""
        endpoint_chips = "".join(f"<span class='chip'>{escape(str(x))}</span>" for x in eps[:28]) if isinstance(eps, list) else ""
        ext_chips = "".join(f"<span class='chip'>{escape(str(x))}</span>" for x in external[:20]) if isinstance(external, list) else ""
        cookie_chips = "".join(f"<span class='chip bad'>{escape(str(x))}</span>" for x in cookie_issues[:18]) if isinstance(cookie_issues, list) else ""
        wp_signal_chips = "".join(f"<span class='chip'>{escape(str(x))}</span>" for x in wp_signals[:18]) if isinstance(wp_signals, list) else ""
        wp_detail_items = []
        if isinstance(wp, dict) and wp:
            for key, label in [("wp_login", "wp-login"), ("xmlrpc", "xmlrpc"), ("wp_json", "wp-json")]:
                it = wp.get(key) or {}
                if not isinstance(it, dict):
                    continue
                st = it.get("status")
                er = it.get("error")
                if er:
                    wp_detail_items.append(("chip bad", f"{label}: error"))
                elif st is not None:
                    sst = int(st)
                    cls = "chip"
                    if sst in {200, 301, 302, 303, 307, 308}:
                        cls = "chip good"
                    elif sst in {401, 403, 405}:
                        cls = "chip warn"
                    elif sst == 404:
                        cls = "chip"
                    else:
                        cls = "chip"
                    wp_detail_items.append((cls, f"{label}: {sst}"))
        wp_detail_chips = "".join(f"<span class='{cls}'>{escape(txt)}</span>" for cls, txt in wp_detail_items[:12])
        wp_chips = (wp_signal_chips + wp_detail_chips) if (wp_signal_chips or wp_detail_chips) else ""
        pc_sig_chips = "".join(f"<span class='chip warn'>{escape(str(x))}</span>" for x in pc_signals[:18]) if isinstance(pc_signals, list) else ""
        pc_found_chips = ""
        if isinstance(pc_found, list) and pc_found:
            items = []
            for it in pc_found[:18]:
                if not isinstance(it, dict):
                    continue
                pth = str(it.get("path") or "").strip()
                st = str(it.get("status") or "").strip()
                u = str(it.get("final_url") or it.get("url") or "").strip()
                label = pth or u
                if label:
                    items.append(f"{label} ({st})")
            pc_found_chips = "".join(f"<span class='chip warn'>{escape(str(x))}</span>" for x in items[:18])

        pc_err = 0
        pc_err_samples = []
        if isinstance(pc_checks, list) and pc_checks:
            for it in pc_checks[:80]:
                if not isinstance(it, dict):
                    continue
                if it.get("error"):
                    pc_err += 1
                    if len(pc_err_samples) < 4:
                        pth = str(it.get("path") or "").strip()
                        pc_err_samples.append(pth or "error")
        pc_meta = ""
        if isinstance(pc_checks, list) and pc_checks:
            pc_meta += f"<span class='chip'>checked: {len(pc_checks)}</span>"
        if pc_err:
            pc_meta += f"<span class='chip bad'>errors: {pc_err}</span>"
        pc_err_chips = "".join(f"<span class='chip bad'>{escape(str(x))}</span>" for x in pc_err_samples)

        sm_chips = ""
        if sm_count > 0:
            sm_chips += f"<span class='chip accent'>urls: {int(sm_count)}</span>"
        if sm_robots:
            sm_chips += f"<span class='chip'><a href='{escape(sm_robots)}' target='_blank' rel='noreferrer'>robots.txt</a></span>"
        if isinstance(sm_sitemaps, list) and sm_sitemaps:
            ok = 0
            errn = 0
            for it in sm_sitemaps[:20]:
                if not isinstance(it, dict):
                    continue
                if it.get("error"):
                    errn += 1
                else:
                    ok += 1
            sm_chips += f"<span class='chip'>sitemaps ok:{ok} err:{errn}</span>"

        rows.append(
            "<div class='card' style='background: linear-gradient(180deg, rgba(10,14,24,0.62), rgba(10,14,24,0.45)); margin: 0 0 12px 0;'>"
            "<div class='card-h'>"
            f"<h2>Web Target</h2>"
            f"<div class='chips'><span class='chip accent'>{status or '-'}</span>{('<span class=\"chip warn\">'+waf+'</span>') if waf else ''}</div>"
            "</div>"
            "<div class='card-b'>"
            f"<div class='code'><a href='{url_e}' target='_blank' rel='noreferrer'>{url_e}</a></div>"
            f"{('<div class=\"chip bad\" style=\"margin-top:10px\">'+err+'</div>') if err else ''}"
            f"<div class='muted' style='margin-top: 10px'>{title}</div>"
            f"<div style='margin-top: 10px'><div class='muted' style='font-family: var(--mono); font-size: 12px; letter-spacing: .06em; text-transform: uppercase;'>tech</div><div class='chips' style='margin-top: 8px'>{tech_chips or '<span class=\"muted\">n/a</span>'}</div></div>"
            "<div style='margin-top: 12px' class='row'>"
            f"<details open><summary>security headers</summary><div class='d'><div class='muted'>missing</div><div class='chips' style='margin-top:8px'>{sec_bad_chips or '<span class=\"muted\">none</span>'}</div><div class='muted' style='margin-top:10px'>present</div><div class='chips' style='margin-top:8px'>{sec_ok_chips or '<span class=\"muted\">none</span>'}</div></div></details>"
            f"<details><summary>cookies</summary><div class='d'><div class='chips'>{cookie_chips or '<span class=\"muted\">no issues detected</span>'}</div></div></details>"
            "</div>"
            "<div style='margin-top: 12px' class='row'>"
            f"<details><summary>login pages</summary><div class='d'><div class='chips'>{login_chips or '<span class=\"muted\">none</span>'}</div></div></details>"
            f"<details><summary>admin panels</summary><div class='d'><div class='chips'>{admin_chips or '<span class=\"muted\">none</span>'}</div></div></details>"
            "</div>"
            "<div style='margin-top: 12px' class='row'>"
            f"<details><summary>quick panel checks</summary><div class='d'><div class='chips'>{pc_meta or ''}</div><div class='muted' style='margin-top:10px'>signals</div><div class='chips' style='margin-top:8px'>{pc_sig_chips or '<span class=\"muted\">none</span>'}</div><div class='muted' style='margin-top:10px'>found</div><div class='chips' style='margin-top:8px'>{pc_found_chips or '<span class=\"muted\">none</span>'}</div><div class='muted' style='margin-top:10px'>errors (sample)</div><div class='chips' style='margin-top:8px'>{pc_err_chips or '<span class=\"muted\">none</span>'}</div></div></details>"
            f"<details><summary>wordpress checks</summary><div class='d'><div class='chips'>{wp_chips or '<span class=\"muted\">n/a</span>'}</div></div></details>"
            "</div>"
            f"<div style='margin-top: 12px'><details><summary>sitemap seeds</summary><div class='d'><div class='chips'>{sm_chips or '<span class=\"muted\">not used</span>'}</div></div></details></div>"
            "<div style='margin-top: 12px' class='row'>"
            f"<details><summary>endpoints</summary><div class='d'><div class='chips'>{endpoint_chips or '<span class=\"muted\">none</span>'}</div></div></details>"
            f"<details><summary>params</summary><div class='d'><div class='chips'>{param_chips or '<span class=\"muted\">none</span>'}</div></div></details>"
            "</div>"
            "<div style='margin-top: 12px' class='row'>"
            f"<details><summary>external links (sample)</summary><div class='d'><div class='chips'>{ext_chips or '<span class=\"muted\">none</span>'}</div></div></details>"
            f"<details><summary>raw errors</summary><div class='d'><div class='muted'>{err or 'none'}</div></div></details>"
            "</div>"
            "</div>"
            "</div>"
        )
    return "\n".join(rows) if rows else "<div class='muted'>No web targets</div>"


def _dns_section(report: Dict[str, Any]) -> str:
    dns = report.get("dns") or {}
    dns_extra = report.get("dns_extra") or {}
    email = report.get("email_security") or {}
    if not isinstance(dns, dict) and not isinstance(email, dict):
        return "<div class='muted'>No DNS data</div>"

    def chips_from_list(lst: Any, *, kind: str = "") -> str:
        if not isinstance(lst, list) or not lst:
            return "<span class='muted'>none</span>"
        cls = "chip"
        if kind == "good":
            cls = "chip good"
        if kind == "warn":
            cls = "chip warn"
        if kind == "bad":
            cls = "chip bad"
        return "<div class='chips'>" + "".join(f"<span class='{cls}'>{escape(str(x))}</span>" for x in lst[:160]) + "</div>"

    dns_html = "<div class='muted'>No DNS data</div>"
    if isinstance(dns, dict) and dns:
        blocks = []
        for k in ["CNAME", "A", "AAAA", "NS", "MX", "TXT", "SOA"]:
            v = dns.get(k)
            if v is None:
                continue
            blocks.append(
                "<div style='margin-top: 10px'>"
                f"<div class='muted' style='font-family: var(--mono); font-size: 12px; letter-spacing: .06em; text-transform: uppercase;'>{escape(str(k))}</div>"
                f"{chips_from_list(v)}"
                "</div>"
            )
        dns_html = "".join(blocks) if blocks else "<div class='muted'>No DNS data</div>"

    extra_html = "<div class='muted'>No DNS extra</div>"
    if isinstance(dns_extra, dict) and dns_extra:
        blocks = []
        for k in ["DMARC", "MTA-STS", "TLS-RPT"]:
            v = dns_extra.get(k)
            if v is None:
                continue
            blocks.append(
                "<div style='margin-top: 10px'>"
                f"<div class='muted' style='font-family: var(--mono); font-size: 12px; letter-spacing: .06em; text-transform: uppercase;'>{escape(str(k))}</div>"
                f"{chips_from_list(v)}"
                "</div>"
            )
        extra_html = "".join(blocks) if blocks else "<div class='muted'>No DNS extra</div>"

    email_html = "<div class='muted'>No Email Security data</div>"
    if isinstance(email, dict) and email:
        spf = escape(str(email.get("spf") or ""))
        pol = escape(str(email.get("dmarc_policy") or ""))
        rua = email.get("dmarc_rua") or []
        pol_cls = "chip bad" if pol == "none" else "chip"
        email_html = (
            "<div style='margin-top: 8px'>"
            "<div class='row'>"
            "<div>"
            "<div class='muted' style='font-family: var(--mono); font-size: 12px; letter-spacing: .06em; text-transform: uppercase;'>SPF</div>"
            f"<div class='chip'>{spf or 'n/a'}</div>"
            "</div>"
            "<div>"
            "<div class='muted' style='font-family: var(--mono); font-size: 12px; letter-spacing: .06em; text-transform: uppercase;'>DMARC policy</div>"
            f"<div class='{pol_cls}'>{pol or 'n/a'}</div>"
            "</div>"
            "</div>"
            "<div style='margin-top: 10px'>"
            "<div class='muted' style='font-family: var(--mono); font-size: 12px; letter-spacing: .06em; text-transform: uppercase;'>DMARC rua</div>"
            f"{chips_from_list(rua)}"
            "</div>"
            "</div>"
        )

    return (
        "<div class='row'>"
        f"<details open><summary>dns records</summary><div class='d'>{dns_html}</div></details>"
        f"<details open><summary>dns extra</summary><div class='d'>{extra_html}</div></details>"
        "</div>"
        "<div style='height:10px'></div>"
        f"<details open><summary>email security</summary><div class='d'>{email_html}</div></details>"
    )


def _rdap_section(report: Dict[str, Any]) -> str:
    rdap = report.get("rdap") or {}
    if not isinstance(rdap, dict) or not rdap:
        return "<div class='muted'>No RDAP data</div>"

    cards = []
    for ip, v in list(rdap.items())[:40]:
        if not isinstance(v, dict):
            continue
        data = v.get("data") or {}
        url = str(v.get("url") or "")
        country = str(data.get("country") or "")
        start = str(data.get("startAddress") or "")
        end = str(data.get("endAddress") or "")
        name = str(data.get("name") or data.get("handle") or "")
        cidrs = data.get("cidr0_cidrs") or []
        cidr_str = ""
        if isinstance(cidrs, list) and cidrs:
            parts = []
            for c in cidrs[:6]:
                if not isinstance(c, dict):
                    continue
                pfx = c.get("v4prefix") or c.get("v6prefix") or ""
                ln = c.get("length")
                if pfx and ln is not None:
                    parts.append(f"{pfx}/{ln}")
            cidr_str = ", ".join(parts)

        head = "<div class='chips'>"
        head += f"<span class='chip accent'>{escape(str(ip))}</span>"
        if country:
            head += f"<span class='chip'>{escape(country)}</span>"
        if cidr_str:
            head += f"<span class='chip'>{escape(cidr_str)}</span>"
        head += "</div>"

        body = "<div style='margin-top:10px' class='muted'>"
        if name:
            body += f"<div><span class='code'>{escape(name)}</span></div>"
        if start or end:
            body += f"<div class='code'>{escape(start)} → {escape(end)}</div>"
        if url:
            body += f"<div><a class='code' href='{escape(url)}' target='_blank' rel='noreferrer'>{escape(url)}</a></div>"
        body += "</div>"

        cards.append(
            "<div class='card' style='background: linear-gradient(180deg, rgba(10,14,24,0.62), rgba(10,14,24,0.45)); margin: 0 0 12px 0;'>"
            "<div class='card-h'><h2>IP RDAP</h2></div>"
            "<div class='card-b'>"
            f"{head}{body}"
            "</div></div>"
        )

    return "".join(cards) if cards else "<div class='muted'>No RDAP data</div>"


def write_report(*, report: Dict[str, Any], export: Optional[str], export_path: Optional[str]) -> Optional[str]:
    if not export:
        return None
    fmt = str(export).strip().lower()
    if fmt not in {"json", "html"}:
        raise ValueError("export harus: json atau html")
    out = export_path
    if not out:
        out = f"report.{fmt}"
    safe_report = _sanitize_report(report)
    if fmt == "json":
        return write_json(out, safe_report)
    return write_html(out, safe_report)


def _sanitize_report(report: Dict[str, Any]) -> Dict[str, Any]:
    r = copy.deepcopy(report or {})

    def redact_url(u: Any) -> str:
        s = str(u or "").strip()
        if not s:
            return ""
        try:
            sp = urlsplit(s)
            if sp.scheme not in {"http", "https"}:
                return s
            q = parse_qsl(sp.query, keep_blank_values=True)
            if not q:
                return urlunsplit((sp.scheme, sp.netloc, sp.path, "", ""))
            rq = urlencode([(k, "REDACTED") for k, _ in q], doseq=True)
            return urlunsplit((sp.scheme, sp.netloc, sp.path, rq, ""))
        except Exception:
            return s

    def redact_hidden(x: Any) -> str:
        s = str(x or "").strip()
        if not s:
            return ""
        if "=" in s:
            k = s.split("=", 1)[0].strip()
            if k:
                return f"{k}=REDACTED"
        return s

    def redact_text(x: Any) -> str:
        s = str(x or "")
        if not s:
            return ""
        s = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._-]+\b", "Bearer REDACTED", s)
        s = re.sub(r"(?i)\b(Authorization|Cookie)\s*:\s*[^\r\n]+", r"\1: REDACTED", s)
        s = re.sub(r"(?i)\b(api[_-]?key|token|access[_-]?token|session|password)=([^&\s]+)", r"\1=REDACTED", s)
        s = re.sub(r"(?i)(https?://[^\s]+)\?([^\s]+)", lambda m: redact_url(m.group(0)), s)
        return s

    web = r.get("web")
    if isinstance(web, dict):
        targets = web.get("targets")
        if isinstance(targets, dict):
            for _, w in targets.items():
                if not isinstance(w, dict):
                    continue
                hdrs = w.get("headers")
                if isinstance(hdrs, dict):
                    for k in list(hdrs.keys()):
                        kl = str(k).lower().strip()
                        if kl in {"set-cookie", "cookie", "authorization", "proxy-authorization"}:
                            hdrs.pop(k, None)
                if "error" in w:
                    w["error"] = redact_text(w.get("error"))
                if "final_url" in w:
                    w["final_url"] = redact_url(w.get("final_url"))
                if "urls_with_params" in w and isinstance(w.get("urls_with_params"), list):
                    w["urls_with_params"] = [redact_url(x) for x in (w.get("urls_with_params") or []) if str(x).strip()][:200]
                if "login_pages" in w and isinstance(w.get("login_pages"), list):
                    w["login_pages"] = [redact_url(x) for x in (w.get("login_pages") or []) if str(x).strip()][:80]
                if "admin_panels" in w and isinstance(w.get("admin_panels"), list):
                    w["admin_panels"] = [redact_url(x) for x in (w.get("admin_panels") or []) if str(x).strip()][:80]
                if "endpoints" in w and isinstance(w.get("endpoints"), list):
                    w["endpoints"] = [redact_url(x) for x in (w.get("endpoints") or []) if str(x).strip()][:300]
                if "external_links" in w and isinstance(w.get("external_links"), list):
                    w["external_links"] = [redact_url(x) for x in (w.get("external_links") or []) if str(x).strip()][:120]
                if "hidden_fields" in w and isinstance(w.get("hidden_fields"), list):
                    w["hidden_fields"] = [redact_hidden(x) for x in (w.get("hidden_fields") or []) if str(x).strip()][:200]

    return r
