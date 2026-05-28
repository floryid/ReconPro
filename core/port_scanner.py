from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, Iterable, List, Sequence, Tuple


def parse_ports(ports: str) -> List[int]:
    s = str(ports or "").strip()
    if not s:
        return []
    out: List[int] = []
    for part in s.split(","):
        p = part.strip()
        if not p:
            continue
        if "-" in p:
            a, b = p.split("-", 1)
            try:
                lo = int(a.strip())
                hi = int(b.strip())
            except ValueError:
                continue
            lo, hi = min(lo, hi), max(lo, hi)
            for x in range(lo, hi + 1):
                if 1 <= x <= 65535:
                    out.append(x)
        else:
            try:
                x = int(p)
            except ValueError:
                continue
            if 1 <= x <= 65535:
                out.append(x)
    seen = set()
    uniq: List[int] = []
    for p in out:
        if p in seen:
            continue
        seen.add(p)
        uniq.append(p)
    return uniq


async def scan_tcp_ports(
    ip: str,
    ports: Sequence[int],
    *,
    timeout_s: float,
    concurrency: int = 200,
) -> Dict[str, Any]:
    sem = asyncio.Semaphore(max(1, int(concurrency)))
    open_ports: List[int] = []
    err_counts: Dict[str, int] = {}

    def _connect_once(port: int) -> Tuple[bool, str]:
        try:
            s = socket.create_connection((str(ip), int(port)), timeout=float(timeout_s))
            try:
                return True, ""
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        except OSError as e:
            code = getattr(e, "winerror", None)
            if code is None:
                code = getattr(e, "errno", None)
            msg = str(e).lower()
            if "timed out" in msg or isinstance(e, TimeoutError):
                return False, "timeout"
            if code in {10061, 111}:
                return False, "refused"
            if code in {10060}:
                return False, "timeout"
            if code in {10051, 101}:
                return False, "network_unreachable"
            if code in {10065, 113}:
                return False, "no_route"
            return False, f"oserror_{int(code) if code is not None else -1}"
        except Exception:
            return False, "error"

    async def one(port: int) -> None:
        async with sem:
            try:
                ok, label = await asyncio.wait_for(asyncio.to_thread(_connect_once, int(port)), timeout=float(timeout_s) + 0.6)
                if ok:
                    open_ports.append(int(port))
                else:
                    k = str(label or "closed")
                    err_counts[k] = int(err_counts.get(k, 0)) + 1
            except Exception:
                k = "timeout"
                err_counts[k] = int(err_counts.get(k, 0)) + 1
                return

    q: asyncio.Queue[int] = asyncio.Queue()
    for p in ports:
        try:
            q.put_nowait(int(p))
        except Exception:
            continue

    worker_n = max(1, min(int(concurrency), int(q.qsize()) or 1))

    async def worker() -> None:
        while True:
            try:
                p = q.get_nowait()
            except Exception:
                return
            try:
                await one(int(p))
            finally:
                try:
                    q.task_done()
                except Exception:
                    pass

    tasks = [asyncio.create_task(worker()) for _ in range(worker_n)]
    try:
        await q.join()
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return {
        "ip": str(ip),
        "attempted": int(len(ports)),
        "timeout_s": float(timeout_s),
        "open_ports": sorted(set(open_ports)),
        "errors": err_counts,
    }
