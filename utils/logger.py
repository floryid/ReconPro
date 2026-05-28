from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional


def setup_logging(*, logfile: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("recon_scan_pro")
    logger.setLevel(level)
    logger.propagate = False

    if logger.handlers:
        return logger

    os.makedirs(os.path.dirname(os.path.abspath(logfile)) or ".", exist_ok=True)

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(fmt)

    fh = RotatingFileHandler(logfile, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(fmt)

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


def quiet_logger(name: str = "recon_scan_pro.null") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
    return logger


def safe_exc(e: BaseException, *, max_len: int = 250) -> str:
    s = f"{type(e).__name__}: {e}"
    s = s.replace("\r", " ").replace("\n", " ")
    if max_len > 0 and len(s) > max_len:
        return s[: max_len - 1] + "…"
    return s


def redact_url(url: str) -> str:
    if not url:
        return ""
    try:
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(url)
        if not parts.query:
            return url
        redacted = ""
        return urlunsplit((parts.scheme, parts.netloc, parts.path, redacted, parts.fragment))
    except Exception:
        return url


def log_kv(logger: logging.Logger, key: str, value: Optional[str]) -> None:
    if value is None:
        return
    logger.info("%s=%s", key, value)
