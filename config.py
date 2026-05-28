from __future__ import annotations

from dataclasses import dataclass


DEFAULT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/125.0.0.0 Safari/537.36",
]


STATIC_EXT_BLACKLIST = {
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".ico",
    ".map",
    ".eot",
    ".webp",
    ".mp4",
    ".mp3",
    ".avi",
    ".mov",
    ".pdf",
}


FOCUS_PATH_HINTS = (
    "/api/",
    "/admin/",
    "/administrator/",
    "/wp-admin/",
    "/wp-login.php",
)


LOGIN_URL_HINTS = (
    "login",
    "signin",
    "sign-in",
    "auth",
    "session",
    "wp-login.php",
    "admin",
)


AUTH_PARAM_HINTS = (
    "password",
    "passwd",
    "pass",
    "pwd",
    "token",
    "apikey",
    "api_key",
    "key",
    "session",
    "jwt",
)


TOP_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    9000,
    9200,
    27017,
]


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Permissions-Policy",
    "Referrer-Policy",
]


@dataclass(frozen=True)
class Defaults:
    timeout_s: float = 10.0
    delay_s: float = 0.0
    concurrency: int = 30
    crawl_pages: int = 20
    crawl_depth: int = 2
    crawl_bytes: int = 250_000
    cache_ttl_s: int = 24 * 3600
    port_timeout_s: float = 1.5
