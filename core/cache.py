from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Optional


class Cache:
    def __init__(self, *, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self._init()

    def _init(self) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT NOT NULL, ts INTEGER NOT NULL)"
            )
            db.commit()

    def get(self, key: str, *, ttl_s: int) -> Optional[Any]:
        now = int(time.time())
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT v, ts FROM cache WHERE k = ?", (str(key),)).fetchone()
        if not row:
            return None
        v, ts = row
        if int(ttl_s) > 0 and now - int(ts) > int(ttl_s):
            return None
        try:
            return json.loads(str(v))
        except Exception:
            return None

    def set(self, key: str, value: Any) -> None:
        now = int(time.time())
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT OR REPLACE INTO cache (k, v, ts) VALUES (?, ?, ?)", (str(key), raw, now))
            db.commit()
