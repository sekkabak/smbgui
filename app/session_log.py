"""In-memory session / wire log."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, asdict
from typing import Any, Deque, Optional


@dataclass
class LogEntry:
    ts: float
    action: str
    host: str
    detail: str
    source: str  # "wire" | "cache" | "local"
    ok: bool = True
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


class SessionLog:
    def __init__(self, maxlen: int = 1000):
        self._entries: Deque[LogEntry] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(
        self,
        action: str,
        host: str = "",
        detail: str = "",
        source: str = "local",
        ok: bool = True,
        error: Optional[str] = None,
    ) -> LogEntry:
        entry = LogEntry(
            ts=time.time(),
            action=action,
            host=host,
            detail=detail,
            source=source,
            ok=ok,
            error=error,
        )
        with self._lock:
            self._entries.append(entry)
        return entry

    def list(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._entries)[-limit:]
        return [e.to_dict() for e in reversed(items)]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
