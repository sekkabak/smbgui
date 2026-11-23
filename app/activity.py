"""Operator-facing live activity / status broadcast."""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Optional


SEVERITIES = ("info", "warn", "error")
# High-level states for the strip
STATES = (
    "idle",
    "connecting",
    "listing",
    "refreshing",
    "downloading",
    "uploading",
    "retrying",
    "reconnecting",
    "waiting",
    "error",
)


@dataclass
class ActivityEvent:
    state: str = "idle"
    message: str = "idle"
    severity: str = "info"  # info|warn|error
    busy: bool = False
    host: str = ""
    path: str = ""
    action: str = ""
    progress: Optional[float] = None  # 0..100
    detail: str = ""
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


class ActivityHub:
    """Latest-snapshot + fan-out of operator activity events."""

    def __init__(self):
        self._lock = threading.RLock()
        self._current = ActivityEvent()
        self._history: list[ActivityEvent] = []
        self._history_max = 100
        self._subs: list[asyncio.Queue] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return self._current.to_dict()

    def history(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return [e.to_dict() for e in self._history[-limit:]]

    def set(
        self,
        state: str = "idle",
        message: str = "",
        *,
        severity: str = "info",
        busy: Optional[bool] = None,
        host: str = "",
        path: str = "",
        action: str = "",
        progress: Optional[float] = None,
        detail: str = "",
    ) -> ActivityEvent:
        if state not in STATES and state != "idle":
            # allow custom but keep busy semantics
            pass
        if severity not in SEVERITIES:
            severity = "info"
        if busy is None:
            busy = state not in ("idle", "error") or (
                state == "error" and False
            )
            if state == "idle":
                busy = False
            elif state == "error":
                busy = False
            else:
                busy = True
        ev = ActivityEvent(
            state=state,
            message=message or state,
            severity=severity,
            busy=busy,
            host=host,
            path=path,
            action=action or state,
            progress=progress,
            detail=detail,
            ts=time.time(),
        )
        with self._lock:
            self._current = ev
            self._history.append(ev)
            if len(self._history) > self._history_max:
                self._history = self._history[-self._history_max :]
        self._broadcast(ev)
        return ev

    def idle(self, message: str = "idle") -> ActivityEvent:
        return self.set("idle", message, severity="info", busy=False)

    def error(self, message: str, host: str = "", path: str = "", detail: str = "") -> ActivityEvent:
        return self.set(
            "error",
            message,
            severity="error",
            busy=False,
            host=host,
            path=path,
            detail=detail,
        )

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=64)
        with self._lock:
            self._subs.append(q)
            # push current snapshot immediately
            try:
                q.put_nowait({"type": "status", **self._current.to_dict()})
            except asyncio.QueueFull:
                pass
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def _broadcast(self, ev: ActivityEvent) -> None:
        payload = {"type": "status", **ev.to_dict()}

        def _put():
            with self._lock:
                subs = list(self._subs)
            for q in subs:
                try:
                    q.put_nowait(payload)
                except asyncio.QueueFull:
                    try:
                        q.get_nowait()
                    except Exception:
                        pass
                    try:
                        q.put_nowait(payload)
                    except Exception:
                        pass

        loop = self._loop
        if loop and loop.is_running():
            loop.call_soon_threadsafe(_put)
        else:
            _put()


activity = ActivityHub()
