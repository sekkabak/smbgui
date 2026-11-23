"""In-process progress event hub for WebSocket upload/download streaming."""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, asdict, field
from typing import Any, Optional


@dataclass
class ProgressEvent:
    job_id: str
    action: str  # upload|download|refresh|zip
    host: str
    path: str
    bytes_done: int
    bytes_total: int
    status: str  # running|done|error
    message: str = ""
    ts: float = field(default_factory=time.time)
    percent: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.bytes_total > 0:
            d["percent"] = round(100.0 * self.bytes_done / self.bytes_total, 2)
        elif self.status == "done":
            d["percent"] = 100.0
        return d


class ProgressHub:
    """Fan-out progress events to asyncio subscriber queues."""

    def __init__(self):
        self._subs: dict[str, list[asyncio.Queue]] = {}
        self._jobs: dict[str, ProgressEvent] = {}
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def new_job(self, action: str, host: str = "", path: str = "", total: int = 0) -> str:
        job_id = uuid.uuid4().hex[:12]
        ev = ProgressEvent(
            job_id=job_id,
            action=action,
            host=host,
            path=path,
            bytes_done=0,
            bytes_total=total,
            status="running",
        )
        with self._lock:
            self._jobs[job_id] = ev
        self._broadcast(ev)
        return job_id

    def update(
        self,
        job_id: str,
        bytes_done: Optional[int] = None,
        bytes_total: Optional[int] = None,
        status: Optional[str] = None,
        message: str = "",
    ) -> None:
        with self._lock:
            ev = self._jobs.get(job_id)
            if not ev:
                return
            if bytes_done is not None:
                ev.bytes_done = bytes_done
            if bytes_total is not None:
                ev.bytes_total = bytes_total
            if status:
                ev.status = status
            if message:
                ev.message = message
            if status == "done" and ev.bytes_total > 0:
                ev.bytes_done = ev.bytes_total
            ev.ts = time.time()
            snapshot = ProgressEvent(**asdict(ev))
        self._broadcast(snapshot)

    def done(self, job_id: str, message: str = "") -> None:
        self.update(job_id, status="done", message=message)

    def error(self, job_id: str, message: str) -> None:
        self.update(job_id, status="error", message=message)

    def get(self, job_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            ev = self._jobs.get(job_id)
            return ev.to_dict() if ev else None

    def subscribe(self, job_id: Optional[str] = None) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        key = job_id or "*"
        with self._lock:
            self._subs.setdefault(key, []).append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue, job_id: Optional[str] = None) -> None:
        key = job_id or "*"
        with self._lock:
            subs = self._subs.get(key, [])
            if q in subs:
                subs.remove(q)

    def _broadcast(self, ev: ProgressEvent) -> None:
        payload = ev.to_dict()

        def _put():
            with self._lock:
                targets = list(self._subs.get(ev.job_id, [])) + list(self._subs.get("*", []))
            for q in targets:
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


# Global hub used by API / WS
hub = ProgressHub()
