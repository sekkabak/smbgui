"""Opaque browser session tokens so secrets are not put in GET query strings."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from .auth import Credentials
from .proxy import ProxyConfig


@dataclass
class WebSession:
    sid: str
    host: str
    port: int
    creds: Credentials
    proxy: Optional[ProxyConfig] = None
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)


class WebSessionStore:
    """In-memory sid → credentials map (process lifetime)."""

    COOKIE_NAME = "smbgui_sid"

    def __init__(self, ttl_seconds: float = 12 * 3600):
        self._sessions: dict[str, WebSession] = {}
        self._lock = threading.RLock()
        self.ttl_seconds = ttl_seconds

    def create(
        self,
        host: str,
        port: int,
        creds: Credentials,
        proxy: Optional[ProxyConfig] = None,
    ) -> str:
        sid = secrets.token_urlsafe(32)
        sess = WebSession(
            sid=sid,
            host=(host or "").strip(),
            port=int(port or 445),
            creds=creds,
            proxy=proxy,
        )
        with self._lock:
            self._sessions[sid] = sess
        return sid

    def get(self, sid: str) -> Optional[WebSession]:
        if not sid:
            return None
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is None:
                return None
            if self.ttl_seconds > 0 and (time.time() - sess.last_used) > self.ttl_seconds:
                self._sessions.pop(sid, None)
                return None
            sess.last_used = time.time()
            return sess

    def get_for_host(self, sid: str, host: str) -> Optional[WebSession]:
        sess = self.get(sid)
        if sess is None:
            return None
        if (host or "").strip().lower() != sess.host.lower():
            return None
        return sess

    def revoke(self, sid: str) -> None:
        with self._lock:
            self._sessions.pop(sid, None)

    def revoke_host(self, host: str) -> int:
        host = (host or "").lower()
        with self._lock:
            keys = [k for k, s in self._sessions.items() if s.host.lower() == host]
            for k in keys:
                self._sessions.pop(k, None)
            return len(keys)


# Process-wide store used by the API router
store = WebSessionStore()
