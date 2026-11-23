"""Persistent bookmarks and recent-connection history."""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class Bookmark:
    id: str
    label: str
    host: str
    port: int = 445
    share: str = ""
    path: str = ""
    username: str = ""
    domain: str = ""
    # never store password/hash by default; optional opt-in
    created_at: float = field(default_factory=time.time)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RecentConnection:
    host: str
    port: int
    username: str
    domain: str
    auth_mode: str
    share: str = ""
    ts: float = field(default_factory=time.time)
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BookmarkStore:
    def __init__(self, path: Path, max_recent: int = 30):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_recent = max_recent
        self._lock = threading.RLock()
        self._bookmarks: list[Bookmark] = []
        self._recent: list[RecentConnection] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            return
        self._bookmarks = [Bookmark(**b) for b in raw.get("bookmarks", [])]
        self._recent = [RecentConnection(**r) for r in raw.get("recent", [])]

    def _save(self) -> None:
        payload = {
            "bookmarks": [b.to_dict() for b in self._bookmarks],
            "recent": [r.to_dict() for r in self._recent],
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(self.path)

    def list_bookmarks(self) -> list[dict[str, Any]]:
        with self._lock:
            return [b.to_dict() for b in self._bookmarks]

    def add_bookmark(
        self,
        label: str,
        host: str,
        port: int = 445,
        share: str = "",
        path: str = "",
        username: str = "",
        domain: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        bm = Bookmark(
            id=uuid.uuid4().hex[:12],
            label=label or f"{host}/{share}/{path}",
            host=host,
            port=port,
            share=share,
            path=path,
            username=username,
            domain=domain,
            notes=notes,
        )
        with self._lock:
            self._bookmarks.append(bm)
            self._save()
        return bm.to_dict()

    def remove_bookmark(self, bookmark_id: str) -> bool:
        with self._lock:
            before = len(self._bookmarks)
            self._bookmarks = [b for b in self._bookmarks if b.id != bookmark_id]
            if len(self._bookmarks) == before:
                return False
            self._save()
            return True

    def update_bookmark(self, bookmark_id: str, **fields) -> Optional[dict[str, Any]]:
        with self._lock:
            for b in self._bookmarks:
                if b.id == bookmark_id:
                    for k, v in fields.items():
                        if hasattr(b, k) and k != "id":
                            setattr(b, k, v)
                    self._save()
                    return b.to_dict()
        return None

    def add_recent(
        self,
        host: str,
        port: int,
        username: str,
        domain: str,
        auth_mode: str,
        share: str = "",
    ) -> dict[str, Any]:
        rc = RecentConnection(
            host=host,
            port=port,
            username=username,
            domain=domain,
            auth_mode=auth_mode,
            share=share,
            label=f"{domain}\\{username}@{host}:{port}" if domain else f"{username}@{host}:{port}",
        )
        with self._lock:
            # Dedupe by host+user+auth_mode
            self._recent = [
                r
                for r in self._recent
                if not (r.host == host and r.username == username and r.auth_mode == auth_mode and r.port == port)
            ]
            self._recent.insert(0, rc)
            self._recent = self._recent[: self.max_recent]
            self._save()
        return rc.to_dict()

    def list_recent(self) -> list[dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self._recent]

    def clear_recent(self) -> None:
        with self._lock:
            self._recent = []
            self._save()
