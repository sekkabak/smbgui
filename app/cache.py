"""In-memory TTL cache + persistent per-host SQLite cache with FTS5 index."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import zipfile
import io
from dataclasses import dataclass, asdict, fields
from pathlib import Path
from typing import Any, Optional, Callable


SCHEMA_VERSION = 2
DEFAULT_TTL_SECONDS = 300
DEFAULT_MAX_LISTINGS = 50_000


@dataclass
class ListingEntry:
    name: str
    size: int
    is_dir: bool
    mtime: float  # unix epoch seconds
    attributes: int = 0
    # optional extended fields
    atime: float = 0.0
    ctime: float = 0.0


@dataclass
class CachedListing:
    host: str
    share: str
    path: str
    cred_fp: str
    entries: list[ListingEntry]
    fetched_at: float
    ttl: int
    stale: bool = False

    def age_seconds(self, now: Optional[float] = None) -> float:
        now = now if now is not None else time.time()
        return max(0.0, now - self.fetched_at)

    def is_expired(self, now: Optional[float] = None) -> bool:
        return self.age_seconds(now) > self.ttl

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "share": self.share,
            "path": self.path,
            "cred_fp": self.cred_fp,
            "entries": [asdict(e) for e in self.entries],
            "fetched_at": self.fetched_at,
            "ttl": self.ttl,
            "stale": self.stale or self.is_expired(),
            "age_seconds": self.age_seconds(),
        }


def _mem_key(host: str, share: str, path: str, cred_fp: str) -> str:
    path = normalize_path(path)
    return f"{host}|{share}|{path}|{cred_fp}"


_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def normalize_path(path: str) -> str:
    """Normalize SMB path separators; reject traversal and Windows reserved device names."""
    path = (path or "").replace("\\", "/").strip("/")
    if not path:
        return ""
    parts = [p for p in path.split("/") if p not in ("", ".")]
    for part in parts:
        if part == ".." or part.startswith(".."):
            raise ValueError("path must not contain '..'")
        # reserved device names (CON, PRN, AUX, NUL, COM1.., LPT1..) with optional extension
        stem = part.split(".")[0].upper()
        if stem in _RESERVED_NAMES:
            raise ValueError(f"path contains reserved name: {part}")
        if "\x00" in part:
            raise ValueError("path contains NUL byte")
    return "/".join(parts)


def paths_equal(a: str, b: str) -> bool:
    """Case-insensitive path compare (Windows/SMB-friendly)."""
    try:
        return normalize_path(a).casefold() == normalize_path(b).casefold()
    except ValueError:
        return False


def normalize_host(host: str) -> str:
    return (host or "").strip().lower()


def _entry_from_dict(d: dict) -> ListingEntry:
    allowed = {f.name for f in fields(ListingEntry)}
    return ListingEntry(**{k: v for k, v in d.items() if k in allowed})


class CacheStore:
    """Thread-safe dual-layer cache (memory + SQLite per host) with FTS5."""

    def __init__(
        self,
        data_dir: Path,
        default_ttl: int = DEFAULT_TTL_SECONDS,
        max_listings: int = DEFAULT_MAX_LISTINGS,
    ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl
        self.max_listings = max_listings
        self._mem: dict[str, CachedListing] = {}
        self._lock = threading.RLock()

    def _db_path(self, host: str) -> Path:
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in normalize_host(host))
        if not safe:
            safe = "unknown"
        return self.data_dir / f"cache_{safe}.db"

    def _connect(self, host: str) -> sqlite3.Connection:
        path = self._db_path(host)
        conn = sqlite3.connect(str(path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        self._ensure_schema(conn)
        return conn

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS listings (
                share TEXT NOT NULL,
                path TEXT NOT NULL,
                cred_fp TEXT NOT NULL,
                entries_json TEXT NOT NULL,
                fetched_at REAL NOT NULL,
                ttl INTEGER NOT NULL,
                PRIMARY KEY (share, path, cred_fp)
            );
            CREATE INDEX IF NOT EXISTS idx_listings_cred ON listings(cred_fp);
            CREATE INDEX IF NOT EXISTS idx_listings_fetched ON listings(fetched_at);
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        cur = conn.execute("SELECT version FROM schema_version LIMIT 1")
        row = cur.fetchone()
        if row is None:
            conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
            conn.commit()
            self._create_fts(conn)
            return

        ver = int(row["version"])
        if ver < 2:
            self._migrate_v1_to_v2(conn)
            ver = 2
        if ver != SCHEMA_VERSION:
            conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
            conn.commit()
        # Ensure FTS exists even if partially migrated
        self._create_fts(conn)

    def _create_fts(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS listings_fts USING fts5(
                name,
                fullpath,
                share,
                path,
                cred_fp UNINDEXED,
                is_dir UNINDEXED,
                size UNINDEXED,
                mtime UNINDEXED,
                tokenize = 'unicode61'
            )
            """
        )
        conn.commit()

    def _migrate_v1_to_v2(self, conn: sqlite3.Connection) -> None:
        self._create_fts(conn)
        # Rebuild FTS from existing listings
        cur = conn.execute(
            "SELECT share, path, cred_fp, entries_json FROM listings"
        )
        for row in cur.fetchall():
            entries = [_entry_from_dict(e) for e in json.loads(row["entries_json"])]
            self._fts_replace(conn, row["share"], row["path"], row["cred_fp"], entries)
        conn.execute("UPDATE schema_version SET version = 2")
        conn.commit()

    def _fts_replace(
        self,
        conn: sqlite3.Connection,
        share: str,
        path: str,
        cred_fp: str,
        entries: list[ListingEntry],
    ) -> None:
        path = normalize_path(path)
        conn.execute(
            "DELETE FROM listings_fts WHERE share=? AND path=? AND cred_fp=?",
            (share, path, cred_fp),
        )
        for e in entries:
            full = f"{share}/{path}/{e.name}".replace("//", "/").strip("/")
            conn.execute(
                """
                INSERT INTO listings_fts(name, fullpath, share, path, cred_fp, is_dir, size, mtime)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    e.name,
                    full,
                    share,
                    path,
                    cred_fp,
                    1 if e.is_dir else 0,
                    e.size,
                    e.mtime,
                ),
            )

    def put(
        self,
        host: str,
        share: str,
        path: str,
        cred_fp: str,
        entries: list[ListingEntry],
        ttl: Optional[int] = None,
        fetched_at: Optional[float] = None,
    ) -> CachedListing:
        host = normalize_host(host)
        path = normalize_path(path)
        ttl = self.default_ttl if ttl is None else ttl
        fetched_at = time.time() if fetched_at is None else fetched_at
        listing = CachedListing(
            host=host,
            share=share,
            path=path,
            cred_fp=cred_fp,
            entries=list(entries),
            fetched_at=fetched_at,
            ttl=ttl,
            stale=False,
        )
        key = _mem_key(host, share, path, cred_fp)
        with self._lock:
            self._mem[key] = listing
            conn = self._connect(host)
            try:
                conn.execute(
                    """
                    INSERT INTO listings(share, path, cred_fp, entries_json, fetched_at, ttl)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(share, path, cred_fp) DO UPDATE SET
                        entries_json=excluded.entries_json,
                        fetched_at=excluded.fetched_at,
                        ttl=excluded.ttl
                    """,
                    (
                        share,
                        path,
                        cred_fp,
                        json.dumps([asdict(e) for e in entries]),
                        fetched_at,
                        ttl,
                    ),
                )
                self._fts_replace(conn, share, path, cred_fp, entries)
                conn.commit()
                self._evict_if_needed(conn, host)
            finally:
                conn.close()
        return listing

    def _evict_if_needed(self, conn: sqlite3.Connection, host: str) -> None:
        cur = conn.execute("SELECT COUNT(*) AS c FROM listings")
        count = int(cur.fetchone()["c"])
        if count <= self.max_listings:
            return
        # Evict oldest listings beyond max
        overflow = count - self.max_listings
        cur = conn.execute(
            "SELECT share, path, cred_fp FROM listings ORDER BY fetched_at ASC LIMIT ?",
            (overflow,),
        )
        rows = cur.fetchall()
        for row in rows:
            key = _mem_key(host, row["share"], row["path"], row["cred_fp"])
            self._mem.pop(key, None)
            conn.execute(
                "DELETE FROM listings WHERE share=? AND path=? AND cred_fp=?",
                (row["share"], row["path"], row["cred_fp"]),
            )
            conn.execute(
                "DELETE FROM listings_fts WHERE share=? AND path=? AND cred_fp=?",
                (row["share"], row["path"], row["cred_fp"]),
            )
        conn.commit()

    def get(
        self,
        host: str,
        share: str,
        path: str,
        cred_fp: str,
        allow_stale: bool = True,
    ) -> Optional[CachedListing]:
        host = normalize_host(host)
        path = normalize_path(path)
        key = _mem_key(host, share, path, cred_fp)
        with self._lock:
            listing = self._mem.get(key)
            if listing is None:
                listing = self._load_from_disk(host, share, path, cred_fp)
                if listing is not None:
                    self._mem[key] = listing
            if listing is None:
                return None
            listing.stale = listing.is_expired()
            if listing.stale and not allow_stale:
                return None
            return listing

    def _load_from_disk(
        self, host: str, share: str, path: str, cred_fp: str
    ) -> Optional[CachedListing]:
        db = self._db_path(host)
        if not db.exists():
            return None
        conn = self._connect(host)
        try:
            cur = conn.execute(
                """
                SELECT share, path, cred_fp, entries_json, fetched_at, ttl
                FROM listings WHERE share=? AND path=? AND cred_fp=?
                """,
                (share, path, cred_fp),
            )
            row = cur.fetchone()
            if row is None:
                return None
            entries = [_entry_from_dict(e) for e in json.loads(row["entries_json"])]
            listing = CachedListing(
                host=host,
                share=row["share"],
                path=row["path"],
                cred_fp=row["cred_fp"],
                entries=entries,
                fetched_at=float(row["fetched_at"]),
                ttl=int(row["ttl"]),
            )
            listing.stale = listing.is_expired()
            return listing
        finally:
            conn.close()

    def invalidate(self, host: str, share: str, path: str, cred_fp: Optional[str] = None) -> int:
        """Invalidate path and its parent. Returns approximate removed count."""
        host = normalize_host(host)
        path = normalize_path(path)
        parent = "/".join(path.split("/")[:-1]) if path else ""
        targets = {path, parent}
        removed = 0
        with self._lock:
            keys = list(self._mem.keys())
            for key in keys:
                parts = key.split("|", 3)
                if len(parts) != 4:
                    continue
                h, sh, p, fp = parts
                if h != host or sh != share:
                    continue
                if cred_fp and fp != cred_fp:
                    continue
                if p in targets:
                    del self._mem[key]
                    removed += 1
            conn = self._connect(host)
            try:
                for p in targets:
                    if cred_fp:
                        cur = conn.execute(
                            "DELETE FROM listings WHERE share=? AND path=? AND cred_fp=?",
                            (share, p, cred_fp),
                        )
                        conn.execute(
                            "DELETE FROM listings_fts WHERE share=? AND path=? AND cred_fp=?",
                            (share, p, cred_fp),
                        )
                    else:
                        cur = conn.execute(
                            "DELETE FROM listings WHERE share=? AND path=?",
                            (share, p),
                        )
                        conn.execute(
                            "DELETE FROM listings_fts WHERE share=? AND path=?",
                            (share, p),
                        )
                    removed += cur.rowcount
                conn.commit()
            finally:
                conn.close()
        return removed

    def invalidate_subtree(
        self, host: str, share: str, path: str, cred_fp: Optional[str] = None
    ) -> int:
        """Invalidate path and all cached descendants."""
        host = normalize_host(host)
        path = normalize_path(path)
        removed = 0
        with self._lock:
            keys = list(self._mem.keys())
            for key in keys:
                parts = key.split("|", 3)
                if len(parts) != 4:
                    continue
                h, sh, p, fp = parts
                if h != host or sh != share:
                    continue
                if cred_fp and fp != cred_fp:
                    continue
                if p == path or (path == "" or p.startswith(path + "/")):
                    del self._mem[key]
                    removed += 1
            conn = self._connect(host)
            try:
                if path:
                    like = path + "/%"
                    if cred_fp:
                        cur = conn.execute(
                            "DELETE FROM listings WHERE share=? AND cred_fp=? AND (path=? OR path LIKE ?)",
                            (share, cred_fp, path, like),
                        )
                        conn.execute(
                            "DELETE FROM listings_fts WHERE share=? AND cred_fp=? AND (path=? OR path LIKE ?)",
                            (share, cred_fp, path, like),
                        )
                    else:
                        cur = conn.execute(
                            "DELETE FROM listings WHERE share=? AND (path=? OR path LIKE ?)",
                            (share, path, like),
                        )
                        conn.execute(
                            "DELETE FROM listings_fts WHERE share=? AND (path=? OR path LIKE ?)",
                            (share, path, like),
                        )
                else:
                    if cred_fp:
                        cur = conn.execute(
                            "DELETE FROM listings WHERE share=? AND cred_fp=?",
                            (share, cred_fp),
                        )
                        conn.execute(
                            "DELETE FROM listings_fts WHERE share=? AND cred_fp=?",
                            (share, cred_fp),
                        )
                    else:
                        cur = conn.execute("DELETE FROM listings WHERE share=?", (share,))
                        conn.execute("DELETE FROM listings_fts WHERE share=?", (share,))
                removed += cur.rowcount
                conn.commit()
            finally:
                conn.close()
        return removed

    def invalidate_host(self, host: str) -> int:
        host = normalize_host(host)
        removed = 0
        with self._lock:
            keys = [k for k in self._mem if k.startswith(f"{host}|")]
            for k in keys:
                del self._mem[k]
                removed += 1
            db = self._db_path(host)
            if db.exists():
                conn = self._connect(host)
                try:
                    cur = conn.execute("SELECT COUNT(*) AS c FROM listings")
                    removed += int(cur.fetchone()["c"])
                    conn.execute("DELETE FROM listings")
                    conn.execute("DELETE FROM listings_fts")
                    conn.commit()
                finally:
                    conn.close()
        return removed

    def clear_host(self, host: str) -> None:
        host = normalize_host(host)
        with self._lock:
            keys = [k for k in self._mem if k.startswith(f"{host}|")]
            for k in keys:
                del self._mem[k]
            db = self._db_path(host)
            if db.exists():
                # Also remove WAL/SHM
                for suffix in ("", "-wal", "-shm"):
                    p = Path(str(db) + suffix) if suffix else db
                    if p.exists():
                        p.unlink()

    def load_host_tree(self, host: str, cred_fp: Optional[str] = None) -> list[CachedListing]:
        host = normalize_host(host)
        db = self._db_path(host)
        if not db.exists():
            return []
        out: list[CachedListing] = []
        with self._lock:
            conn = self._connect(host)
            try:
                if cred_fp:
                    cur = conn.execute(
                        "SELECT share, path, cred_fp, entries_json, fetched_at, ttl FROM listings WHERE cred_fp=?",
                        (cred_fp,),
                    )
                else:
                    cur = conn.execute(
                        "SELECT share, path, cred_fp, entries_json, fetched_at, ttl FROM listings"
                    )
                for row in cur.fetchall():
                    entries = [_entry_from_dict(e) for e in json.loads(row["entries_json"])]
                    listing = CachedListing(
                        host=host,
                        share=row["share"],
                        path=row["path"],
                        cred_fp=row["cred_fp"],
                        entries=entries,
                        fetched_at=float(row["fetched_at"]),
                        ttl=int(row["ttl"]),
                    )
                    listing.stale = listing.is_expired()
                    key = _mem_key(host, listing.share, listing.path, listing.cred_fp)
                    self._mem[key] = listing
                    out.append(listing)
            finally:
                conn.close()
        return out

    def search(
        self,
        host: str,
        query: str,
        cred_fp: Optional[str] = None,
        share: Optional[str] = None,
        limit: int = 200,
        use_fts: bool = True,
    ) -> list[dict[str, Any]]:
        """Search via FTS5 when available; fall back to substring scan."""
        host = normalize_host(host)
        q = (query or "").strip()
        if not q:
            return []
        db = self._db_path(host)
        if not db.exists():
            return []

        with self._lock:
            conn = self._connect(host)
            try:
                if use_fts:
                    hits = self._fts_search(conn, q, cred_fp, share, limit)
                    if hits is not None:
                        return hits
                # Fallback linear
                return self._linear_search(conn, q.lower(), cred_fp, share, limit)
            finally:
                conn.close()

    def _fts_search(
        self,
        conn: sqlite3.Connection,
        query: str,
        cred_fp: Optional[str],
        share: Optional[str],
        limit: int,
    ) -> Optional[list[dict[str, Any]]]:
        # Build FTS query: quote tokens, OR them for fuzzy-ish match; also prefix
        tokens = [t for t in re_split_tokens(query) if t]
        if not tokens:
            return []
        # Use prefix matching: token*
        fts_q = " OR ".join(f'"{t}"*' if not t.endswith("*") else f'"{t[:-1]}"*' for t in tokens)
        try:
            sql = """
                SELECT name, fullpath, share, path, cred_fp, is_dir, size, mtime
                FROM listings_fts WHERE listings_fts MATCH ?
            """
            params: list[Any] = [fts_q]
            if cred_fp:
                sql += " AND cred_fp=?"
                params.append(cred_fp)
            if share:
                sql += " AND share=?"
                params.append(share)
            sql += " LIMIT ?"
            params.append(limit)
            cur = conn.execute(sql, params)
            hits = []
            for row in cur.fetchall():
                hits.append(
                    {
                        "share": row["share"],
                        "path": row["path"],
                        "name": row["name"],
                        "is_dir": bool(row["is_dir"]),
                        "size": int(row["size"] or 0),
                        "mtime": float(row["mtime"] or 0),
                        "fullpath": row["fullpath"],
                        "stale": False,
                    }
                )
            return hits
        except sqlite3.OperationalError:
            return None

    def _linear_search(
        self,
        conn: sqlite3.Connection,
        q: str,
        cred_fp: Optional[str],
        share: Optional[str],
        limit: int,
    ) -> list[dict[str, Any]]:
        if cred_fp:
            cur = conn.execute(
                "SELECT share, path, cred_fp, entries_json, fetched_at, ttl FROM listings WHERE cred_fp=?",
                (cred_fp,),
            )
        else:
            cur = conn.execute(
                "SELECT share, path, cred_fp, entries_json, fetched_at, ttl FROM listings"
            )
        hits: list[dict[str, Any]] = []
        now = time.time()
        for row in cur.fetchall():
            if share and row["share"] != share:
                continue
            stale = (now - float(row["fetched_at"])) > int(row["ttl"])
            for e in json.loads(row["entries_json"]):
                name = e.get("name", "")
                full = f"{row['share']}/{row['path']}/{name}".replace("//", "/")
                if q in name.lower() or q in full.lower():
                    hits.append(
                        {
                            "share": row["share"],
                            "path": row["path"],
                            "name": name,
                            "is_dir": bool(e.get("is_dir")),
                            "size": int(e.get("size") or 0),
                            "mtime": float(e.get("mtime") or 0),
                            "fullpath": full,
                            "stale": stale,
                        }
                    )
                    if len(hits) >= limit:
                        return hits
        return hits

    def status(self, host: Optional[str] = None) -> dict[str, Any]:
        with self._lock:
            mem_count = len(self._mem)
            hosts: dict[str, Any] = {}
            for db in self.data_dir.glob("cache_*.db"):
                h = db.stem.replace("cache_", "", 1)
                if host and normalize_host(host) != normalize_host(h):
                    continue
                conn = sqlite3.connect(str(db))
                conn.row_factory = sqlite3.Row
                try:
                    self._ensure_schema(conn)
                    cur = conn.execute("SELECT COUNT(*) AS c FROM listings")
                    count = int(cur.fetchone()["c"])
                    try:
                        cur = conn.execute("SELECT COUNT(*) AS c FROM listings_fts")
                        fts_count = int(cur.fetchone()["c"])
                    except sqlite3.Error:
                        fts_count = 0
                    cur = conn.execute("SELECT version FROM schema_version LIMIT 1")
                    ver_row = cur.fetchone()
                    ver = int(ver_row["version"]) if ver_row else None
                except sqlite3.Error:
                    count = 0
                    fts_count = 0
                    ver = None
                finally:
                    conn.close()
                hosts[h] = {
                    "db_path": str(db),
                    "listings": count,
                    "fts_entries": fts_count,
                    "schema_version": ver,
                    "size_bytes": db.stat().st_size if db.exists() else 0,
                }
            return {
                "memory_entries": mem_count,
                "default_ttl": self.default_ttl,
                "max_listings": self.max_listings,
                "schema_version": SCHEMA_VERSION,
                "hosts": hosts,
            }

    def set_ttl(self, ttl: int) -> None:
        self.default_ttl = max(1, int(ttl))

    def set_max_listings(self, n: int) -> None:
        self.max_listings = max(100, int(n))

    def export_host(self, host: str) -> bytes:
        """Export host cache DB as zip bytes."""
        host = normalize_host(host)
        db = self._db_path(host)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            meta = {"host": host, "schema_version": SCHEMA_VERSION, "exported_at": time.time()}
            zf.writestr("meta.json", json.dumps(meta))
            if db.exists():
                # Checkpoint WAL first
                with self._lock:
                    conn = self._connect(host)
                    try:
                        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    finally:
                        conn.close()
                zf.write(db, arcname=f"cache_{host}.db")
        return buf.getvalue()

    def import_host(self, host: str, data: bytes) -> dict[str, Any]:
        """Import a previously exported cache zip for host."""
        host = normalize_host(host)
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            names = zf.namelist()
            db_name = next((n for n in names if n.endswith(".db")), None)
            if not db_name:
                raise ValueError("zip missing cache db")
            target = self._db_path(host)
            with self._lock:
                # Clear memory for host
                keys = [k for k in self._mem if k.startswith(f"{host}|")]
                for k in keys:
                    del self._mem[k]
                for suffix in ("", "-wal", "-shm"):
                    p = Path(str(target) + suffix) if suffix else target
                    if p.exists():
                        p.unlink()
                target.write_bytes(zf.read(db_name))
                # Run migrations
                conn = self._connect(host)
                try:
                    cur = conn.execute("SELECT COUNT(*) AS c FROM listings")
                    count = int(cur.fetchone()["c"])
                finally:
                    conn.close()
        return {"host": host, "listings": count, "schema_version": SCHEMA_VERSION}


def re_split_tokens(query: str) -> list[str]:
    import re

    return [t for t in re.split(r"[\s/\\]+", query.strip()) if t]
