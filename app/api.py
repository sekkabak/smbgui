"""FastAPI routes for smbgui (full feature set)."""

from __future__ import annotations

import mimetypes
import time
from typing import Any, Optional

from fastapi import APIRouter, Cookie, File, Form, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from .auth import Credentials, credentials_from_fields, parse_connection_string
from .bookmarks import BookmarkStore
from .cache import CacheStore, ListingEntry, normalize_path
from .export_listing import (
    export_filename,
    normalize_format,
    rows_from_listing,
    to_csv,
    to_json,
)
from .shares_util import classify_share, is_browsable_share
from .logging_util import setup_logging, log_event
from .progress import hub as progress_hub
from .activity import activity
from .jobs import jobs as job_manager
from .config import settings as reliability_settings, parts_dir
from .proxy import proxy_from_fields, resolve_proxy
from .resilience import RetryPolicy
from .web_sessions import WebSessionStore, store as web_sessions
from pathlib import Path as FsPath
import asyncio
from concurrent.futures import ThreadPoolExecutor

from .session_log import SessionLog
from . import smb_client as smb

PREVIEW_MAX_BYTES = 2 * 1024 * 1024
logger = setup_logging()


def error_response(code: str, message: str, status: int = 400) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


class AuthMixin(BaseModel):
    host: str = ""
    port: int = 445
    username: str = ""
    password: str = ""
    domain: str = ""
    hash: Optional[str] = None
    guest: bool = False
    use_kerberos: bool = False
    aes_key: str = ""
    kdc_host: str = ""
    dc_ip: str = ""
    ccache: str = ""
    spn: str = ""
    # Opaque UI session id (preferred over re-sending secrets after connect)
    sid: str = ""
    # Reliability / proxy (optional per-request overrides)
    proxy_type: str = ""
    proxy_host: str = ""
    proxy_port: int = 0
    proxy_user: str = ""
    proxy_pass: str = ""
    connect_timeout: Optional[float] = None


class ConnectBody(AuthMixin):
    connection: Optional[str] = None
    ttl: Optional[int] = None


class PathBody(AuthMixin):
    share: str = ""
    path: str = ""


class DeleteBody(PathBody):
    is_dir: bool = False
    recursive: bool = False


class RenameBody(PathBody):
    new_path: str


class CopyMoveBody(AuthMixin):
    src_share: str
    src_path: str
    dst_share: str
    dst_path: str
    action: str = "copy"  # copy|move


class BulkBody(AuthMixin):
    share: str
    paths: list[dict[str, Any]]  # [{path, is_dir}]
    action: str  # delete|download_zip
    dst_share: str = ""
    dst_path: str = ""


class RefreshBody(AuthMixin):
    share: Optional[str] = None
    path: str = ""
    all: bool = False
    recursive: bool = False
    max_depth: int = 8
    max_dirs: int = 2000


class ClearCacheBody(BaseModel):
    host: str


class SettingsBody(BaseModel):
    ttl: Optional[int] = None
    max_listings: Optional[int] = None
    # Reliability knobs
    connect_timeout: Optional[float] = None
    io_timeout: Optional[float] = None
    keepalive_seconds: Optional[float] = None
    max_retries: Optional[int] = None
    base_delay: Optional[float] = None
    max_delay: Optional[float] = None
    jitter: Optional[float] = None
    retry_enabled: Optional[bool] = None
    auto_reconnect: Optional[bool] = None
    resume_enabled: Optional[bool] = None
    proxy: Optional[dict] = None


class BookmarkAddBody(BaseModel):
    label: str = ""
    host: str
    port: int = 445
    share: str = ""
    path: str = ""
    username: str = ""
    domain: str = ""
    notes: str = ""


def _proxy_from_body(body) -> Any:
    host = getattr(body, "proxy_host", "") or ""
    if host:
        return proxy_from_fields(
            proxy_type=getattr(body, "proxy_type", "") or "socks5",
            proxy_host=host,
            proxy_port=int(getattr(body, "proxy_port", 0) or 0),
            proxy_user=getattr(body, "proxy_user", "") or "",
            proxy_pass=getattr(body, "proxy_pass", "") or "",
            enabled=True,
        )
    return None


def _creds_from_body(body) -> Credentials:
    return credentials_from_fields(
        username=getattr(body, "username", "") or "",
        password=getattr(body, "password", "") or "",
        domain=getattr(body, "domain", "") or "",
        hash_str=getattr(body, "hash", None),
        guest=bool(getattr(body, "guest", False)),
        use_kerberos=bool(getattr(body, "use_kerberos", False)),
        aes_key=getattr(body, "aes_key", "") or "",
        kdc_host=getattr(body, "kdc_host", "") or "",
        dc_ip=getattr(body, "dc_ip", "") or "",
        ccache=getattr(body, "ccache", "") or "",
        spn=getattr(body, "spn", "") or "",
    )


def _sid_from(request: Optional[Request], sid: str = "", cookie_sid: Optional[str] = None) -> str:
    if sid:
        return sid
    if cookie_sid:
        return cookie_sid
    if request is not None:
        return request.cookies.get(WebSessionStore.COOKIE_NAME, "") or ""
    return ""


def _creds_from_fields_or_session(
    *,
    host: str,
    port: int = 445,
    username: str = "",
    password: str = "",
    domain: str = "",
    hash: Optional[str] = None,
    guest: bool = False,
    use_kerberos: bool = False,
    aes_key: str = "",
    kdc_host: str = "",
    dc_ip: str = "",
    ccache: str = "",
    spn: str = "",
    sid: str = "",
    request: Optional[Request] = None,
    cookie_sid: Optional[str] = None,
) -> tuple[Credentials, int, Optional[Any]]:
    """
    Resolve credentials for a request.

    Prefer opaque ``sid`` (cookie or query/body) so secrets are not required on
    every GET. Explicit password/hash fields still work for API clients.
    Returns (creds, port, proxy_or_None).
    """
    token = _sid_from(request, sid, cookie_sid)
    has_secrets = bool(password or hash or aes_key or guest or username)
    if token and not has_secrets:
        sess = web_sessions.get_for_host(token, host)
        if sess is not None:
            return sess.creds, sess.port or port, sess.proxy
        # sid present but miss — fall through; may still have nothing useful
    creds = credentials_from_fields(
        username, password, domain, hash, guest, use_kerberos, aes_key, kdc_host, dc_ip, ccache, spn
    )
    return creds, port, None


def _creds_from_body_or_session(body, request: Optional[Request] = None, cookie_sid: Optional[str] = None):
    sid = getattr(body, "sid", "") or ""
    host = getattr(body, "host", "") or ""
    has_secrets = bool(
        getattr(body, "password", None)
        or getattr(body, "hash", None)
        or getattr(body, "aes_key", None)
        or getattr(body, "guest", False)
        or getattr(body, "username", None)
    )
    token = _sid_from(request, sid, cookie_sid)
    if token and not has_secrets and host:
        sess = web_sessions.get_for_host(token, host)
        if sess is not None:
            if not getattr(body, "port", None) or body.port == 445:
                body.port = sess.port  # type: ignore[attr-defined]
            return sess.creds
    return _creds_from_body(body)


def _set_sid_cookie(response: Response, sid: str) -> None:
    response.set_cookie(
        key=WebSessionStore.COOKIE_NAME,
        value=sid,
        httponly=True,
        samesite="lax",
        max_age=12 * 3600,
        path="/",
    )


def create_router(
    pool: smb.SMBPool,
    cache: CacheStore,
    slog: SessionLog,
    bookmarks: BookmarkStore,
) -> APIRouter:
    router = APIRouter(prefix="/api")
    last_conn: dict[str, dict[str, Any]] = {}
    sessions_meta: dict[str, dict[str, Any]] = {}  # session_id -> public meta (no secrets)

    def _resolve_connect(body: ConnectBody):
        if body.connection:
            host, port, base = parse_connection_string(body.connection)
            if body.guest:
                creds = credentials_from_fields(guest=True)
            else:
                creds = credentials_from_fields(
                    username=body.username or base.username,
                    password=body.password or base.password,
                    domain=body.domain or base.domain,
                    hash_str=body.hash,
                    guest=False,
                    use_kerberos=body.use_kerberos,
                    aes_key=body.aes_key,
                    kdc_host=body.kdc_host,
                    dc_ip=body.dc_ip,
                    ccache=body.ccache,
                    spn=body.spn,
                )
            if body.port and body.port != 445:
                port = body.port
            return host, port, creds
        host = (body.host or "").strip()
        if not host:
            raise ValueError("host is required")
        return host, int(body.port or 445), _creds_from_body(body)

    def _store_meta(host: str, port: int, creds, session: smb.PooledSession, ui_sid: str = ""):
        # Never persist raw secrets in last_conn / sessions_meta (public-meta only).
        meta = {
            "session_id": session.session_id,
            "sid": ui_sid,
            "host": host,
            "port": port,
            "username": creds.username,
            "domain": creds.domain,
            "guest": creds.is_guest,
            "is_hash": creds.is_hash,
            "use_kerberos": creds.use_kerberos,
            "kdc_host": creds.kdc_host,
            "dc_ip": creds.dc_ip,
            "ccache": bool(creds.ccache),
            "cred_fp": creds.fingerprint(),
            "display_user": creds.display_user(),
            "auth_mode": creds.auth_mode(),
        }
        last_conn[host.lower()] = meta
        sessions_meta[session.session_id] = meta
        return meta

    @router.post("/connect")
    def connect(body: ConnectBody):
        try:
            host, port, creds = _resolve_connect(body)
        except ValueError as e:
            slog.add("connect", detail=str(e), source="local", ok=False, error=str(e))
            return error_response("invalid_request", str(e))

        proxy = _proxy_from_body(body)
        timeout = body.connect_timeout
        activity.set("connecting", f"connecting to {host}:{port}…", host=host, action="connect")
        try:
            session = pool.connect(host, port, creds, timeout=timeout, proxy=proxy)
            shares = smb.list_shares(session)
        except smb.SMBError as e:
            slog.add("connect", host=host, detail=str(e), source="wire", ok=False, error=e.message)
            log_event(logger, "connect_failed", host=host, action="connect", error=e.message)
            activity.error(f"connect failed: {e.message}", host=host)
            return error_response(e.code, e.message, status=502)

        if body.ttl:
            cache.set_ttl(int(body.ttl))

        cached = cache.load_host_tree(host, cred_fp=creds.fingerprint())
        ui_sid = web_sessions.create(host=host, port=port, creds=creds, proxy=proxy)
        meta = _store_meta(host, port, creds, session, ui_sid=ui_sid)
        bookmarks.add_recent(
            host=host,
            port=port,
            username=creds.username,
            domain=creds.domain,
            auth_mode=creds.auth_mode(),
        )
        slog.add(
            "connect",
            host=host,
            detail=f"{creds.display_user()} mode={creds.auth_mode()} shares={len(shares)}",
            source="wire",
            ok=True,
        )
        log_event(logger, "connected", host=host, action="connect")
        activity.idle(f"connected to {host} as {creds.display_user()}")
        payload = {
            "ok": True,
            "host": host,
            "port": port,
            "user": creds.display_user(),
            "cred_fp": creds.fingerprint(),
            "auth_mode": creds.auth_mode(),
            "is_hash": creds.is_hash,
            "guest": creds.is_guest,
            "use_kerberos": creds.use_kerberos,
            "session_id": session.session_id,
            "sid": ui_sid,
            "shares": [smb.share_to_dict(s) for s in shares],
            "cached_listings": len(cached),
            "server_name": session.conn.getServerName(),
            "public": creds.public_dict(),
        }
        resp = JSONResponse(content=payload)
        _set_sid_cookie(resp, ui_sid)
        return resp

    @router.get("/sessions")
    def sessions():
        return {"sessions": pool.list_sessions()}

    @router.post("/reconnect")
    def reconnect(
        body: AuthMixin,
        request: Request,
        smbgui_sid: Optional[str] = Cookie(None, alias=WebSessionStore.COOKIE_NAME),
    ):
        creds = _creds_from_body_or_session(body, request, smbgui_sid)
        try:
            session = pool.reconnect(body.host, body.port, creds)
            shares = smb.list_shares(session)
        except smb.SMBError as e:
            return error_response(e.code, e.message, status=502)
        ui_sid = _sid_from(request, getattr(body, "sid", ""), smbgui_sid)
        if not ui_sid or web_sessions.get_for_host(ui_sid, body.host) is None:
            ui_sid = web_sessions.create(body.host, body.port, creds)
        _store_meta(body.host, body.port, creds, session, ui_sid=ui_sid)
        slog.add("reconnect", host=body.host, detail="ok", source="wire", ok=True)
        payload = {
            "ok": True,
            "session_id": session.session_id,
            "sid": ui_sid,
            "shares": [smb.share_to_dict(s) for s in shares],
        }
        resp = JSONResponse(content=payload)
        _set_sid_cookie(resp, ui_sid)
        return resp

    @router.get("/shares")
    def shares(
        request: Request,
        host: str = Query(...),
        port: int = Query(445),
        username: str = "",
        password: str = "",
        domain: str = "",
        hash: Optional[str] = None,
        guest: bool = False,
        use_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: str = "",
        dc_ip: str = "",
        ccache: str = "",
        sid: str = "",
        use_cache: bool = True,
        show_hidden: bool = True,
        show_ipc: bool = True,
        smbgui_sid: Optional[str] = Cookie(None, alias=WebSessionStore.COOKIE_NAME),
    ):
        creds, port, _px = _creds_from_fields_or_session(
            host=host,
            port=port,
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            guest=guest,
            use_kerberos=use_kerberos,
            aes_key=aes_key,
            kdc_host=kdc_host,
            dc_ip=dc_ip,
            ccache=ccache,
            sid=sid,
            request=request,
            cookie_sid=smbgui_sid,
        )
        if use_cache:
            cached = cache.get(host, "__shares__", "", creds.fingerprint(), allow_stale=True)
            if cached is not None:
                slog.add("shares", host=host, detail="from cache", source="cache", ok=True)
                return {
                    "host": host,
                    "shares": [{**classify_share(e.name), "remark": "", "type": 0} for e in cached.entries],
                    "from_cache": True,
                    "stale": cached.stale,
                    "fetched_at": cached.fetched_at,
                }
        try:
            session = pool.get(host, port, creds)
            items = smb.list_shares(session, include_hidden=show_hidden, include_ipc=show_ipc)
        except smb.SMBError as e:
            return error_response(e.code, e.message, status=502)
        entries = [ListingEntry(name=s.name, size=0, is_dir=True, mtime=0) for s in items]
        listing = cache.put(host, "__shares__", "", creds.fingerprint(), entries)
        slog.add("shares", host=host, detail=f"wire count={len(items)}", source="wire", ok=True)
        return {
            "host": host,
            "shares": [smb.share_to_dict(s) for s in items],
            "from_cache": False,
            "stale": False,
            "fetched_at": listing.fetched_at,
        }

    @router.get("/list")
    def list_dir(
        request: Request,
        host: str = Query(...),
        share: str = Query(...),
        path: str = "",
        port: int = 445,
        username: str = "",
        password: str = "",
        domain: str = "",
        hash: Optional[str] = None,
        guest: bool = False,
        use_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: str = "",
        dc_ip: str = "",
        ccache: str = "",
        sid: str = "",
        use_cache: bool = True,
        smbgui_sid: Optional[str] = Cookie(None, alias=WebSessionStore.COOKIE_NAME),
    ):
        creds, port, _px = _creds_from_fields_or_session(
            host=host,
            port=port,
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            guest=guest,
            use_kerberos=use_kerberos,
            aes_key=aes_key,
            kdc_host=kdc_host,
            dc_ip=dc_ip,
            ccache=ccache,
            sid=sid,
            request=request,
            cookie_sid=smbgui_sid,
        )
        try:
            path = normalize_path(path)
        except ValueError as e:
            return error_response("invalid_path", str(e))
        if use_cache:
            cached = cache.get(host, share, path, creds.fingerprint(), allow_stale=True)
            if cached is not None:
                slog.add(
                    "list",
                    host=host,
                    detail=f"{share}/{path} cache stale={cached.stale}",
                    source="cache",
                    ok=True,
                )
                return {
                    "host": host,
                    "share": share,
                    "path": path,
                    "entries": [e.__dict__ for e in cached.entries],
                    "from_cache": True,
                    "stale": cached.stale,
                    "fetched_at": cached.fetched_at,
                    "refreshed_at": time.strftime("%H:%M", time.localtime(cached.fetched_at)),
                    "ttl": cached.ttl,
                }
        if not is_browsable_share(share):
            return error_response(
                "not_browsable",
                f"{share} is not a filesystem share (IPC$ is for named pipes only)",
                status=400,
            )
        activity.set("listing", f"listing {share}/{path}…", host=host, path=f"{share}/{path}", action="list")
        try:
            session = pool.get(host, port, creds)
            entries = smb.list_directory(session, share, path)
        except smb.SMBError as e:
            slog.add("list", host=host, detail=str(e), source="wire", ok=False, error=e.message)
            activity.error(f"list failed: {e.message}", host=host, path=f"{share}/{path}")
            return error_response(e.code, e.message, status=502)
        listing = cache.put(host, share, path, creds.fingerprint(), entries)
        slog.add("list", host=host, detail=f"{share}/{path} wire count={len(entries)}", source="wire", ok=True)
        activity.idle(f"listed {share}/{path} ({len(entries)} entries)")
        return {
            "host": host,
            "share": share,
            "path": path,
            "entries": [e.__dict__ for e in entries],
            "from_cache": False,
            "stale": False,
            "fetched_at": listing.fetched_at,
            "refreshed_at": time.strftime("%H:%M", time.localtime(listing.fetched_at)),
            "ttl": listing.ttl,
        }

    @router.post("/refresh")
    def refresh(body: RefreshBody):
        creds = _creds_from_body(body)
        host = body.host
        if body.all:
            removed = cache.invalidate_host(host)
            try:
                session = pool.get(host, body.port, creds)
                items = smb.list_shares(session)
                entries = [ListingEntry(name=s.name, size=0, is_dir=True, mtime=0) for s in items]
                listing = cache.put(host, "__shares__", "", creds.fingerprint(), entries)
            except smb.SMBError as e:
                return error_response(e.code, e.message, status=502)
            slog.add("refresh_all", host=host, detail=f"invalidated={removed}", source="wire", ok=True)
            return {
                "ok": True,
                "scope": "host",
                "invalidated": removed,
                "shares": [smb.share_to_dict(s) for s in items],
                "fetched_at": listing.fetched_at,
                "refreshed_at": time.strftime("%H:%M", time.localtime(listing.fetched_at)),
            }

        share = body.share or ""
        if not share:
            return error_response("invalid_request", "share is required unless all=true")
        path = normalize_path(body.path)

        if body.recursive:
            job_id = progress_hub.new_job("refresh", host=host, path=f"{share}/{path}")
            cache.invalidate_subtree(host, share, path, creds.fingerprint())
            try:
                session = pool.get(host, body.port, creds)
            except smb.SMBError as e:
                progress_hub.error(job_id, e.message)
                return error_response(e.code, e.message, status=502)
            dirs_done = 0
            root_entries: list[ListingEntry] = []
            try:
                for dirpath, entries in smb.walk_directories(
                    session, share, path, max_depth=body.max_depth, max_dirs=body.max_dirs
                ):
                    cache.put(host, share, dirpath, creds.fingerprint(), entries)
                    dirs_done += 1
                    progress_hub.update(
                        job_id,
                        bytes_done=dirs_done,
                        bytes_total=body.max_dirs,
                        message=f"listed {share}/{dirpath}",
                    )
                    pct = round(100.0 * dirs_done / max(1, body.max_dirs), 1)
                    activity.set(
                        "refreshing",
                        f"refreshing ({dirs_done}/{body.max_dirs} dirs) {share}/{dirpath}",
                        host=host,
                        path=f"{share}/{dirpath}",
                        action="refresh",
                        progress=pct,
                    )
                    if dirpath == path:
                        root_entries = entries
            except smb.SMBError as e:
                progress_hub.error(job_id, e.message)
                return error_response(e.code, e.message, status=502)
            progress_hub.done(job_id, message=f"dirs={dirs_done}")
            activity.idle(f"refresh done — {dirs_done} dirs")
            slog.add(
                "refresh_recursive",
                host=host,
                detail=f"{share}/{path} dirs={dirs_done}",
                source="wire",
                ok=True,
            )
            now = time.time()
            return {
                "ok": True,
                "scope": "recursive",
                "host": host,
                "share": share,
                "path": path,
                "dirs_refreshed": dirs_done,
                "entries": [e.__dict__ for e in root_entries],
                "job_id": job_id,
                "fetched_at": now,
                "refreshed_at": time.strftime("%H:%M", time.localtime(now)),
                "from_cache": False,
                "stale": False,
            }

        cache.invalidate(host, share, path, creds.fingerprint())
        activity.set("refreshing", f"refreshing {share}/{path}…", host=host, path=f"{share}/{path}", action="refresh")
        try:
            session = pool.get(host, body.port, creds)
            entries = smb.list_directory(session, share, path)
        except smb.SMBError as e:
            activity.error(f"refresh failed: {e.message}", host=host)
            return error_response(e.code, e.message, status=502)
        listing = cache.put(host, share, path, creds.fingerprint(), entries)
        slog.add("refresh", host=host, detail=f"{share}/{path} count={len(entries)}", source="wire", ok=True)
        activity.idle(f"refreshed {share}/{path}")
        return {
            "ok": True,
            "scope": "path",
            "host": host,
            "share": share,
            "path": path,
            "entries": [e.__dict__ for e in entries],
            "from_cache": False,
            "stale": False,
            "fetched_at": listing.fetched_at,
            "refreshed_at": time.strftime("%H:%M", time.localtime(listing.fetched_at)),
        }

    @router.get("/file")
    def get_file(
        request: Request,
        host: str = Query(...),
        share: str = Query(...),
        path: str = Query(...),
        port: int = 445,
        username: str = "",
        password: str = "",
        domain: str = "",
        hash: Optional[str] = None,
        guest: bool = False,
        use_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: str = "",
        dc_ip: str = "",
        ccache: str = "",
        sid: str = "",
        preview: bool = False,
        smbgui_sid: Optional[str] = Cookie(None, alias=WebSessionStore.COOKIE_NAME),
    ):
        creds, port, _px = _creds_from_fields_or_session(
            host=host,
            port=port,
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            guest=guest,
            use_kerberos=use_kerberos,
            aes_key=aes_key,
            kdc_host=kdc_host,
            dc_ip=dc_ip,
            ccache=ccache,
            sid=sid,
            request=request,
            cookie_sid=smbgui_sid,
        )
        try:
            path = normalize_path(path)
        except ValueError as e:
            return error_response("invalid_path", str(e))
        job_id = progress_hub.new_job("download", host=host, path=f"{share}/{path}")

        def prog(done, total):
            progress_hub.update(job_id, bytes_done=done, bytes_total=total if total > 0 else 0)

        name = path.split("/")[-1] if path else "file"
        ctype, _ = mimetypes.guess_type(name)
        ctype = ctype or "application/octet-stream"

        try:
            session = pool.get(host, port, creds)
            if preview:
                data = smb.download_file(session, share, path, progress=prog)
                if len(data) > PREVIEW_MAX_BYTES:
                    progress_hub.error(job_id, "too large")
                    return error_response(
                        "too_large", f"file exceeds preview limit of {PREVIEW_MAX_BYTES} bytes", 413
                    )
                progress_hub.done(job_id)
                slog.add("preview", host=host, detail=f"{share}/{path} bytes={len(data)}", source="wire", ok=True)
                return Response(
                    content=data,
                    media_type=ctype,
                    headers={
                        "X-Preview": "1",
                        "X-Job-Id": job_id,
                        "Content-Disposition": f'inline; filename="{name}"',
                    },
                )

            # Stream download — avoid buffering whole file in RAM for large files
            def gen():
                try:
                    for chunk in smb.iter_file(session, share, path, progress=prog):
                        yield chunk
                    progress_hub.done(job_id)
                    slog.add("download", host=host, detail=f"{share}/{path}", source="wire", ok=True)
                except smb.SMBError as e:
                    progress_hub.error(job_id, e.message)
                    raise

            return StreamingResponse(
                gen(),
                media_type=ctype,
                headers={"Content-Disposition": f'attachment; filename="{name}"', "X-Job-Id": job_id},
            )
        except smb.SMBError as e:
            progress_hub.error(job_id, e.message)
            return error_response(e.code, e.message, status=502)

    @router.get("/zip")
    def zip_folder(
        request: Request,
        host: str = Query(...),
        share: str = Query(...),
        path: str = "",
        port: int = 445,
        username: str = "",
        password: str = "",
        domain: str = "",
        hash: Optional[str] = None,
        guest: bool = False,
        use_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: str = "",
        dc_ip: str = "",
        ccache: str = "",
        sid: str = "",
        smbgui_sid: Optional[str] = Cookie(None, alias=WebSessionStore.COOKIE_NAME),
    ):
        creds, port, _px = _creds_from_fields_or_session(
            host=host,
            port=port,
            username=username,
            password=password,
            domain=domain,
            hash=hash,
            guest=guest,
            use_kerberos=use_kerberos,
            aes_key=aes_key,
            kdc_host=kdc_host,
            dc_ip=dc_ip,
            ccache=ccache,
            sid=sid,
            request=request,
            cookie_sid=smbgui_sid,
        )
        try:
            path = normalize_path(path)
        except ValueError as e:
            return error_response("invalid_path", str(e))
        job_id = progress_hub.new_job("zip", host=host, path=f"{share}/{path}")

        def prog(done, total):
            progress_hub.update(job_id, bytes_done=done, message=f"files={done}")

        try:
            session = pool.get(host, port, creds)
            data = smb.zip_folder(session, share, path, progress=prog)
        except smb.SMBError as e:
            progress_hub.error(job_id, e.message)
            return error_response(e.code, e.message, status=502)
        progress_hub.done(job_id)
        name = (path.split("/")[-1] if path else share) + ".zip"
        slog.add("zip", host=host, detail=f"{share}/{path} bytes={len(data)}", source="wire", ok=True)
        return Response(
            content=data,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{name}"', "X-Job-Id": job_id},
        )

    @router.post("/upload")
    async def upload(
        host: str = Form(...),
        share: str = Form(...),
        path: str = Form(""),
        port: int = Form(445),
        username: str = Form(""),
        password: str = Form(""),
        domain: str = Form(""),
        hash: Optional[str] = Form(None),
        guest: bool = Form(False),
        use_kerberos: bool = Form(False),
        aes_key: str = Form(""),
        kdc_host: str = Form(""),
        dc_ip: str = Form(""),
        ccache: str = Form(""),
        job_id: Optional[str] = Form(None),
        file: UploadFile = File(...),
        smbgui_sid: Optional[str] = Cookie(None, alias=WebSessionStore.COOKIE_NAME),
    ):
        creds, port, _px = _creds_from_fields_or_session(
            host=host, port=port, username=username, password=password, domain=domain,
            hash=hash, guest=guest, use_kerberos=use_kerberos, aes_key=aes_key,
            kdc_host=kdc_host, dc_ip=dc_ip, ccache=ccache, cookie_sid=smbgui_sid,
        )
        try:
            dest_dir = normalize_path(path)
        except ValueError as e:
            return error_response("invalid_path", str(e))
        filename = file.filename or "upload.bin"
        dest = f"{dest_dir}/{filename}" if dest_dir else filename
        data = await file.read()
        jid = job_id or progress_hub.new_job("upload", host=host, path=f"{share}/{dest}", total=len(data))
        progress_hub.update(jid, bytes_total=len(data))

        def prog(done, total):
            progress_hub.update(jid, bytes_done=done, bytes_total=total)

        try:
            session = pool.get(host, port, creds)
            size = smb.upload_file(session, share, dest, data, progress=prog)
        except smb.SMBError as e:
            progress_hub.error(jid, e.message)
            slog.add("upload", host=host, detail=str(e), source="wire", ok=False, error=e.message)
            return error_response(e.code, e.message, status=502)

        cache.invalidate(host, share, dest_dir, creds.fingerprint())
        try:
            entries = smb.list_directory(session, share, dest_dir)
            cache.put(host, share, dest_dir, creds.fingerprint(), entries)
        except Exception:
            pass
        progress_hub.done(jid)
        slog.add("upload", host=host, detail=f"{share}/{dest} bytes={size}", source="wire", ok=True)
        return {"ok": True, "path": dest, "size": size, "job_id": jid}

    @router.post("/mkdir")
    def api_mkdir(body: PathBody):
        creds = _creds_from_body(body)
        path = normalize_path(body.path)
        if not path:
            return error_response("invalid_request", "path is required")
        try:
            session = pool.get(body.host, body.port, creds)
            smb.mkdir(session, body.share, path)
        except smb.SMBError as e:
            return error_response(e.code, e.message, status=502)
        cache.invalidate(body.host, body.share, path, creds.fingerprint())
        slog.add("mkdir", host=body.host, detail=f"{body.share}/{path}", source="wire", ok=True)
        return {"ok": True, "path": path}

    @router.post("/delete")
    def api_delete(body: DeleteBody):
        creds = _creds_from_body(body)
        path = normalize_path(body.path)
        if not path:
            return error_response("invalid_request", "path is required")
        try:
            session = pool.get(body.host, body.port, creds)
            if body.recursive and body.is_dir:
                n = smb.delete_tree(session, body.share, path)
            else:
                smb.delete_path(session, body.share, path, is_dir=body.is_dir)
                n = 1
        except smb.SMBError as e:
            return error_response(e.code, e.message, status=502)
        cache.invalidate_subtree(body.host, body.share, path, creds.fingerprint())
        slog.add("delete", host=body.host, detail=f"{body.share}/{path} n={n}", source="wire", ok=True)
        return {"ok": True, "path": path, "deleted": n}

    @router.post("/rename")
    def api_rename(body: RenameBody):
        creds = _creds_from_body(body)
        old_path = normalize_path(body.path)
        new_path = normalize_path(body.new_path)
        if not old_path or not new_path:
            return error_response("invalid_request", "path and new_path are required")
        try:
            session = pool.get(body.host, body.port, creds)
            smb.rename(session, body.share, old_path, new_path)
        except smb.SMBError as e:
            return error_response(e.code, e.message, status=502)
        cache.invalidate(body.host, body.share, old_path, creds.fingerprint())
        cache.invalidate(body.host, body.share, new_path, creds.fingerprint())
        slog.add("rename", host=body.host, detail=f"{body.share}/{old_path} -> {new_path}", source="wire", ok=True)
        return {"ok": True, "path": old_path, "new_path": new_path}

    @router.post("/copy")
    def api_copy(body: CopyMoveBody):
        creds = _creds_from_body(body)
        try:
            session = pool.get(body.host, body.port, creds)
            if body.action == "move":
                smb.move_file(session, body.src_share, body.src_path, body.dst_share, body.dst_path)
            else:
                smb.copy_file(session, body.src_share, body.src_path, body.dst_share, body.dst_path)
        except smb.SMBError as e:
            return error_response(e.code, e.message, status=502)
        cache.invalidate(body.host, body.src_share, body.src_path, creds.fingerprint())
        cache.invalidate(body.host, body.dst_share, body.dst_path, creds.fingerprint())
        slog.add(
            body.action,
            host=body.host,
            detail=f"{body.src_share}/{body.src_path} -> {body.dst_share}/{body.dst_path}",
            source="wire",
            ok=True,
        )
        return {"ok": True, "action": body.action}

    @router.post("/bulk")
    def api_bulk(body: BulkBody):
        creds = _creds_from_body(body)
        try:
            session = pool.get(body.host, body.port, creds)
        except smb.SMBError as e:
            return error_response(e.code, e.message, status=502)
        results = []
        if body.action == "delete":
            for item in body.paths:
                p = normalize_path(item.get("path", ""))
                is_dir = bool(item.get("is_dir"))
                try:
                    if is_dir:
                        n = smb.delete_tree(session, body.share, p)
                    else:
                        smb.delete_path(session, body.share, p, is_dir=False)
                        n = 1
                    cache.invalidate_subtree(body.host, body.share, p, creds.fingerprint())
                    results.append({"path": p, "ok": True, "deleted": n})
                except smb.SMBError as e:
                    results.append({"path": p, "ok": False, "error": e.message})
            return {"ok": True, "action": "delete", "results": results}
        if body.action == "download_zip":
            # Zip selected files into one archive
            import io, zipfile

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for item in body.paths:
                    p = normalize_path(item.get("path", ""))
                    if item.get("is_dir"):
                        data = smb.zip_folder(session, body.share, p)
                        zf.writestr((p.split("/")[-1] or "folder") + ".zip", data)
                    else:
                        data = smb.download_file(session, body.share, p)
                        zf.writestr(p.split("/")[-1], data)
            slog.add("bulk_zip", host=body.host, detail=f"n={len(body.paths)}", source="wire", ok=True)
            return Response(
                content=buf.getvalue(),
                media_type="application/zip",
                headers={"Content-Disposition": 'attachment; filename="selection.zip"'},
            )
        return error_response("invalid_request", f"unknown bulk action {body.action}")

    @router.get("/properties")
    def properties(
        request: Request,
        host: str = Query(...),
        share: str = Query(...),
        path: str = Query(...),
        port: int = 445,
        username: str = "",
        password: str = "",
        domain: str = "",
        hash: Optional[str] = None,
        guest: bool = False,
        use_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: str = "",
        dc_ip: str = "",
        ccache: str = "",
        sid: str = "",
        smbgui_sid: Optional[str] = Cookie(None, alias=WebSessionStore.COOKIE_NAME),
    ):
        creds, port, _px = _creds_from_fields_or_session(
            host=host, port=port, username=username, password=password, domain=domain,
            hash=hash, guest=guest, use_kerberos=use_kerberos, aes_key=aes_key,
            kdc_host=kdc_host, dc_ip=dc_ip, ccache=ccache, sid=sid,
            request=request, cookie_sid=smbgui_sid,
        )
        try:
            path = normalize_path(path)
        except ValueError as e:
            return error_response("invalid_path", str(e))
        try:
            session = pool.get(host, port, creds)
            props = smb.get_properties(session, share, path)
        except smb.SMBError as e:
            return error_response(e.code, e.message, status=502)
        return props.to_dict()

    @router.get("/search")
    def search(
        request: Request,
        host: str = Query(...),
        q: str = Query(...),
        share: Optional[str] = None,
        username: str = "",
        password: str = "",
        domain: str = "",
        hash: Optional[str] = None,
        guest: bool = False,
        use_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: str = "",
        dc_ip: str = "",
        ccache: str = "",
        sid: str = "",
        limit: int = 200,
        smbgui_sid: Optional[str] = Cookie(None, alias=WebSessionStore.COOKIE_NAME),
    ):
        creds, _port, _px = _creds_from_fields_or_session(
            host=host, username=username, password=password, domain=domain,
            hash=hash, guest=guest, use_kerberos=use_kerberos, aes_key=aes_key,
            kdc_host=kdc_host, dc_ip=dc_ip, ccache=ccache, sid=sid,
            request=request, cookie_sid=smbgui_sid,
        )
        hits = cache.search(host, q, cred_fp=creds.fingerprint(), share=share, limit=limit, use_fts=True)
        slog.add("search", host=host, detail=f"q={q!r} hits={len(hits)}", source="cache", ok=True)
        return {"host": host, "query": q, "hits": hits, "from_cache": True, "engine": "fts"}

    @router.get("/cache/status")
    def cache_status(host: Optional[str] = None):
        return cache.status(host=host)

    @router.get("/cache/tree")
    def cache_tree(host: str = Query(...), cred_fp: Optional[str] = None):
        listings = cache.load_host_tree(host, cred_fp=cred_fp)
        return {"host": host, "listings": [L.to_dict() for L in listings]}

    @router.post("/cache/clear")
    def cache_clear(body: ClearCacheBody):
        cache.clear_host(body.host)
        slog.add("cache_clear", host=body.host, detail="cleared", source="local", ok=True)
        return {"ok": True, "host": body.host}

    @router.post("/cache/settings")
    def cache_settings(body: SettingsBody):
        if body.ttl is not None:
            cache.set_ttl(body.ttl)
        if body.max_listings is not None:
            cache.set_max_listings(body.max_listings)
        rel = body.model_dump(exclude_none=True)
        rel = {k: v for k, v in rel.items() if k not in ("ttl", "max_listings")}
        if rel:
            reliability_settings.update_from_dict(rel)
            pool.reliability = reliability_settings
        return {
            "ok": True,
            "ttl": cache.default_ttl,
            "max_listings": cache.max_listings,
            "reliability": reliability_settings.to_dict(),
        }

    @router.get("/cache/export")
    def cache_export(host: str = Query(...)):
        data = cache.export_host(host)
        return Response(
            content=data,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="cache_{host}.zip"'},
        )

    @router.post("/cache/import")
    async def cache_import(host: str = Form(...), file: UploadFile = File(...)):
        data = await file.read()
        try:
            info = cache.import_host(host, data)
        except Exception as e:
            return error_response("import_failed", str(e))
        return {"ok": True, **info}

    @router.get("/log")
    def get_log(limit: int = 200):
        return {"entries": slog.list(limit=limit)}

    @router.get("/session")
    def session_info(host: str = Query(...)):
        meta = last_conn.get(host.lower())
        if not meta:
            return error_response("not_found", "no session meta for host", status=404)
        safe = {k: v for k, v in meta.items() if k not in ("password", "hash", "aes_key")}
        return safe


    @router.get("/export/listing")
    def export_listing(
        request: Request,
        host: str = Query(...),
        share: str = Query(...),
        path: str = "",
        format: str = Query("csv"),
        recursive: bool = False,
        max_depth: int = 8,
        max_dirs: int = 2000,
        use_cache: bool = True,
        port: int = 445,
        username: str = "",
        password: str = "",
        domain: str = "",
        hash: Optional[str] = None,
        guest: bool = False,
        use_kerberos: bool = False,
        aes_key: str = "",
        kdc_host: str = "",
        dc_ip: str = "",
        ccache: str = "",
        sid: str = "",
        smbgui_sid: Optional[str] = Cookie(None, alias=WebSessionStore.COOKIE_NAME),
    ):
        """Export folder listing as CSV or JSON (optionally recursive, bounded)."""
        try:
            fmt = normalize_format(format)
        except ValueError as e:
            return error_response("invalid_request", str(e))
        if not is_browsable_share(share):
            return error_response("not_browsable", f"{share} is not exportable", 400)

        creds, port, _px = _creds_from_fields_or_session(
            host=host, port=port, username=username, password=password, domain=domain,
            hash=hash, guest=guest, use_kerberos=use_kerberos, aes_key=aes_key,
            kdc_host=kdc_host, dc_ip=dc_ip, ccache=ccache, sid=sid,
            request=request, cookie_sid=smbgui_sid,
        )
        try:
            path = normalize_path(path)
        except ValueError as e:
            return error_response("invalid_path", str(e))
        rows: list = []

        def collect_from_cache_or_wire(dirpath: str):
            if use_cache:
                cached = cache.get(host, share, dirpath, creds.fingerprint(), allow_stale=True)
                if cached is not None:
                    return cached.entries, True
            session = pool.get(host, port, creds)
            entries = smb.list_directory(session, share, dirpath)
            cache.put(host, share, dirpath, creds.fingerprint(), entries)
            return entries, False

        try:
            if not recursive:
                entries, from_cache = collect_from_cache_or_wire(path)
                rows = rows_from_listing(share, path, entries)
            else:
                # Prefer walking via SMB with same caps; use cache when available for each dir
                session = pool.get(host, port, creds)
                dirs_done = 0
                for dirpath, entries in smb.walk_directories(
                    session, share, path, max_depth=max_depth, max_dirs=max_dirs
                ):
                    cache.put(host, share, dirpath, creds.fingerprint(), entries)
                    rows.extend(rows_from_listing(share, dirpath, entries))
                    dirs_done += 1
                from_cache = False
        except smb.SMBError as e:
            return error_response(e.code, e.message, status=502)

        filename = export_filename(share, path, fmt)
        if fmt == "csv":
            body = to_csv(rows)
            media = "text/csv; charset=utf-8"
        else:
            body = to_json(rows)
            media = "application/json"
        slog.add(
            "export_listing",
            host=host,
            detail=f"{share}/{path} fmt={fmt} recursive={recursive} rows={len(rows)}",
            source="cache" if use_cache else "wire",
            ok=True,
        )
        return Response(
            content=body.encode("utf-8"),
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Row-Count": str(len(rows)),
            },
        )

    @router.get("/shares/classify")
    def shares_classify(name: str = Query(...)):
        """Classify a share name (admin/hidden/ipc/drive) without connecting."""
        return classify_share(name)


    @router.get("/status")
    def get_status():
        """Latest operator activity snapshot."""
        return activity.snapshot()

    @router.get("/status/history")
    def get_status_history(limit: int = 50):
        return {"events": activity.history(limit=limit)}

    @router.get("/reliability")
    def get_reliability():
        return reliability_settings.to_dict()

    @router.post("/reliability")
    def set_reliability(body: SettingsBody):
        d = body.model_dump(exclude_none=True)
        # cache ttl still handled separately below
        rel = {k: v for k, v in d.items() if k not in ("ttl", "max_listings")}
        if rel:
            reliability_settings.update_from_dict(rel)
            pool.reliability = reliability_settings
        if body.ttl is not None:
            cache.set_ttl(body.ttl)
        if body.max_listings is not None:
            cache.set_max_listings(body.max_listings)
        slog.add("reliability", detail=str(reliability_settings.to_dict()), source="local", ok=True)
        return {"ok": True, "reliability": reliability_settings.to_dict(), "ttl": cache.default_ttl}

    @router.get("/jobs")
    def list_jobs(limit: int = 50):
        return {"jobs": job_manager.list(limit=limit)}

    @router.get("/jobs/{job_id}")
    def get_job(job_id: str):
        job = job_manager.get(job_id)
        if not job:
            return error_response("not_found", "job not found", 404)
        info = job.to_dict()
        # For completed download jobs, expose a fetch URL hint
        if job.status == "done" and isinstance(job.result, dict):
            info["result"] = {k: v for k, v in job.result.items() if k != "data"}
            if "local_path" in job.result:
                info["download_url"] = f"/api/jobs/{job_id}/result"
        return info

    @router.post("/jobs/{job_id}/cancel")
    def cancel_job(job_id: str):
        if not job_manager.cancel(job_id):
            return error_response("not_found", "job not found", 404)
        slog.add("job_cancel", detail=job_id, source="local", ok=True)
        activity.set("waiting", f"cancel requested for job {job_id}", severity="warn", action="cancel")
        return {"ok": True, "job_id": job_id}

    @router.get("/jobs/{job_id}/result")
    def job_result(job_id: str):
        job = job_manager.get(job_id)
        if not job or job.status != "done":
            return error_response("not_ready", "job not done or missing", 404)
        result = job.result or {}
        if isinstance(result, dict) and result.get("local_path"):
            path = FsPath(result["local_path"])
            if not path.exists():
                return error_response("not_found", "result file missing", 404)
            name = result.get("filename") or path.name

            def file_iter(p: FsPath, chunk: int = 1024 * 1024):
                with open(p, "rb") as fh:
                    while True:
                        block = fh.read(chunk)
                        if not block:
                            break
                        yield block

            return StreamingResponse(
                file_iter(path),
                media_type="application/octet-stream",
                headers={"Content-Disposition": f'attachment; filename="{name}"'},
            )
        if isinstance(result, (bytes, bytearray)):
            return Response(content=bytes(result), media_type="application/octet-stream")
        return result

    @router.post("/transfer/download")
    def start_download_job(body: PathBody, request: Request, smbgui_sid: Optional[str] = Cookie(None, alias=WebSessionStore.COOKIE_NAME)):
        """Start a background resumable download (hours-safe; poll /api/jobs/{id})."""
        creds = _creds_from_body_or_session(body, request, smbgui_sid)
        proxy = _proxy_from_body(body)
        try:
            path = normalize_path(body.path)
        except ValueError as e:
            return error_response("invalid_path", str(e))
        if not path:
            return error_response("invalid_request", "path required")
        filename = path.split("/")[-1]

        def work(job):
            dest = parts_dir() / f"{job.job_id}_{body.host}_{body.share}_{filename}".replace("/", "_").replace("\\", "_")
            activity.set("downloading", f"downloading {path}…", host=body.host, path=f"{body.share}/{path}", action="download")
            def on_retry(n, e, d):
                job_manager.update_progress(job, job.bytes_done, message=f"retry {n} waiting {d:.1f}s: {e}")
                activity.set(
                    "retrying",
                    f"retry {n}/{reliability_settings.max_retries} ({e}) — backing off {d:.0f}s",
                    severity="warn",
                    host=body.host,
                    path=f"{body.share}/{path}",
                    action="download",
                    detail=str(e),
                )

            def do(session):
                def prog(done, total):
                    total_v = total if total and total > 0 else job.bytes_total
                    job_manager.update_progress(job, done, total_v, message="downloading")
                    pct = round(100.0 * done / total_v, 1) if total_v and total_v > 0 else None
                    activity.set(
                        "downloading",
                        f"downloading {filename}" + (f" {pct}%" if pct is not None else f" {done} bytes"),
                        host=body.host,
                        path=f"{body.share}/{path}",
                        action="download",
                        progress=pct,
                    )
                return smb.download_resumable(
                    session,
                    body.share,
                    path,
                    dest,
                    progress=prog,
                    cancel_check=job.cancel_event.is_set,
                )

            local = pool.run(
                body.host, body.port, creds, do,
                operation=f"download:{path}",
                proxy=proxy,
                on_retry=on_retry,
            )
            activity.idle(f"download done: {filename}")
            return {"local_path": str(local), "filename": filename}

        job = job_manager.submit("download", work, host=body.host, path=f"{body.share}/{path}")
        return {"ok": True, "job_id": job.job_id, "status": job.status}

    @router.post("/transfer/upload")
    async def start_upload_job(
        host: str = Form(...),
        share: str = Form(...),
        path: str = Form(""),
        port: int = Form(445),
        username: str = Form(""),
        password: str = Form(""),
        domain: str = Form(""),
        hash: Optional[str] = Form(None),
        guest: bool = Form(False),
        proxy_type: str = Form(""),
        proxy_host: str = Form(""),
        proxy_port: int = Form(0),
        proxy_user: str = Form(""),
        proxy_pass: str = Form(""),
        resume_offset: int = Form(0),
        file: UploadFile = File(...),
        smbgui_sid: Optional[str] = Cookie(None, alias=WebSessionStore.COOKIE_NAME),
    ):
        """Accept file to disk then background resumable upload (hours-safe)."""
        from .auth import credentials_from_fields as cff
        # Prefer cookie/session when form omits secrets
        token = smbgui_sid or ""
        if token and not (password or hash or username or guest):
            sess = web_sessions.get_for_host(token, host)
            if sess is not None:
                creds = sess.creds
                port = sess.port or port
            else:
                creds = cff(username, password, domain, hash, guest)
        else:
            creds = cff(username, password, domain, hash, guest)
        proxy = proxy_from_fields(proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass) if proxy_host else None
        try:
            dest_dir = normalize_path(path)
        except ValueError as e:
            return error_response("invalid_path", str(e))
        filename = file.filename or "upload.bin"
        remote = f"{dest_dir}/{filename}" if dest_dir else filename
        # Stream upload body to a unique temp path (avoid part-name collisions)
        import uuid
        staging = parts_dir() / f"upload_staging_{uuid.uuid4().hex}_{filename}".replace("/", "_").replace("\\", "_")
        size = 0
        with open(staging, "wb") as fh:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                size += len(chunk)

        def work(job):
            local = parts_dir() / f"{job.job_id}_upload_{host}_{filename}".replace("/", "_").replace("\\", "_")
            try:
                staging.replace(local)
            except Exception:
                local = staging
            job.bytes_total = size
            activity.set("uploading", f"uploading {filename}…", host=host, path=f"{share}/{remote}", action="upload")
            def on_retry(n, e, d):
                # On retry, let upload_resumable query remote EOF (remote_offset=0 + query_remote)
                job_manager.update_progress(job, job.bytes_done, size, message=f"retry {n} waiting {d:.1f}s")
                activity.set(
                    "retrying",
                    f"retry {n}/{reliability_settings.max_retries} ({e}) — backing off {d:.0f}s",
                    severity="warn",
                    host=host,
                    path=f"{share}/{remote}",
                    action="upload",
                )

            def do(session):
                def prog(done, total):
                    job_manager.update_progress(job, done, total, message="uploading")
                    pct = round(100.0 * done / total, 1) if total else None
                    activity.set(
                        "uploading",
                        f"uploading {filename}" + (f" {pct}%" if pct is not None else ""),
                        host=host,
                        path=f"{share}/{remote}",
                        action="upload",
                        progress=pct,
                    )
                # First attempt may use client resume_offset; retries query remote EOF
                offset = int(resume_offset or 0)
                if job.bytes_done and job.bytes_done > 0:
                    offset = 0  # force remote query after partial progress / reconnect
                return smb.upload_resumable(
                    session, share, remote, local,
                    progress=prog,
                    cancel_check=job.cancel_event.is_set,
                    remote_offset=offset,
                    query_remote=True,
                )

            n = pool.run(host, port, creds, do, operation=f"upload:{remote}", proxy=proxy, on_retry=on_retry)
            cache.invalidate(host, share, dest_dir, creds.fingerprint())
            activity.idle(f"upload done: {filename}")
            return {"remote_path": remote, "size": n, "local_path": str(local)}

        job = job_manager.submit("upload", work, host=host, path=f"{share}/{remote}", bytes_total=size)
        return {"ok": True, "job_id": job.job_id, "status": job.status, "size": size}

    # --- bookmarks ---
    @router.get("/bookmarks")
    def get_bookmarks():
        return {"bookmarks": bookmarks.list_bookmarks(), "recent": bookmarks.list_recent()}

    @router.post("/bookmarks")
    def add_bookmark(body: BookmarkAddBody):
        bm = bookmarks.add_bookmark(**body.model_dump())
        return {"ok": True, "bookmark": bm}

    @router.delete("/bookmarks/{bookmark_id}")
    def del_bookmark(bookmark_id: str):
        ok = bookmarks.remove_bookmark(bookmark_id)
        if not ok:
            return error_response("not_found", "bookmark not found", 404)
        return {"ok": True}

    @router.get("/progress/{job_id}")
    def get_progress(job_id: str):
        ev = progress_hub.get(job_id)
        if not ev:
            return error_response("not_found", "job not found", 404)
        return ev

    return router


def create_ws_router() -> APIRouter:
    """WebSocket progress + operator status streaming."""
    router = APIRouter()

    @router.websocket("/ws/status")
    async def ws_status(websocket: WebSocket):
        await websocket.accept()
        q = activity.subscribe()
        try:
            await websocket.send_json({"type": "hello", "channel": "status"})
            # send current snapshot
            await websocket.send_json({"type": "status", **activity.snapshot()})
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=20.0)
                    await websocket.send_json(msg)
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "ping", "ts": time.time(), "status": activity.snapshot()})
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            activity.unsubscribe(q)

    @router.websocket("/ws/progress")
    async def ws_progress(websocket: WebSocket):
        await websocket.accept()
        job_id = websocket.query_params.get("job_id")
        q = progress_hub.subscribe(job_id)
        try:
            # send hello
            await websocket.send_json({"type": "hello", "job_id": job_id})
            while True:
                # Also accept client pings / new job subscriptions
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=1.0)
                    await websocket.send_json({"type": "progress", **msg})
                except asyncio.TimeoutError:
                    try:
                        # non-blocking check for client messages
                        import asyncio as _aio

                        try:
                            client_msg = await _aio.wait_for(websocket.receive_json(), timeout=0.01)
                            if isinstance(client_msg, dict) and client_msg.get("subscribe"):
                                progress_hub.unsubscribe(q, job_id)
                                job_id = client_msg["subscribe"]
                                q = progress_hub.subscribe(job_id)
                        except Exception:
                            pass
                    except Exception:
                        pass
                    await websocket.send_json({"type": "ping", "ts": time.time()})
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            progress_hub.unsubscribe(q, job_id)

    return router


# late import for asyncio used in ws
import asyncio  # noqa: E402
