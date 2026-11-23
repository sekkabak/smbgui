"""Impacket SMBConnection wrapper with pooling, Kerberos, copy/move, zip, properties."""

from __future__ import annotations

import io
import os
import threading
import time
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Iterator, Optional

from impacket.smbconnection import SMBConnection, SessionError

from .auth import Credentials, spn_to_remote_name
from .cache import ListingEntry, normalize_path, paths_equal
from .config import ReliabilitySettings, settings as global_settings
from .logging_util import setup_logging, log_event
from .proxy import ProxyConfig, proxy_socket_context, resolve_proxy
from .activity import activity
from .resilience import (
    is_connection_dead_error,
    with_retry,
)

logger = setup_logging()

# Serialize KRB5CCNAME mutations across concurrent Kerberos logins.
_krb5_env_lock = threading.RLock()


@dataclass
class ShareInfo:
    name: str
    remark: str
    type: int
    is_hidden: bool = False
    is_admin: bool = False
    is_ipc: bool = False
    browsable: bool = True
    drive_letter: str | None = None

    def to_dict(self):
        return asdict(self)


@dataclass
class FileProperties:
    share: str
    path: str
    name: str
    size: int
    is_dir: bool
    mtime: float
    atime: float
    ctime: float
    attributes: int
    attributes_human: list[str]
    owner: str = ""
    group: str = ""
    acl: str = ""

    def to_dict(self):
        return asdict(self)


ATTR_FLAGS = [
    (0x01, "READONLY"),
    (0x02, "HIDDEN"),
    (0x04, "SYSTEM"),
    (0x10, "DIRECTORY"),
    (0x20, "ARCHIVE"),
    (0x80, "NORMAL"),
    (0x100, "TEMPORARY"),
    (0x800, "COMPRESSED"),
]


class SMBError(Exception):
    def __init__(self, message: str, code: str = "smb_error"):
        super().__init__(message)
        self.code = code
        self.message = message


def _raise_smb(op: str, e: BaseException) -> None:
    msg = str(e)
    upper = msg.upper()
    if "PATH_NOT_COVERED" in upper or "STATUS_PATH_NOT_COVERED" in upper:
        raise SMBError(
            f"{op}: DFS PATH_NOT_COVERED — target is on another DFS referral; "
            "smbgui does not follow DFS referrals (use the concrete file-server host/share)",
            code="dfs_path_not_covered",
        ) from e
    if isinstance(e, SMBError):
        raise e
    raise SMBError(f"{op} failed: {e}") from e


class PooledSession:
    def __init__(self, host: str, port: int, creds: Credentials, conn: SMBConnection):
        self.host = host
        self.port = port
        self.creds = creds
        self.conn = conn
        self.lock = threading.RLock()
        self.connected_at = time.time()
        self.last_used = time.time()
        self.session_id = f"{host.lower()}:{port}:{creds.fingerprint()}"


class SMBPool:
    """One reused SMBConnection per (host, port, cred fingerprint). Multi-host aware.

    Supports long timeouts, proxy sockets, retry, and auto-reconnect.
    Per-key connect locks prevent duplicate concurrent connects and close superseded sockets.
    """

    def __init__(self, reliability: ReliabilitySettings | None = None):
        self._sessions: dict[str, PooledSession] = {}
        self._lock = threading.RLock()
        self._key_locks: dict[str, threading.Lock] = {}
        self.reliability = reliability or global_settings

    def _key(self, host: str, port: int, creds: Credentials, proxy: ProxyConfig | None = None) -> str:
        px = (proxy or self.reliability.proxy).fingerprint()
        return f"{host.lower()}:{port}:{creds.fingerprint()}:{px}"

    def _key_lock(self, key: str) -> threading.Lock:
        with self._lock:
            lock = self._key_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[key] = lock
            return lock

    @staticmethod
    def _close_conn(conn) -> None:
        try:
            conn.close()
        except Exception:
            pass

    def list_sessions(self) -> list[dict]:
        with self._lock:
            out = []
            for s in self._sessions.values():
                out.append(
                    {
                        "session_id": s.session_id,
                        "host": s.host,
                        "port": s.port,
                        "user": s.creds.display_user(),
                        "auth_mode": s.creds.auth_mode(),
                        "cred_fp": s.creds.fingerprint(),
                        "connected_at": s.connected_at,
                        "last_used": s.last_used,
                    }
                )
            return out

    def connect(
        self,
        host: str,
        port: int,
        creds: Credentials,
        timeout: float | None = None,
        proxy: ProxyConfig | None = None,
    ) -> PooledSession:
        proxy = resolve_proxy(proxy or self.reliability.proxy)
        key = self._key(host, port, creds, proxy)
        connect_timeout = timeout if timeout is not None else self.reliability.connect_timeout
        # Impacket expects a numeric timeout; use a huge value for "infinite"
        smb_timeout = connect_timeout if connect_timeout and connect_timeout > 0 else 60 * 60 * 24 * 7

        with self._key_lock(key):
            with self._lock:
                existing = self._sessions.get(key)
                if existing is not None:
                    try:
                        self._keepalive(existing)
                        existing.last_used = time.time()
                        return existing
                    except Exception:
                        self._close_conn(existing.conn)
                        self._sessions.pop(key, None)

            # TCP always to the file server host. dc_ip/kdc_host are Kerberos-only.
            remote_name = host
            if creds.use_kerberos and creds.spn:
                remote_name = spn_to_remote_name(creds.spn) or host

            def _open():
                with proxy_socket_context(proxy):
                    conn = SMBConnection(
                        remoteName=remote_name,
                        remoteHost=host,
                        sess_port=port,
                        timeout=int(smb_timeout) if smb_timeout else 3600,
                    )
                    self._apply_io_timeout(conn)
                    self._authenticate(conn, host, creds)
                    return conn

            conn = with_retry(
                _open,
                self.reliability.retry_policy(),
                operation=f"connect:{host}",
                on_retry=lambda n, e, d: log_event(
                    logger, "connect_retry", host=host, action="connect", error=str(e)
                ),
            )
            session = PooledSession(host=host, port=port, creds=creds, conn=conn)
            session.proxy = proxy  # type: ignore[attr-defined]
            with self._lock:
                prev = self._sessions.get(key)
                self._sessions[key] = session
                if prev is not None and prev is not session:
                    self._close_conn(prev.conn)
            return session

    def _apply_io_timeout(self, conn: SMBConnection) -> None:
        io_t = self.reliability.effective_io_timeout()
        try:
            # 0 / None => effectively no timeout (week)
            val = io_t if io_t is not None else (60 * 60 * 24 * 7)
            conn.setTimeout(val)
        except Exception as e:
            logger.debug("setTimeout failed: %s", e)

    def _keepalive(self, session: PooledSession) -> None:
        """Cheap live check: SMB2/3 echo when available, else list IPC$.

        Must not race getFile/putFile on the same connection — take session.lock
        non-blocking and skip if an op is already in flight.
        """
        acquired = session.lock.acquire(blocking=False)
        if not acquired:
            return
        try:
            server = session.conn.getSMBServer()
            if hasattr(server, "echo"):
                server.echo()
            else:
                # SMB1 fallback — forces a wire round-trip via tree connect to IPC$
                try:
                    tid = session.conn.connectTree("IPC$")
                    session.conn.disconnectTree(tid)
                except Exception:
                    _ = session.conn.getServerOS()
            session.last_used = time.time()
        finally:
            session.lock.release()

    def _authenticate(self, conn: SMBConnection, host: str, creds: Credentials) -> None:
        if creds.is_guest:
            # Guest account (not null session). Fall back to anonymous only on
            # logon/access failures — re-raise network/protocol errors.
            try:
                conn.login(creds.username or "Guest", creds.password or "", creds.domain or "")
            except Exception as e:
                msg = f"{e}".upper()
                logonish = any(
                    s in msg
                    for s in (
                        "STATUS_LOGON_FAILURE",
                        "STATUS_WRONG_PASSWORD",
                        "STATUS_ACCOUNT",
                        "STATUS_ACCESS_DENIED",
                        "STATUS_LOGON_TYPE_NOT_GRANTED",
                        "STATUS_NO_SUCH_USER",
                        "STATUS_USER_EXISTS",  # some servers
                        "AUTHENTICATION",
                        "LOGON_FAILURE",
                    )
                )
                if not logonish:
                    raise
                conn.login("", "")
            return
        if creds.use_kerberos:
            with _krb5_env_lock:
                old_cc = os.environ.get("KRB5CCNAME")
                try:
                    if creds.ccache:
                        os.environ["KRB5CCNAME"] = creds.ccache
                    kdc = creds.kdc_host or creds.dc_ip or None
                    # Only use ticket cache when we have an explicit ccache (or
                    # env already set outside). Always-True can pick a wrong TGT.
                    use_cache = bool(creds.ccache) or bool(os.environ.get("KRB5CCNAME"))
                    conn.kerberosLogin(
                        creds.username,
                        creds.password or "",
                        creds.domain or "",
                        lmhash=creds.lmhash or "",
                        nthash=creds.nthash or "",
                        aesKey=creds.aes_key or "",
                        kdcHost=kdc,
                        useCache=use_cache,
                    )
                finally:
                    if creds.ccache:
                        if old_cc is None:
                            os.environ.pop("KRB5CCNAME", None)
                        else:
                            os.environ["KRB5CCNAME"] = old_cc
            return
        if creds.is_hash:
            conn.login(
                creds.username,
                creds.password or "",
                creds.domain or "",
                lmhash=creds.lmhash,
                nthash=creds.nthash,
            )
            return
        conn.login(creds.username, creds.password or "", creds.domain or "")

    def get(
        self,
        host: str,
        port: int,
        creds: Credentials,
        proxy: ProxyConfig | None = None,
    ) -> PooledSession:
        proxy = resolve_proxy(proxy or self.reliability.proxy)
        key = self._key(host, port, creds, proxy)
        need_connect = False
        dead = False
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                need_connect = True
            else:
                try:
                    ka = self.reliability.keepalive_seconds
                    if ka and ka > 0 and (time.time() - session.last_used) > ka:
                        self._keepalive(session)
                    session.last_used = time.time()
                    return session
                except Exception:
                    dead = True
        if need_connect:
            return self.connect(host, port, creds, proxy=proxy)
        if dead and self.reliability.auto_reconnect:
            log_event(logger, "auto_reconnect", host=host, action="get")
            return self.reconnect(host, port, creds, proxy=proxy)
        raise SMBError("session dead and auto_reconnect disabled", code="connection_error")

    def reconnect(
        self,
        host: str,
        port: int,
        creds: Credentials,
        proxy: ProxyConfig | None = None,
    ) -> PooledSession:
        self.disconnect(host, port, creds, proxy=proxy)
        return self.connect(host, port, creds, proxy=proxy)

    def disconnect(
        self,
        host: str,
        port: int,
        creds: Credentials,
        proxy: ProxyConfig | None = None,
    ) -> None:
        proxy = resolve_proxy(proxy or self.reliability.proxy)
        key = self._key(host, port, creds, proxy)
        # Also try legacy key without proxy for backward compat
        with self._lock:
            for k in (key, f"{host.lower()}:{port}:{creds.fingerprint()}"):
                session = self._sessions.pop(k, None)
                if session:
                    self._close_conn(session.conn)

    def disconnect_host(self, host: str) -> None:
        host = host.lower()
        with self._lock:
            for key in list(self._sessions):
                if key.startswith(f"{host}:"):
                    session = self._sessions.pop(key)
                    self._close_conn(session.conn)

    def run(
        self,
        host: str,
        port: int,
        creds: Credentials,
        fn: Callable,
        *,
        operation: str = "smb_op",
        proxy: ProxyConfig | None = None,
        on_retry=None,
    ):
        """Run fn(session) with retry + auto-reconnect on dead connections."""

        def attempt():
            session = self.get(host, port, creds, proxy=proxy)
            try:
                return fn(session)
            except Exception as e:
                if self.reliability.auto_reconnect and is_connection_dead_error(e):
                    log_event(logger, "reconnect_mid_op", host=host, action=operation, error=str(e))
                    activity.set(
                        "reconnecting",
                        f"reconnecting to {host}… ({e})",
                        severity="warn",
                        host=host,
                        action=operation,
                        detail=str(e),
                    )
                    session = self.reconnect(host, port, creds, proxy=proxy)
                    return fn(session)
                raise

        return with_retry(
            attempt,
            self.reliability.retry_policy(),
            operation=operation,
            on_retry=on_retry,
        )



def _share_field(share_obj, key: str, default=""):
    try:
        val = share_obj[key]
    except Exception:
        return default
    if isinstance(val, bytes):
        return val.decode("utf-16le", errors="ignore").rstrip("\x00")
    if isinstance(val, str):
        return val.rstrip("\x00")
    return val if val is not None else default


def list_shares(
    session: PooledSession,
    *,
    include_hidden: bool = True,
    include_ipc: bool = True,
) -> list[ShareInfo]:
    """List shares. Hidden/admin $-shares are included by default; IPC$ is included as non-browsable."""
    from .shares_util import classify_share

    with session.lock:
        try:
            raw = session.conn.listShares()
        except Exception as e:
            raise SMBError(f"listShares failed: {e}") from e
    out: list[ShareInfo] = []
    for s in raw:
        name = _share_field(s, "shi1_netname", "")
        if not name:
            continue
        remark = _share_field(s, "shi1_remark", "")
        try:
            typ = int(s["shi1_type"])
        except Exception:
            typ = 0
        flags = classify_share(name)
        if flags["is_ipc"] and not include_ipc:
            continue
        if flags["is_hidden"] and not flags["is_ipc"] and not include_hidden:
            continue
        out.append(
            ShareInfo(
                name=name,
                remark=remark or "",
                type=typ,
                is_hidden=flags["is_hidden"],
                is_admin=flags["is_admin"],
                is_ipc=flags["is_ipc"],
                browsable=flags["browsable"],
                drive_letter=flags["drive_letter"],
            )
        )
    # Prefer browsable shares first, then alpha
    out.sort(key=lambda s: (not s.browsable, s.is_hidden, s.name.lower()))
    return out


def share_to_dict(s: ShareInfo) -> dict:
    return s.to_dict()


def _file_times(info) -> tuple[float, float, float]:
    mtime = atime = ctime = 0.0
    try:
        if hasattr(info, "get_mtime_epoch"):
            mtime = float(info.get_mtime_epoch() or 0)
        if hasattr(info, "get_atime_epoch"):
            atime = float(info.get_atime_epoch() or 0)
        if hasattr(info, "get_ctime_epoch"):
            ctime = float(info.get_ctime_epoch() or 0)
    except Exception:
        pass
    return mtime, atime, ctime


def _attrs(info) -> int:
    try:
        if hasattr(info, "get_attributes"):
            return int(info.get_attributes() or 0)
    except Exception:
        pass
    return 0


def _attrs_human(attrs: int) -> list[str]:
    return [name for flag, name in ATTR_FLAGS if attrs & flag]


def list_directory(session: PooledSession, share: str, path: str = "") -> list[ListingEntry]:
    path = normalize_path(path)
    pattern = f"{path}/*" if path else "*"
    pattern = pattern.replace("/", "\\")
    with session.lock:
        try:
            files = session.conn.listPath(share, pattern)
        except Exception as e:
            _raise_smb("listPath", e)

    entries: list[ListingEntry] = []
    for f in files:
        name = f.get_longname()
        if name in (".", ".."):
            continue
        is_dir = bool(f.is_directory())
        size = int(f.get_filesize() or 0)
        mtime, atime, ctime = _file_times(f)
        attrs = _attrs(f)
        entries.append(
            ListingEntry(
                name=name,
                size=size,
                is_dir=is_dir,
                mtime=mtime,
                atime=atime,
                ctime=ctime,
                attributes=attrs,
            )
        )
    entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
    return entries



def download_file(
    session: PooledSession,
    share: str,
    path: str,
    progress: Optional[Callable[[int, int], None]] = None,
) -> bytes:
    """Download entire file into memory (small files). Prefer download_resumable / iter_file for large."""
    path = normalize_path(path).replace("/", "\\")
    buf = io.BytesIO()
    total = [0]

    def callback(data: bytes):
        buf.write(data)
        total[0] += len(data)
        if progress:
            progress(total[0], -1)

    with session.lock:
        try:
            session.conn.getFile(share, path, callback)
        except Exception as e:
            _raise_smb("getFile", e)
    return buf.getvalue()


def iter_file(
    session: PooledSession,
    share: str,
    path: str,
    *,
    chunk_queue_size: int = 8,
    progress: Optional[Callable[[int, int], None]] = None,
) -> Iterator[bytes]:
    """
    Stream a remote file as chunks without holding the whole file in RAM.

    Holds session.lock for the duration of the transfer (Impacket getFile is
    single-connection / callback-driven). Prefer background jobs for multi-hour
    downloads so the HTTP layer does not block.

    On client abort (GeneratorExit), set a cancel flag so the worker stops
    blocking on the bounded queue and releases session.lock in ``finally``.
    """
    import queue as queue_mod

    smb_path = normalize_path(path).replace("/", "\\")
    q: queue_mod.Queue = queue_mod.Queue(maxsize=max(1, chunk_queue_size))
    done_flag = object()
    err_box: list[BaseException] = []
    total = [0]
    aborted = threading.Event()

    def callback(data: bytes):
        if aborted.is_set():
            raise SMBError("download aborted by client", code="cancelled")
        total[0] += len(data)
        if progress:
            progress(total[0], -1)
        # Drop-on-abort / timeout so a cancelled consumer cannot wedge the pool forever
        while True:
            if aborted.is_set():
                raise SMBError("download aborted by client", code="cancelled")
            try:
                q.put(data, timeout=0.5)
                return
            except queue_mod.Full:
                continue

    def worker():
        try:
            session.lock.acquire()
            try:
                if aborted.is_set():
                    return
                session.conn.getFile(share, smb_path, callback)
            finally:
                session.lock.release()
        except BaseException as e:
            if not aborted.is_set():
                err_box.append(e)
        finally:
            try:
                q.put(done_flag, timeout=1)
            except Exception:
                pass

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    try:
        while True:
            item = q.get()
            if item is done_flag:
                break
            yield item
    except GeneratorExit:
        aborted.set()
        # Drain so a blocked put can complete and the worker can exit
        try:
            while True:
                q.get_nowait()
        except Exception:
            pass
        raise
    finally:
        aborted.set()
        t.join(timeout=5)
    if err_box and not aborted.is_set():
        _raise_smb("getFile", err_box[0])
    if err_box and aborted.is_set():
        # Swallow cancel-induced errors after abort
        code = getattr(err_box[0], "code", "")
        if code != "cancelled" and "abort" not in str(err_box[0]).lower():
            pass


def download_resumable(
    session: PooledSession,
    share: str,
    path: str,
    dest_path: Path,
    progress: Optional[Callable[[int, int], None]] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    known_size: int = -1,
) -> Path:
    """
    Download to dest_path using a .part file, resuming from existing bytes via getFile(offset=...).
    Returns final path.
    """
    dest_path = Path(dest_path)
    part_path = Path(str(dest_path) + ".part")
    offset = part_path.stat().st_size if part_path.exists() else 0
    smb_path = normalize_path(path).replace("/", "\\")

    mode = "ab" if offset else "wb"
    with open(part_path, mode) as fh:
        done = [offset]

        def callback(data: bytes):
            if cancel_check and cancel_check():
                raise SMBError("cancelled", code="cancelled")
            fh.write(data)
            done[0] += len(data)
            if progress:
                progress(done[0], known_size)

        with session.lock:
            try:
                session.conn.getFile(share, smb_path, callback, offset=offset)
            except Exception as e:
                _raise_smb(f"getFile@offset={offset}", e)

    part_path.replace(dest_path)
    return dest_path


def upload_file(
    session: PooledSession,
    share: str,
    path: str,
    data: bytes,
    progress: Optional[Callable[[int, int], None]] = None,
) -> int:
    path = normalize_path(path).replace("/", "\\")
    bio = io.BytesIO(data)
    size = len(data)
    sent = [0]

    def callback(buf_size: int):
        chunk = bio.read(buf_size)
        sent[0] += len(chunk)
        if progress:
            progress(sent[0], size)
        return chunk

    with session.lock:
        try:
            session.conn.putFile(share, path, callback)
        except Exception as e:
            _raise_smb("putFile", e)
    return size


def query_remote_size(session: PooledSession, share: str, path: str) -> int:
    """Return remote EndOfFile / filesize for path, or raise if missing."""
    path_n = normalize_path(path)
    smb_path = path_n.replace("/", "\\")
    with session.lock:
        try:
            files = session.conn.listPath(share, smb_path)
        except Exception as e:
            msg = f"{e}".upper()
            if any(
                s in msg
                for s in (
                    "OBJECT_NAME_NOT_FOUND",
                    "NO_SUCH_FILE",
                    "OBJECT_PATH_NOT_FOUND",
                    "STATUS_NO_SUCH_FILE",
                )
            ):
                raise SMBError(f"remote path not found: {share}/{path_n}", code="not_found") from e
            _raise_smb("query_remote_size", e)
    if not files:
        raise SMBError(f"remote path not found: {share}/{path_n}", code="not_found")
    return int(files[0].get_filesize() or 0)


def set_remote_eof(session: PooledSession, share: str, path: str, size: int) -> None:
    """Set remote file EndOfFile to ``size`` (needed after resumable putFile)."""
    from impacket import smb as smb_mod
    from impacket import smb3structs
    from impacket.smb import SMBSetFileEndOfFileInfo
    from impacket.smb3structs import FILE_WRITE_ATTRIBUTES
    from impacket.smbconnection import (
        FILE_NON_DIRECTORY_FILE,
        FILE_OPEN,
        FILE_SHARE_READ,
        FILE_WRITE_DATA,
    )

    smb_path = normalize_path(path).replace("/", "\\")
    info = SMBSetFileEndOfFileInfo()
    info["EndOfFile"] = int(size)
    with session.lock:
        tree_id = session.conn.connectTree(share)
        file_id = None
        try:
            file_id = session.conn.openFile(
                tree_id,
                smb_path,
                desiredAccess=FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
                shareMode=FILE_SHARE_READ,
                creationOption=FILE_NON_DIRECTORY_FILE,
                creationDisposition=FILE_OPEN,
            )
            dialect = session.conn.getDialect()
            if dialect == smb_mod.SMB_DIALECT:
                session.conn.setInfo(tree_id, file_id, smb_mod.SMB_SET_FILE_END_OF_FILE_INFO, info)
            else:
                session.conn.setInfo(tree_id, file_id, smb3structs.SMB2_FILE_END_OF_FILE_INFO, info)
        except Exception as e:
            _raise_smb("set_remote_eof", e)
        finally:
            if file_id is not None:
                try:
                    session.conn.closeFile(tree_id, file_id)
                except Exception:
                    pass
            try:
                session.conn.disconnectTree(tree_id)
            except Exception:
                pass


def upload_resumable(
    session: PooledSession,
    share: str,
    path: str,
    src_path: Path,
    progress: Optional[Callable[[int, int], None]] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    remote_offset: int = 0,
    *,
    query_remote: bool = True,
) -> int:
    """
    Upload local file, optionally resuming at remote_offset (putFile offset=).

    When ``query_remote`` is True and remote_offset is 0, probe remote EndOfFile
    to advance the checkpoint after a reconnect. After a successful write, set
    remote EOF to the intended local file size.
    """
    src_path = Path(src_path)
    size = src_path.stat().st_size
    smb_path = normalize_path(path).replace("/", "\\")
    offset = max(0, int(remote_offset))

    if query_remote and offset == 0:
        try:
            remote_sz = query_remote_size(session, share, path)
            if 0 < remote_sz < size:
                offset = remote_sz
            elif remote_sz >= size:
                # Already complete — still ensure EOF matches
                set_remote_eof(session, share, path, size)
                if progress:
                    progress(size, size)
                return size
        except SMBError as e:
            # Only treat not-found as start-fresh. Transient/network/ACCESS_DENIED
            # must NOT force FILE_OVERWRITE_IF from offset 0.
            msg = f"{e.message} {e}".upper()
            not_found = (
                e.code == "not_found"
                or "OBJECT_NAME_NOT_FOUND" in msg
                or "NO_SUCH_FILE" in msg
                or "OBJECT_PATH_NOT_FOUND" in msg
                or "STATUS_OBJECT_NAME_NOT_FOUND" in msg
            )
            if not_found:
                offset = 0
            else:
                raise

    if offset > size:
        offset = 0

    with open(src_path, "rb") as fh:
        fh.seek(offset)
        sent = [offset]

        def callback(buf_size: int):
            if cancel_check and cancel_check():
                raise SMBError("cancelled", code="cancelled")
            chunk = fh.read(buf_size)
            sent[0] += len(chunk)
            if progress:
                progress(sent[0], size)
            return chunk

        with session.lock:
            try:
                # mode=3 FILE_OPEN_IF for resume; mode=5 OVERWRITE_IF for fresh
                mode = 3 if offset > 0 else 5
                session.conn.putFile(share, smb_path, callback, mode=mode, offset=offset)
            except Exception as e:
                _raise_smb(f"putFile@offset={offset}", e)

    # Fail the upload if EOF cannot be set — otherwise remote size may be wrong
    set_remote_eof(session, share, path, size)
    return size


def upload_file_stream(
    session: PooledSession,
    share: str,
    path: str,
    reader: Callable[[int], bytes],
    size: int,
    progress: Optional[Callable[[int, int], None]] = None,
) -> int:
    """Upload from a callable reader(buf_size)->bytes (for large/chunked uploads)."""
    path = normalize_path(path).replace("/", "\\")
    sent = [0]

    def callback(buf_size: int):
        chunk = reader(buf_size)
        sent[0] += len(chunk)
        if progress:
            progress(sent[0], size)
        return chunk

    with session.lock:
        try:
            session.conn.putFile(share, path, callback)
        except Exception as e:
            _raise_smb("putFile", e)
    return size


def mkdir(session: PooledSession, share: str, path: str) -> None:
    path = normalize_path(path).replace("/", "\\")
    with session.lock:
        try:
            session.conn.createDirectory(share, path)
        except Exception as e:
            _raise_smb("createDirectory", e)


def delete_path(session: PooledSession, share: str, path: str, is_dir: bool = False) -> None:
    path = normalize_path(path).replace("/", "\\")
    with session.lock:
        try:
            if is_dir:
                session.conn.deleteDirectory(share, path)
            else:
                session.conn.deleteFile(share, path)
        except Exception as e:
            _raise_smb("delete", e)


def delete_tree(session: PooledSession, share: str, path: str) -> int:
    """Recursively delete a directory tree. Returns number of deleted nodes."""
    path = normalize_path(path)
    deleted = 0
    try:
        entries = list_directory(session, share, path)
    except SMBError:
        # maybe it's a file
        delete_path(session, share, path, is_dir=False)
        return 1
    for e in entries:
        child = f"{path}/{e.name}" if path else e.name
        if e.is_dir:
            deleted += delete_tree(session, share, child)
        else:
            delete_path(session, share, child, is_dir=False)
            deleted += 1
    if path:
        delete_path(session, share, path, is_dir=True)
        deleted += 1
    return deleted


def rename(session: PooledSession, share: str, old_path: str, new_path: str) -> None:
    old_path = normalize_path(old_path).replace("/", "\\")
    new_path = normalize_path(new_path).replace("/", "\\")
    with session.lock:
        try:
            session.conn.rename(share, old_path, new_path)
        except Exception as e:
            _raise_smb("rename", e)


def copy_file(
    session: PooledSession,
    src_share: str,
    src_path: str,
    dst_share: str,
    dst_path: str,
    progress: Optional[Callable[[int, int], None]] = None,
) -> int:
    """Server-side-ish copy via download+upload (works across shares)."""
    data = download_file(session, src_share, src_path, progress=progress)
    return upload_file(session, dst_share, dst_path, data, progress=progress)


def move_file(
    session: PooledSession,
    src_share: str,
    src_path: str,
    dst_share: str,
    dst_path: str,
) -> None:
    if src_share == dst_share:
        # Same share: try rename (also handles move within share)
        try:
            rename(session, src_share, src_path, dst_path)
            return
        except SMBError:
            pass
    copy_file(session, src_share, src_path, dst_share, dst_path)
    delete_path(session, src_share, src_path, is_dir=False)


def get_file_info(session: PooledSession, share: str, path: str) -> Optional[ListingEntry]:
    path = normalize_path(path)
    if not path:
        return None
    parts = path.split("/")
    name = parts[-1]
    parent = "/".join(parts[:-1])
    try:
        entries = list_directory(session, share, parent)
    except SMBError:
        return None
    for e in entries:
        if e.name == name or e.name.casefold() == name.casefold():
            return e
        if paths_equal(e.name, name):
            return e
    return None


def get_properties(session: PooledSession, share: str, path: str) -> FileProperties:
    path = normalize_path(path)
    info = get_file_info(session, share, path)
    if info is None:
        raise SMBError(f"path not found: {share}/{path}", code="not_found")
    name = path.split("/")[-1] if path else share
    # Best-effort ACL/owner via queryInfo if available — Impacket support varies;
    # we leave owner/acl empty when not retrievable rather than failing.
    owner = group = acl = ""
    return FileProperties(
        share=share,
        path=path,
        name=name,
        size=info.size,
        is_dir=info.is_dir,
        mtime=info.mtime,
        atime=info.atime,
        ctime=info.ctime,
        attributes=info.attributes,
        attributes_human=_attrs_human(info.attributes),
        owner=owner,
        group=group,
        acl=acl,
    )


def walk_directories(
    session: PooledSession,
    share: str,
    path: str = "",
    max_depth: int = 8,
    max_dirs: int = 2000,
) -> Iterator[tuple[str, list[ListingEntry]]]:
    """Yield (path, entries) breadth-first with depth/count safeguards."""
    path = normalize_path(path)
    queue: list[tuple[str, int]] = [(path, 0)]
    seen = 0
    while queue:
        current, depth = queue.pop(0)
        try:
            entries = list_directory(session, share, current)
        except SMBError:
            continue
        yield current, entries
        seen += 1
        if seen >= max_dirs:
            return
        if depth >= max_depth:
            continue
        for e in entries:
            if e.is_dir:
                child = f"{current}/{e.name}" if current else e.name
                queue.append((child, depth + 1))


def zip_folder(
    session: PooledSession,
    share: str,
    path: str = "",
    max_files: int = 5000,
    max_total_bytes: int = 200 * 1024 * 1024,
    progress: Optional[Callable[[int, int], None]] = None,
) -> bytes:
    """Download a folder tree into an in-memory zip (bounded)."""
    path = normalize_path(path)
    buf = io.BytesIO()
    files_done = 0
    bytes_done = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, entries in walk_directories(session, share, path, max_depth=12, max_dirs=2000):
            for e in entries:
                if e.is_dir:
                    # ensure directory entry
                    rel = f"{dirpath}/{e.name}" if dirpath else e.name
                    if path and rel.startswith(path + "/"):
                        arc = rel[len(path) + 1 :]
                    elif path and rel == path:
                        continue
                    else:
                        arc = rel
                    if arc:
                        zf.writestr(arc.rstrip("/") + "/", b"")
                    continue
                files_done += 1
                if files_done > max_files:
                    raise SMBError("zip exceeds max_files limit", code="too_large")
                full = f"{dirpath}/{e.name}" if dirpath else e.name
                if path and full.startswith(path + "/"):
                    arc = full[len(path) + 1 :]
                else:
                    arc = full if not path else e.name
                data = download_file(session, share, full)
                bytes_done += len(data)
                if bytes_done > max_total_bytes:
                    raise SMBError("zip exceeds max_total_bytes limit", code="too_large")
                zf.writestr(arc, data)
                if progress:
                    progress(files_done, -1)
    return buf.getvalue()
