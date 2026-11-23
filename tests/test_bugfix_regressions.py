"""Regression tests for the combined critical/high/medium bugfix list."""

from __future__ import annotations

import queue
import socket
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.auth import credentials_from_fields
from app.cache import normalize_path
from app.proxy import ProxyConfig, proxy_from_fields, proxy_socket_context
from app.resilience import classify_error
from app.smb_client import SMBError, SMBPool, iter_file, upload_resumable


def test_normalize_allows_dotdot_prefix_name():
    assert normalize_path("..foo") == "..foo"
    assert normalize_path("dir/..bar.txt") == "dir/..bar.txt"


def test_normalize_rejects_wildcards():
    with pytest.raises(ValueError, match="wildcard"):
        normalize_path("foo/*.txt")
    with pytest.raises(ValueError, match="wildcard"):
        normalize_path("a?/b")


def test_unknown_status_is_fatal_not_hours_of_retry():
    assert classify_error(Exception("STATUS_SOME_OBSCURE_CODE")) == "fatal"
    assert classify_error(Exception("STATUS_IO_TIMEOUT")) == "retriable"
    assert classify_error(Exception("STATUS_DISK_FULL")) == "fatal"


def test_upload_query_access_denied_does_not_overwrite_from_zero(tmp_path: Path):
    session = MagicMock()
    session.lock = threading.RLock()
    src = tmp_path / "src.bin"
    src.write_bytes(b"ABCDEFGHIJ")
    put_calls = []

    def fake_putFile(share, path, callback, shareAccessMode=1, mode=5, offset=0, password=None):
        put_calls.append({"mode": mode, "offset": offset})
        while True:
            chunk = callback(4)
            if not chunk:
                break

    session.conn.putFile.side_effect = fake_putFile

    with patch(
        "app.smb_client.query_remote_size",
        side_effect=SMBError("ACCESS_DENIED", code="smb_error"),
    ):
        with pytest.raises(SMBError, match="ACCESS_DENIED"):
            upload_resumable(session, "share", "remote.bin", src, remote_offset=0, query_remote=True)
    assert put_calls == []  # must not fall through to OVERWRITE_IF from 0


def test_upload_query_not_found_starts_fresh(tmp_path: Path):
    session = MagicMock()
    session.lock = threading.RLock()
    src = tmp_path / "src.bin"
    src.write_bytes(b"ABCDEFGHIJ")
    put_calls = []

    def fake_putFile(share, path, callback, shareAccessMode=1, mode=5, offset=0, password=None):
        put_calls.append({"mode": mode, "offset": offset})
        while True:
            chunk = callback(4)
            if not chunk:
                break

    session.conn.putFile.side_effect = fake_putFile

    with patch(
        "app.smb_client.query_remote_size",
        side_effect=SMBError("missing", code="not_found"),
    ):
        with patch("app.smb_client.set_remote_eof"):
            upload_resumable(session, "share", "remote.bin", src, remote_offset=0, query_remote=True)
    assert put_calls[0]["mode"] == 5
    assert put_calls[0]["offset"] == 0


def test_set_remote_eof_failure_fails_upload(tmp_path: Path):
    session = MagicMock()
    session.lock = threading.RLock()
    src = tmp_path / "src.bin"
    src.write_bytes(b"ABCDEFGHIJ")

    def fake_putFile(share, path, callback, shareAccessMode=1, mode=5, offset=0, password=None):
        while True:
            chunk = callback(4)
            if not chunk:
                break

    session.conn.putFile.side_effect = fake_putFile

    with patch("app.smb_client.query_remote_size", side_effect=SMBError("x", code="not_found")):
        with patch("app.smb_client.set_remote_eof", side_effect=SMBError("eof failed", code="smb_error")):
            with pytest.raises(SMBError, match="eof failed"):
                upload_resumable(session, "share", "remote.bin", src, remote_offset=0, query_remote=True)


def test_keepalive_skips_when_session_lock_held():
    pool = SMBPool()
    mock_conn = MagicMock()
    echo = MagicMock()
    mock_conn.getSMBServer.return_value = MagicMock(echo=echo)
    session = MagicMock()
    session.conn = mock_conn
    session.lock = threading.RLock()
    session.last_used = 0.0
    held = threading.Event()
    release = threading.Event()

    def holder():
        session.lock.acquire()
        held.set()
        release.wait(timeout=5)
        session.lock.release()

    t = threading.Thread(target=holder)
    t.start()
    assert held.wait(timeout=2)
    try:
        pool._keepalive(session)
    finally:
        release.set()
        t.join(timeout=2)
    echo.assert_not_called()


def test_keepalive_runs_when_lock_free():
    pool = SMBPool()
    mock_conn = MagicMock()
    echo = MagicMock()
    mock_conn.getSMBServer.return_value = MagicMock(echo=echo)
    session = MagicMock()
    session.conn = mock_conn
    session.lock = threading.RLock()
    session.last_used = 0.0
    pool._keepalive(session)
    echo.assert_called_once()


def test_iter_file_abort_releases_lock():
    session = MagicMock()
    session.lock = threading.RLock()
    started = threading.Event()
    in_callback = threading.Event()

    def fake_getFile(share, path, callback, **kwargs):
        started.set()
        # Produce enough chunks to fill a small queue and block
        for i in range(20):
            in_callback.set()
            callback(b"x" * 64)
        return None

    session.conn.getFile.side_effect = fake_getFile

    gen = iter_file(session, "share", "f.bin", chunk_queue_size=1)
    # Pull one chunk then abort
    assert next(gen) == b"x" * 64
    gen.close()
    # Lock must be free after abort (worker exits)
    deadline = time.time() + 3
    while time.time() < deadline:
        if session.lock.acquire(blocking=False):
            session.lock.release()
            break
        time.sleep(0.05)
    else:
        pytest.fail("session.lock still held after iter_file abort")


def test_proxy_socket_context_is_thread_local():
    """Other threads must not inherit socks.socksocket during an active proxy context."""
    proxy = proxy_from_fields("socks5", "127.0.0.1", 1080)
    results = {}

    def other_thread():
        # Give main thread time to enter the context
        time.sleep(0.05)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        results["other_is_socks"] = type(s).__name__ == "socksocket"
        results["other_isinstance"] = isinstance(s, socket.socket)
        s.close()

    t = threading.Thread(target=other_thread)
    with proxy_socket_context(proxy):
        t.start()
        main_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        results["main_is_socks"] = type(main_sock).__name__ == "socksocket"
        main_sock.close()
        t.join(timeout=2)

    assert results.get("main_is_socks") is True
    assert results.get("other_is_socks") is False
    assert results.get("other_isinstance") is True


def test_guest_login_reraises_network_errors():
    pool = SMBPool()
    creds = credentials_from_fields(guest=True)
    mock_conn = MagicMock()
    mock_conn.login.side_effect = ConnectionResetError("connection reset by peer")
    with pytest.raises(ConnectionResetError):
        pool._authenticate(mock_conn, "h", creds)


def test_guest_login_falls_back_on_logon_failure():
    pool = SMBPool()
    creds = credentials_from_fields(guest=True)
    mock_conn = MagicMock()
    mock_conn.login.side_effect = [
        Exception("STATUS_LOGON_FAILURE"),
        None,  # anonymous
    ]
    pool._authenticate(mock_conn, "h", creds)
    assert mock_conn.login.call_count == 2
    assert mock_conn.login.call_args_list[1].args[0] == ""


def test_kerberos_usecache_true_only_with_ccache():
    pool = SMBPool()
    creds = credentials_from_fields(
        username="alice",
        domain="CORP",
        password="x",
        use_kerberos=True,
        ccache="/tmp/fake_ccache",
        kdc_host="dc",
    )
    mock_conn = MagicMock()
    with patch.dict("os.environ", {}, clear=False):
        # Ensure no ambient KRB5CCNAME from outer env for this assertion path
        import os

        old = os.environ.pop("KRB5CCNAME", None)
        try:
            pool._authenticate(mock_conn, "h", creds)
        finally:
            if old is not None:
                os.environ["KRB5CCNAME"] = old
    assert mock_conn.kerberosLogin.call_args.kwargs.get("useCache") is True
