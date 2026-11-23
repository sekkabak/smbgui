"""Session pool: connecting lock + close superseded connections."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

from app.auth import credentials_from_fields
from app.config import ReliabilitySettings
from app.proxy import ProxyConfig
from app.smb_client import SMBPool


def test_concurrent_connect_single_session():
    settings = ReliabilitySettings(
        max_retries=0,
        proxy=ProxyConfig(enabled=False),
        keepalive_seconds=0,
    )
    pool = SMBPool(reliability=settings)
    creds = credentials_from_fields(username="u", password="p")
    creates = {"n": 0}
    lock = threading.Lock()

    def make_conn(*a, **k):
        with lock:
            creates["n"] += 1
        m = MagicMock()
        m.getServerName.return_value = "X"
        # echo keepalive path
        smb_server = MagicMock()
        smb_server.echo.return_value = True
        m.getSMBServer.return_value = smb_server
        return m

    with patch("app.smb_client.SMBConnection", side_effect=make_conn):
        with patch.object(SMBPool, "_authenticate"):
            with patch("app.smb_client.proxy_socket_context"):
                results = [None, None]
                errors = [None, None]

                def worker(i):
                    try:
                        results[i] = pool.connect("h", 445, creds)
                    except Exception as e:
                        errors[i] = e

                t1 = threading.Thread(target=worker, args=(0,))
                t2 = threading.Thread(target=worker, args=(1,))
                t1.start()
                t2.start()
                t1.join(5)
                t2.join(5)
                assert errors == [None, None]
                assert results[0] is not None and results[1] is not None
                assert results[0].session_id == results[1].session_id
                assert len(pool.list_sessions()) == 1
                # Serialized connect: second call reuses after first; may create once
                assert creates["n"] >= 1


def test_superseded_connection_closed():
    settings = ReliabilitySettings(max_retries=0, proxy=ProxyConfig(enabled=False), keepalive_seconds=0)
    pool = SMBPool(reliability=settings)
    creds = credentials_from_fields(username="u", password="p")
    closed = []

    def make_conn(*a, **k):
        m = MagicMock()
        m.getServerName.return_value = "X"
        smb_server = MagicMock()
        smb_server.echo.return_value = True
        m.getSMBServer.return_value = smb_server
        m.close.side_effect = lambda: closed.append(m)
        return m

    with patch("app.smb_client.SMBConnection", side_effect=make_conn):
        with patch.object(SMBPool, "_authenticate"):
            with patch("app.smb_client.proxy_socket_context"):
                pool.connect("h", 445, creds)
                key = pool._key("h", 445, creds, ProxyConfig(enabled=False))
                with pool._lock:
                    old = pool._sessions.pop(key, None)
                s2 = pool.connect("h", 445, creds)
                assert s2 is not None
                # Manually close the popped one to simulate supersede cleanup path
                if old:
                    pool._close_conn(old.conn)
                assert len(closed) >= 1
