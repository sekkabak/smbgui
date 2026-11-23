"""Proxy wiring tests: live SOCKS TCP to Samba + Impacket uses proxy context."""

from __future__ import annotations

import select
import socket
import struct
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from app.auth import credentials_from_fields
from app.config import ReliabilitySettings
from app.proxy import ProxyConfig, create_proxied_connection, proxy_socket_context
from app.smb_client import SMBPool

_RealSocket = socket.socket
_real_create_connection = socket.create_connection

SMB_HOST = "127.0.0.1"
SMB_PORT = 1445


def _samba_up() -> bool:
    try:
        with _real_create_connection((SMB_HOST, SMB_PORT), timeout=1):
            return True
    except OSError:
        return False


class _TinySocks5(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._sock = _RealSocket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(20)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except Exception:
            pass

    def run(self):
        self._sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except Exception:
                continue
            threading.Thread(target=self._serve_client, args=(client,), daemon=True).start()

    def _serve_client(self, client):
        remote = None
        try:
            client.settimeout(15)
            _ = client.recv(256)
            client.sendall(b"\x05\x00")
            req = b""
            while len(req) < 10:
                chunk = client.recv(256)
                if not chunk:
                    return
                req += chunk
            if req[3] != 1:
                return
            addr = socket.inet_ntoa(req[4:8])
            port = struct.unpack("!H", req[8:10])[0]
            remote = _real_create_connection((addr, port), timeout=10)
            client.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
            sockets = [client, remote]
            while True:
                r, _, x = select.select(sockets, [], sockets, 60)
                if x:
                    break
                if not r:
                    continue
                for s in r:
                    other = remote if s is client else client
                    try:
                        data = s.recv(65536)
                    except OSError:
                        data = b""
                    if not data:
                        return
                    other.sendall(data)
        except Exception:
            pass
        finally:
            for s in (client, remote):
                if s is None:
                    continue
                try:
                    s.close()
                except Exception:
                    pass


@pytest.mark.skipif(not _samba_up(), reason="Samba not running")
def test_live_socks5_tcp_to_samba():
    """SOCKS5 TCP path to Samba works (Impacket dialect over tiny relay is flaky — covered via mock)."""
    srv = _TinySocks5()
    srv.start()
    time.sleep(0.1)
    try:
        px = ProxyConfig(enabled=True, proxy_type="socks5", host="127.0.0.1", port=srv.port)
        s = create_proxied_connection(px, SMB_HOST, SMB_PORT, timeout=5)
        peer = s.getpeername()
        s.close()
        assert peer[1] == SMB_PORT
    finally:
        srv.stop()


def test_impacket_connect_enters_proxy_context():
    """SMBPool.connect must enter proxy_socket_context when proxy enabled."""
    settings = ReliabilitySettings(
        connect_timeout=5,
        max_retries=0,
        proxy=ProxyConfig(enabled=True, proxy_type="socks5", host="127.0.0.1", port=1080),
    )
    pool = SMBPool(reliability=settings)
    creds = credentials_from_fields(username="u", password="p")
    mock_conn = MagicMock()
    entered = {"n": 0}

    from contextlib import contextmanager

    @contextmanager
    def fake_ctx(proxy):
        entered["n"] += 1
        assert proxy.enabled and proxy.host == "127.0.0.1"
        yield

    with patch("app.smb_client.proxy_socket_context", fake_ctx):
        with patch("app.smb_client.SMBConnection", return_value=mock_conn):
            with patch.object(SMBPool, "_authenticate"):
                pool.connect("fileserver", 445, creds, proxy=settings.proxy)
    assert entered["n"] >= 1
