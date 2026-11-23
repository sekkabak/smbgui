"""Resumable transfer offset logic + reconnect-on-dead-connection (mocked)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.auth import credentials_from_fields
from app.config import ReliabilitySettings
from app.proxy import ProxyConfig
from app.smb_client import SMBPool, SMBError, download_resumable, upload_resumable


def test_download_resumable_resumes_at_offset(tmp_path: Path):
    session = MagicMock()
    # Simulate getFile calling callback with remaining data when offset given
    remote = b"HELLO-WORLD-RESUME-TEST"

    def fake_getFile(share, path, callback, shareAccessMode=1, mode=1, offset=0, password=None):
        callback(remote[offset:])

    session.conn.getFile.side_effect = fake_getFile
    session.lock = __import__("threading").RLock()

    dest = tmp_path / "out.bin"
    part = Path(str(dest) + ".part")
    # Pre-seed first 6 bytes as if previous attempt wrote them
    part.write_bytes(remote[:6])

    download_resumable(session, "share", "file.bin", dest, known_size=len(remote))
    assert dest.read_bytes() == remote
    assert session.conn.getFile.call_args.kwargs.get("offset") == 6 or session.conn.getFile.call_args[1].get("offset") == 6


def test_upload_resumable_uses_offset(tmp_path: Path):
    session = MagicMock()
    session.lock = __import__("threading").RLock()
    src = tmp_path / "src.bin"
    payload = b"ABCDEFGHIJ"
    src.write_bytes(payload)
    seen = {}

    def fake_putFile(share, path, callback, shareAccessMode=1, mode=5, offset=0, password=None):
        seen["offset"] = offset
        seen["mode"] = mode
        # drain callback like Impacket would
        while True:
            chunk = callback(3)
            if not chunk:
                break

    session.conn.putFile.side_effect = fake_putFile
    upload_resumable(session, "share", "remote.bin", src, remote_offset=4)
    assert seen["offset"] == 4
    assert seen["mode"] == 3  # FILE_OPEN_IF


def test_pool_reconnects_on_dead_connection():
    settings = ReliabilitySettings(
        max_retries=2,
        base_delay=0.001,
        max_delay=0.01,
        jitter=0,
        auto_reconnect=True,
        proxy=ProxyConfig(enabled=False),
    )
    pool = SMBPool(reliability=settings)
    creds = credentials_from_fields(username="u", password="p")

    mock_conn = MagicMock()
    mock_conn.getServerName.return_value = "X"
    mock_conn.getSMBServer.return_value = MagicMock(echo=MagicMock(return_value=True))
    calls = {"auth": 0, "op": 0}

    def auth(conn, host, creds):
        calls["auth"] += 1

    with patch.object(SMBPool, "_authenticate", side_effect=auth):
        with patch("app.smb_client.SMBConnection", return_value=mock_conn):
            with patch("app.smb_client.proxy_socket_context"):
                session = pool.connect("h", 445, creds)

                def op(sess):
                    calls["op"] += 1
                    if calls["op"] == 1:
                        raise ConnectionResetError("connection reset by peer")
                    return "ok"

                # First get succeeds; run() should reconnect and retry op
                result = pool.run("h", 445, creds, op, operation="test")
                assert result == "ok"
                assert calls["op"] == 2
