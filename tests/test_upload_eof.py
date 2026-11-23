"""Upload resume: query remote EOF and set intended size after write."""

from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.smb_client import query_remote_size, set_remote_eof, upload_resumable


def test_query_remote_size_uses_listpath():
    session = MagicMock()
    session.lock = threading.RLock()
    entry = MagicMock()
    entry.get_longname.return_value = "remote.bin"
    entry.get_filesize.return_value = 42
    session.conn.listPath.return_value = [entry]
    assert query_remote_size(session, "share", "dir/remote.bin") == 42


def test_upload_resumable_sets_eof_after_write(tmp_path: Path):
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

    with patch("app.smb_client.set_remote_eof") as set_eof:
        with patch("app.smb_client.query_remote_size", side_effect=Exception("skip")):
            upload_resumable(session, "share", "remote.bin", src, remote_offset=0, query_remote=False)
        set_eof.assert_called_once()
        assert set_eof.call_args.args[3] == 10


def test_set_remote_eof_opens_and_sets_info():
    session = MagicMock()
    session.lock = threading.RLock()
    session.conn.connectTree.return_value = 1
    session.conn.openFile.return_value = 99
    session.conn.getDialect.return_value = "SMB2"
    set_remote_eof(session, "share", "f.bin", 100)
    session.conn.setInfo.assert_called_once()
    session.conn.closeFile.assert_called_once_with(1, 99)
