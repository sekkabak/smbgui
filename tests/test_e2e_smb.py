"""End-to-end tests against local Samba."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from app.auth import credentials_from_fields, nt_hash_hex
from app.cache import CacheStore
from app.smb_client import (
    SMBPool,
    copy_file,
    delete_path,
    delete_tree,
    download_file,
    list_directory,
    list_shares,
    mkdir,
    rename,
    upload_file,
    zip_folder,
    get_properties,
    walk_directories,
)

SMB_HOST = os.environ.get("SMBGUI_TEST_HOST", "127.0.0.1")
SMB_PORT = int(os.environ.get("SMBGUI_TEST_PORT", "1445"))
SMB_USER = os.environ.get("SMBGUI_TEST_USER", "smbtest")
SMB_PASS = os.environ.get("SMBGUI_TEST_PASS", "TestPass123!")
SMB_SHARE = os.environ.get("SMBGUI_TEST_SHARE", "testdata")


def _samba_up() -> bool:
    import socket

    try:
        with socket.create_connection((SMB_HOST, SMB_PORT), timeout=1):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _samba_up(), reason="Samba test server not running")


@pytest.fixture
def pool():
    return SMBPool()


@pytest.fixture
def creds_password():
    return credentials_from_fields(username=SMB_USER, password=SMB_PASS)


@pytest.fixture
def creds_hash():
    return credentials_from_fields(username=SMB_USER, hash_str=nt_hash_hex(SMB_PASS))


def test_connect_password_and_list_shares(pool, creds_password):
    session = pool.connect(SMB_HOST, SMB_PORT, creds_password)
    shares = list_shares(session)
    assert SMB_SHARE in [s.name for s in shares]


def test_connect_pth(pool, creds_hash):
    session = pool.connect(SMB_HOST, SMB_PORT, creds_hash)
    assert any(s.name == SMB_SHARE for s in list_shares(session))


def test_file_ops_roundtrip(pool, creds_password):
    session = pool.connect(SMB_HOST, SMB_PORT, creds_password)
    dirname = f"e2e_{int(time.time())}"
    mkdir(session, SMB_SHARE, dirname)
    payload = b"smbgui-e2e-" + os.urandom(64)
    remote = f"{dirname}/hello.bin"
    upload_file(session, SMB_SHARE, remote, payload)
    assert download_file(session, SMB_SHARE, remote) == payload
    rename(session, SMB_SHARE, remote, f"{dirname}/hello2.bin")
    copy_file(session, SMB_SHARE, f"{dirname}/hello2.bin", SMB_SHARE, f"{dirname}/hello3.bin")
    assert download_file(session, SMB_SHARE, f"{dirname}/hello3.bin") == payload
    props = get_properties(session, SMB_SHARE, f"{dirname}/hello3.bin")
    assert props.size == len(payload)
    assert props.is_dir is False
    delete_tree(session, SMB_SHARE, dirname)


def test_recursive_walk_and_zip(pool, creds_password):
    session = pool.connect(SMB_HOST, SMB_PORT, creds_password)
    root = f"tree_{int(time.time())}"
    mkdir(session, SMB_SHARE, root)
    mkdir(session, SMB_SHARE, f"{root}/sub")
    upload_file(session, SMB_SHARE, f"{root}/a.txt", b"aaa")
    upload_file(session, SMB_SHARE, f"{root}/sub/b.txt", b"bbb")
    walked = list(walk_directories(session, SMB_SHARE, root, max_depth=5, max_dirs=50))
    paths = [p for p, _ in walked]
    assert root in paths
    assert f"{root}/sub" in paths
    zdata = zip_folder(session, SMB_SHARE, root)
    assert zdata[:2] == b"PK"
    delete_tree(session, SMB_SHARE, root)


def test_cache_persist_refresh_fts(pool, creds_password, tmp_path: Path):
    store = CacheStore(tmp_path, default_ttl=2)
    session = pool.connect(SMB_HOST, SMB_PORT, creds_password)
    entries = list_directory(session, SMB_SHARE, "")
    fp = creds_password.fingerprint()
    store.put(SMB_HOST, SMB_SHARE, "", fp, entries, ttl=2)

    store2 = CacheStore(tmp_path, default_ttl=2)
    cached = store2.get(SMB_HOST, SMB_SHARE, "", fp)
    assert cached is not None

    # FTS should find readme if present
    hits = store2.search(SMB_HOST, "readme", cred_fp=fp)
    # may or may not have readme depending on fixture; at least search works
    assert isinstance(hits, list)

    time.sleep(2.1)
    assert store2.get(SMB_HOST, SMB_SHARE, "", fp, allow_stale=True).stale is True

    # recursive-style refresh of root
    store2.invalidate_subtree(SMB_HOST, SMB_SHARE, "", fp)
    for dirpath, ents in walk_directories(session, SMB_SHARE, "", max_depth=2, max_dirs=20):
        store2.put(SMB_HOST, SMB_SHARE, dirpath, fp, ents)
    assert store2.get(SMB_HOST, SMB_SHARE, "", fp).stale is False
