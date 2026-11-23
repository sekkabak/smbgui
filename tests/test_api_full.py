"""HTTP-level tests for expanded API (requires Samba)."""

from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient

from app.auth import nt_hash_hex
from app.main import app

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
def client():
    return TestClient(app)


def _auth():
    return {"username": SMB_USER, "password": SMB_PASS, "port": SMB_PORT}


def test_api_connect_pth_recursive_search_bulk_zip_bookmarks(client):
    # password connect
    r = client.post("/api/connect", json={"connection": f"{SMB_USER}:{SMB_PASS}@{SMB_HOST}:{SMB_PORT}"})
    assert r.status_code == 200 and r.json()["ok"]

    # PTH
    r = client.post(
        "/api/connect",
        json={"host": SMB_HOST, "port": SMB_PORT, "username": SMB_USER, "hash": nt_hash_hex(SMB_PASS)},
    )
    assert r.json()["auth_mode"] == "pth"

    auth = _auth()
    dirname = f"api_full_{int(time.time())}"
    assert client.post("/api/mkdir", json={"host": SMB_HOST, "share": SMB_SHARE, "path": dirname, **auth}).json()["ok"]
    assert client.post(
        "/api/mkdir", json={"host": SMB_HOST, "share": SMB_SHARE, "path": f"{dirname}/sub", **auth}
    ).json()["ok"]

    files = {"file": ("x.txt", b"hello-full", "text/plain")}
    data = {
        "host": SMB_HOST,
        "share": SMB_SHARE,
        "path": f"{dirname}/sub",
        "username": SMB_USER,
        "password": SMB_PASS,
        "port": str(SMB_PORT),
    }
    assert client.post("/api/upload", data=data, files=files).json()["ok"]

    # recursive refresh
    r = client.post(
        "/api/refresh",
        json={
            "host": SMB_HOST,
            "share": SMB_SHARE,
            "path": dirname,
            "recursive": True,
            "max_depth": 5,
            "max_dirs": 50,
            **auth,
        },
    )
    assert r.status_code == 200
    assert r.json()["scope"] == "recursive"
    assert r.json()["dirs_refreshed"] >= 2
    assert r.json().get("job_id")

    # FTS search
    r = client.get("/api/search", params={"host": SMB_HOST, "q": "x.txt", **auth})
    assert r.json()["engine"] == "fts"
    assert any(h["name"] == "x.txt" for h in r.json()["hits"])

    # properties
    r = client.get(
        "/api/properties",
        params={"host": SMB_HOST, "share": SMB_SHARE, "path": f"{dirname}/sub/x.txt", **auth},
    )
    assert r.json()["size"] == 10

    # copy
    assert client.post(
        "/api/copy",
        json={
            "host": SMB_HOST,
            "src_share": SMB_SHARE,
            "src_path": f"{dirname}/sub/x.txt",
            "dst_share": SMB_SHARE,
            "dst_path": f"{dirname}/y.txt",
            "action": "copy",
            **auth,
        },
    ).json()["ok"]

    # zip folder
    r = client.get("/api/zip", params={"host": SMB_HOST, "share": SMB_SHARE, "path": dirname, **auth})
    assert r.status_code == 200
    assert r.content[:2] == b"PK"

    # bulk delete
    r = client.post(
        "/api/bulk",
        json={
            "host": SMB_HOST,
            "share": SMB_SHARE,
            "action": "delete",
            "paths": [{"path": dirname, "is_dir": True}],
            **auth,
        },
    )
    assert r.json()["ok"]

    # bookmarks persist
    r = client.post(
        "/api/bookmarks",
        json={"label": "t", "host": SMB_HOST, "port": SMB_PORT, "share": SMB_SHARE, "path": "", "username": SMB_USER},
    )
    assert r.json()["ok"]
    bid = r.json()["bookmark"]["id"]
    assert any(b["id"] == bid for b in client.get("/api/bookmarks").json()["bookmarks"])
    assert client.delete(f"/api/bookmarks/{bid}").json()["ok"]

    # cache export
    r = client.get("/api/cache/export", params={"host": SMB_HOST})
    assert r.status_code == 200 and r.content[:2] == b"PK"

    # sessions list
    assert "sessions" in client.get("/api/sessions").json()

    # settings
    assert client.post("/api/cache/settings", json={"ttl": 120}).json()["ttl"] == 120
