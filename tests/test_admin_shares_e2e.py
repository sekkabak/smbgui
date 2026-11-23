"""E2E: hidden admin$ share on local Samba (if present)."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.auth import credentials_from_fields
from app.smb_client import SMBPool, list_shares, list_directory
from app.shares_util import is_admin_share, is_hidden_share

SMB_HOST = os.environ.get("SMBGUI_TEST_HOST", "127.0.0.1")
SMB_PORT = int(os.environ.get("SMBGUI_TEST_PORT", "1445"))
SMB_USER = os.environ.get("SMBGUI_TEST_USER", "smbtest")
SMB_PASS = os.environ.get("SMBGUI_TEST_PASS", "TestPass123!")


def _samba_up() -> bool:
    import socket

    try:
        with socket.create_connection((SMB_HOST, SMB_PORT), timeout=1):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _samba_up(), reason="Samba not running")


def test_list_shares_includes_hidden_admin():
    pool = SMBPool()
    creds = credentials_from_fields(username=SMB_USER, password=SMB_PASS)
    session = pool.connect(SMB_HOST, SMB_PORT, creds)
    shares = list_shares(session, include_hidden=True, include_ipc=True)
    names = {s.name for s in shares}
    # IPC$ should be present as non-browsable when include_ipc
    ipc = [s for s in shares if s.is_ipc]
    assert ipc and ipc[0].browsable is False
    # Our fixture adds admin$
    if "admin$" in names:
        admin = next(s for s in shares if s.name == "admin$")
        assert admin.is_hidden and admin.is_admin and admin.browsable
        entries = list_directory(session, "admin$", "")
        assert any(e.name == "secret.txt" for e in entries)
    else:
        pytest.skip("admin$ share not configured in Samba fixture")


def test_api_export_and_classify():
    c = TestClient(app)
    r = c.post("/api/connect", json={"connection": f"{SMB_USER}:{SMB_PASS}@{SMB_HOST}:{SMB_PORT}"})
    assert r.status_code == 200
    shares = {s["name"]: s for s in r.json()["shares"]}
    # classify endpoint
    assert c.get("/api/shares/classify", params={"name": "C$"}).json()["is_admin"] is True
    assert c.get("/api/shares/classify", params={"name": "IPC$"}).json()["browsable"] is False

    auth = {"username": SMB_USER, "password": SMB_PASS, "port": SMB_PORT}
    # export csv current folder
    r = c.get(
        "/api/export/listing",
        params={"host": SMB_HOST, "share": "testdata", "path": "", "format": "csv", **auth},
    )
    assert r.status_code == 200
    assert "text/csv" in r.headers.get("content-type", "")
    body = r.content.decode()
    assert body.startswith("share,path,name,type,")
    assert "readme.txt" in body or "subdir" in body

    r = c.get(
        "/api/export/listing",
        params={
            "host": SMB_HOST,
            "share": "testdata",
            "path": "",
            "format": "json",
            "recursive": True,
            "max_depth": 3,
            **auth,
        },
    )
    assert r.status_code == 200
    data = r.json() if False else __import__("json").loads(r.content)
    assert isinstance(data, list)
    assert any(row.get("name") for row in data)

    # IPC$ list should fail gracefully
    r = c.get("/api/list", params={"host": SMB_HOST, "share": "IPC$", "path": "", **auth})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "not_browsable"

    # Direct browse admin$ if present
    if "admin$" in shares:
        r = c.get("/api/list", params={"host": SMB_HOST, "share": "admin$", "path": "", **auth})
        assert r.status_code == 200
        assert any(e["name"] == "secret.txt" for e in r.json()["entries"])
