"""Opaque sid cookie — secrets not required on subsequent GETs."""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.auth import credentials_from_fields
from app.main import app
from app.smb_client import PooledSession, ShareInfo


def test_connect_sets_cookie_and_list_works_without_password():
    client = TestClient(app)
    creds = credentials_from_fields(username="u", password="secret")
    mock_conn = MagicMock()
    mock_conn.getServerName.return_value = "X"
    mock_conn.getSMBServer.return_value = MagicMock(echo=MagicMock(return_value=True))
    mock_conn.listShares.return_value = []
    session = PooledSession("h.example", 445, creds, mock_conn)

    with patch("app.main.pool.connect", return_value=session):
        with patch("app.smb_client.list_shares", return_value=[ShareInfo(name="data", remark="", type=0)]):
            r = client.post(
                "/api/connect",
                json={"host": "h.example", "username": "u", "password": "secret"},
            )
    assert r.status_code == 200
    assert r.json()["sid"]
    assert "smbgui_sid" in r.cookies

    with patch("app.main.pool.get", return_value=session):
        with patch("app.smb_client.list_directory", return_value=[]):
            # No password in query — cookie + host only
            r2 = client.get("/api/list", params={"host": "h.example", "share": "data", "path": ""})
    assert r2.status_code == 200
    assert r2.json()["share"] == "data"
