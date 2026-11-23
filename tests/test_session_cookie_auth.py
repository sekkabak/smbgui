"""Opaque sid cookie — secrets not required on subsequent GETs / mutating POSTs."""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.auth import credentials_from_fields
from app.main import app
from app.proxy import ProxyConfig
from app.smb_client import PooledSession, ShareInfo
from app.web_sessions import store as web_sessions


def _connect(client: TestClient, host="h.example", username="u", password="secret", **extra):
    creds = credentials_from_fields(username=username, password=password)
    mock_conn = MagicMock()
    mock_conn.getServerName.return_value = "X"
    mock_conn.getSMBServer.return_value = MagicMock(echo=MagicMock(return_value=True))
    mock_conn.listShares.return_value = []
    session = PooledSession(host, 445, creds, mock_conn)

    with patch("app.main.pool.connect", return_value=session):
        with patch("app.smb_client.list_shares", return_value=[ShareInfo(name="data", remark="", type=0)]):
            r = client.post(
                "/api/connect",
                json={"host": host, "username": username, "password": password, **extra},
            )
    assert r.status_code == 200, r.text
    return r, session, creds


def test_connect_sets_cookie_and_list_works_without_password():
    client = TestClient(app)
    r, session, _ = _connect(client)
    assert r.json()["sid"]
    assert "smbgui_sid" in r.cookies

    with patch("app.main.pool.get", return_value=session) as get:
        with patch("app.smb_client.list_directory", return_value=[]):
            r2 = client.get(
                "/api/list",
                params={"host": "h.example", "share": "data", "path": "", "use_cache": "false"},
            )
    assert r2.status_code == 200
    assert r2.json()["share"] == "data"
    assert get.called
    assert "proxy" in (get.call_args.kwargs or {})


def test_cookie_only_mkdir_uses_stored_creds_not_empty_username():
    client = TestClient(app)
    r, session, creds = _connect(client)
    assert r.cookies.get("smbgui_sid")

    seen = {}

    def fake_get(host, port, got_creds, proxy=None):
        seen["username"] = got_creds.username
        seen["password"] = got_creds.password
        seen["proxy"] = proxy
        return session

    with patch("app.main.pool.get", side_effect=fake_get):
        with patch("app.smb_client.mkdir"):
            # authBody-style: only port + host/share/path — secrets via cookie
            r2 = client.post(
                "/api/mkdir",
                json={"host": "h.example", "share": "data", "path": "newdir", "port": 445},
            )
    assert r2.status_code == 200, r2.text
    assert seen["username"] == "u"
    assert seen["password"] == "secret"


def test_cookie_only_delete_uses_stored_creds():
    client = TestClient(app)
    r, session, _ = _connect(client)
    seen = {}

    def fake_get(host, port, got_creds, proxy=None):
        seen["username"] = got_creds.username
        return session

    with patch("app.main.pool.get", side_effect=fake_get):
        with patch("app.smb_client.delete_path"):
            r2 = client.post(
                "/api/delete",
                json={
                    "host": "h.example",
                    "share": "data",
                    "path": "f.txt",
                    "port": 445,
                    "is_dir": False,
                },
            )
    assert r2.status_code == 200, r2.text
    assert seen["username"] == "u"


def test_connect_with_proxy_passed_to_subsequent_list():
    client = TestClient(app)
    proxy_fields = {
        "proxy_type": "socks5",
        "proxy_host": "127.0.0.1",
        "proxy_port": 1080,
    }
    r, session, _ = _connect(client, **proxy_fields)
    assert r.status_code == 200
    seen = {}

    def fake_get(host, port, got_creds, proxy=None):
        seen["proxy"] = proxy
        return session

    with patch("app.main.pool.get", side_effect=fake_get):
        with patch("app.smb_client.list_directory", return_value=[]):
            r2 = client.get("/api/list", params={"host": "h.example", "share": "data", "path": ""})
    assert r2.status_code == 200
    assert seen["proxy"] is not None
    assert getattr(seen["proxy"], "enabled", False) is True
    assert seen["proxy"].host == "127.0.0.1"
    assert seen["proxy"].port == 1080


def test_get_for_host_miss_does_not_use_empty_creds():
    client = TestClient(app)
    r, session, _ = _connect(client, host="host-a")
    sid = r.json()["sid"]
    # Cookie is for host-a; request host-b with that sid → must not invent empty user
    with patch("app.main.pool.get") as get:
        r2 = client.get(
            "/api/list",
            params={"host": "host-b", "share": "data", "path": "", "sid": sid},
        )
    assert r2.status_code == 401
    get.assert_not_called()


def test_session_endpoint_omits_raw_sid():
    client = TestClient(app)
    _connect(client)
    r = client.get("/api/session", params={"host": "h.example"})
    assert r.status_code == 200
    assert "sid" not in r.json()


def test_logout_revokes_session():
    client = TestClient(app)
    r, session, _ = _connect(client)
    sid = r.json()["sid"]
    assert web_sessions.get(sid) is not None
    with patch("app.main.pool.disconnect_host"):
        r2 = client.post("/api/logout", json={"host": "h.example", "sid": sid})
    assert r2.status_code == 200
    assert web_sessions.get(sid) is None


def test_file_cross_site_blocked():
    client = TestClient(app)
    r, session, _ = _connect(client)
    with patch("app.main.pool.get", return_value=session):
        r2 = client.get(
            "/api/file",
            params={"host": "h.example", "share": "data", "path": "f.txt"},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
    assert r2.status_code == 403


def test_samesite_strict_cookie():
    client = TestClient(app)
    r, _, _ = _connect(client)
    # Starlette TestClient exposes set-cookie; check raw header
    set_cookie = r.headers.get("set-cookie", "")
    assert "samesite=strict" in set_cookie.lower() or "SameSite=strict" in set_cookie
