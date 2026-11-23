"""Unit tests for Kerberos code-path wiring (no real KDC)."""

from unittest.mock import MagicMock, patch

from app.auth import credentials_from_fields
from app.smb_client import SMBPool


def test_kerberos_login_tcp_to_file_server_not_dc():
    """TCP remoteHost must be the file server; dc_ip is only for kdcHost."""
    creds = credentials_from_fields(
        username="alice",
        domain="CORP",
        password="Secret1!",
        use_kerberos=True,
        aes_key="a" * 32,
        kdc_host="dc.corp.local",
        dc_ip="10.0.0.10",
    )
    pool = SMBPool()
    mock_conn = MagicMock()
    mock_conn.getServerName.return_value = "FILESERVER"

    with patch("app.smb_client.SMBConnection", return_value=mock_conn) as ctor:
        with patch("app.smb_client.proxy_socket_context"):
            session = pool.connect("fileserver.corp.local", 445, creds, timeout=5)
        kwargs = ctor.call_args.kwargs
        assert kwargs.get("remoteHost") == "fileserver.corp.local"
        assert kwargs.get("remoteName") == "fileserver.corp.local"
        mock_conn.kerberosLogin.assert_called_once()
        _args, kw = mock_conn.kerberosLogin.call_args
        assert _args[0] == "alice"
        assert _args[2] == "CORP"
        assert kw.get("aesKey") == "a" * 32
        assert kw.get("kdcHost") == "dc.corp.local"
        assert kw.get("useCache") is True
        assert session.creds.use_kerberos is True


def test_kerberos_kdc_falls_back_to_dc_ip():
    creds = credentials_from_fields(
        username="alice",
        domain="CORP",
        password="x",
        use_kerberos=True,
        dc_ip="10.0.0.10",
    )
    pool = SMBPool()
    mock_conn = MagicMock()
    with patch("app.smb_client.SMBConnection", return_value=mock_conn):
        with patch("app.smb_client.proxy_socket_context"):
            pool.connect("fileserver", 445, creds)
    _args, kw = mock_conn.kerberosLogin.call_args
    assert kw.get("kdcHost") == "10.0.0.10"


def test_kerberos_sets_ccache_env():
    creds = credentials_from_fields(
        username="alice",
        domain="CORP",
        use_kerberos=True,
        ccache="/tmp/fake_ccache_smbgui",
        kdc_host="dc.corp.local",
    )
    pool = SMBPool()
    mock_conn = MagicMock()

    seen = {}

    def fake_kerb(*a, **k):
        import os

        seen["cc"] = os.environ.get("KRB5CCNAME")

    mock_conn.kerberosLogin.side_effect = fake_kerb

    with patch("app.smb_client.SMBConnection", return_value=mock_conn):
        with patch("app.smb_client.proxy_socket_context"):
            pool.connect("host", 445, creds)
    assert seen["cc"] == "/tmp/fake_ccache_smbgui"


def test_password_path_does_not_call_kerberos():
    creds = credentials_from_fields(username="u", password="p")
    pool = SMBPool()
    mock_conn = MagicMock()
    with patch("app.smb_client.SMBConnection", return_value=mock_conn):
        with patch("app.smb_client.proxy_socket_context"):
            pool.connect("h", 445, creds)
    mock_conn.login.assert_called()
    mock_conn.kerberosLogin.assert_not_called()


def test_spn_overrides_remote_name_for_kerberos():
    creds = credentials_from_fields(
        username="alice",
        domain="CORP",
        password="x",
        use_kerberos=True,
        kdc_host="dc.corp.local",
        spn="cifs/files01.corp.local",
    )
    pool = SMBPool()
    mock_conn = MagicMock()
    with patch("app.smb_client.SMBConnection", return_value=mock_conn) as ctor:
        with patch("app.smb_client.proxy_socket_context"):
            pool.connect("10.0.0.5", 445, creds)
    assert ctor.call_args.kwargs.get("remoteName") == "files01.corp.local"
    assert ctor.call_args.kwargs.get("remoteHost") == "10.0.0.5"
