from app.config import ReliabilitySettings, load_reliability_from_env


def test_load_from_env(monkeypatch):
    monkeypatch.setenv("SMBGUI_CONNECT_TIMEOUT", "7200")
    monkeypatch.setenv("SMBGUI_IO_TIMEOUT", "0")
    monkeypatch.setenv("SMBGUI_MAX_RETRIES", "15")
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:1080")
    s = load_reliability_from_env()
    assert s.connect_timeout == 7200
    assert s.io_timeout == 0
    assert s.max_retries == 15
    assert s.effective_io_timeout() is None
    assert s.proxy.enabled and s.proxy.port == 1080


def test_update_from_dict():
    s = ReliabilitySettings()
    s.update_from_dict({"max_retries": 3, "retry_enabled": False, "proxy": {"enabled": True, "proxy_type": "socks5", "host": "10.0.0.1", "port": 9050}})
    assert s.max_retries == 3
    assert s.retry_enabled is False
    assert s.proxy.host == "10.0.0.1"
