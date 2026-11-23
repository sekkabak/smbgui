import os

import pytest

from app.proxy import parse_proxy_url, proxy_from_env, proxy_from_fields, proxy_socket_context, create_proxied_connection


def test_parse_proxy_url_socks5():
    p = parse_proxy_url("socks5://alice:secret@10.0.0.1:1080")
    assert p.enabled and p.proxy_type == "socks5"
    assert p.host == "10.0.0.1" and p.port == 1080
    assert p.username == "alice" and p.password == "secret"


def test_parse_proxy_url_http():
    p = parse_proxy_url("http://proxy.corp:8080")
    assert p.proxy_type == "http" and p.port == 8080


def test_proxy_from_env(monkeypatch):
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:9050")
    p = proxy_from_env()
    assert p.enabled and p.port == 9050


def test_proxy_from_fields():
    p = proxy_from_fields("socks5", "1.2.3.4", 1080, "u", "p")
    assert p.enabled and p.host == "1.2.3.4"


def test_proxy_socket_context_noop_when_disabled():
    with proxy_socket_context(proxy_from_fields(enabled=False)):
        pass


def test_create_proxied_connection_direct_to_samba():
    """Direct (no proxy) TCP to local Samba fixture if up."""
    import socket

    try:
        with socket.create_connection(("127.0.0.1", 1445), timeout=1):
            pass
    except OSError:
        pytest.skip("Samba not up")
    from app.proxy import ProxyConfig

    s = create_proxied_connection(ProxyConfig(enabled=False), "127.0.0.1", 1445, timeout=2)
    s.close()
