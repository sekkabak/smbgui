"""Proxy configuration and SOCKS/HTTP CONNECT socket helpers for SMB."""

from __future__ import annotations

import os
import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from typing import Any, Iterator, Optional
from urllib.parse import urlparse


@dataclass
class ProxyConfig:
    enabled: bool = False
    proxy_type: str = "socks5"  # socks5|socks4|http
    host: str = ""
    port: int = 1080
    username: str = ""
    password: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if d.get("password"):
            d["password"] = "***"
        return d

    def fingerprint(self) -> str:
        if not self.enabled:
            return "direct"
        return f"{self.proxy_type}:{self.host}:{self.port}:{self.username}"


_ENV_KEYS = (
    "ALL_PROXY",
    "all_proxy",
    "SOCKS_PROXY",
    "socks_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
)

# Thread-local: only opted-in SMB connect paths create proxied sockets.
_tls = threading.local()
_orig_socket = socket.socket
_patch_lock = threading.Lock()
_patched = False


def parse_proxy_url(url: str) -> ProxyConfig:
    url = (url or "").strip()
    if not url:
        return ProxyConfig(enabled=False)
    if "://" not in url:
        url = "socks5://" + url
    u = urlparse(url)
    scheme = (u.scheme or "socks5").lower()
    if scheme in ("socks", "socks5h"):
        scheme = "socks5"
    elif scheme == "socks4a":
        scheme = "socks4"
    elif scheme in ("https",):
        scheme = "http"
    if scheme not in ("socks5", "socks4", "http"):
        raise ValueError(f"unsupported proxy scheme: {scheme}")
    host = u.hostname or ""
    port = u.port or (1080 if scheme.startswith("socks") else 8080)
    return ProxyConfig(
        enabled=bool(host),
        proxy_type=scheme,
        host=host,
        port=int(port),
        username=u.username or "",
        password=u.password or "",
    )


def proxy_from_env() -> ProxyConfig:
    for key in _ENV_KEYS:
        val = os.environ.get(key)
        if val:
            try:
                return parse_proxy_url(val)
            except ValueError:
                continue
    return ProxyConfig(enabled=False)


def proxy_from_fields(
    proxy_type: str = "",
    proxy_host: str = "",
    proxy_port: int = 0,
    proxy_user: str = "",
    proxy_pass: str = "",
    enabled: Optional[bool] = None,
) -> ProxyConfig:
    host = (proxy_host or "").strip()
    ptype = (proxy_type or "socks5").strip().lower() or "socks5"
    if ptype in ("socks", "socks5h"):
        ptype = "socks5"
    if enabled is None:
        enabled = bool(host)
    if not host:
        return ProxyConfig(enabled=False)
    port = int(proxy_port or (1080 if ptype.startswith("socks") else 8080))
    return ProxyConfig(
        enabled=bool(enabled),
        proxy_type=ptype,
        host=host,
        port=port,
        username=proxy_user or "",
        password=proxy_pass or "",
    )


def resolve_proxy(
    explicit: Optional[ProxyConfig] = None,
    *,
    use_env: bool = True,
) -> ProxyConfig:
    if explicit and explicit.enabled and explicit.host:
        return explicit
    if use_env:
        return proxy_from_env()
    return ProxyConfig(enabled=False)


class _ThreadLocalSocket(_orig_socket):
    """
    ``socket.socket`` stand-in. Remains a real type (isinstance-safe for httpx).

    When this thread has opted into a proxy via ``proxy_socket_context``,
    ``__new__`` returns a configured ``socks.socksocket`` instead. Other threads
    keep getting plain sockets — no process-wide contamination during yield.
    """

    def __new__(cls, *args, **kwargs):
        proxy = getattr(_tls, "proxy", None)
        if proxy is not None and getattr(proxy, "enabled", False) and proxy.host:
            import socks

            type_map = {
                "socks5": socks.SOCKS5,
                "socks4": socks.SOCKS4,
                "http": socks.HTTP,
            }
            if proxy.proxy_type not in type_map:
                raise ValueError(f"unsupported proxy_type: {proxy.proxy_type}")
            sock = socks.socksocket(*args, **kwargs)
            sock.set_proxy(
                type_map[proxy.proxy_type],
                proxy.host,
                int(proxy.port),
                True,
                proxy.username or None,
                proxy.password or None,
            )
            return sock
        return _orig_socket.__new__(cls, *args, **kwargs)

    def __init__(self, *args, **kwargs):
        # Only invoked when __new__ returned a _ThreadLocalSocket (non-proxy path).
        _orig_socket.__init__(self, *args, **kwargs)


def _ensure_thread_local_socket_patch() -> None:
    global _patched
    with _patch_lock:
        if _patched:
            return
        socket.socket = _ThreadLocalSocket  # type: ignore[misc,assignment]
        _patched = True


@contextmanager
def proxy_socket_context(proxy: ProxyConfig) -> Iterator[None]:
    """
    Route new TCP sockets through the configured proxy via PySocks for the
    duration of the with-block **on this thread only**.

    Impacket constructs sockets internally. A thread-local-aware ``socket.socket``
    subclass is installed once process-wide; only threads inside this context
    create proxied sockets.
    """
    if not proxy or not proxy.enabled:
        yield
        return
    try:
        import socks  # noqa: F401
    except ImportError as e:
        raise RuntimeError("PySocks is required for proxy support; pip install PySocks") from e

    if proxy.proxy_type not in ("socks5", "socks4", "http"):
        raise ValueError(f"unsupported proxy_type: {proxy.proxy_type}")

    _ensure_thread_local_socket_patch()
    prev = getattr(_tls, "proxy", None)
    _tls.proxy = proxy
    try:
        yield
    finally:
        _tls.proxy = prev


def create_proxied_connection(
    proxy: ProxyConfig,
    dest_host: str,
    dest_port: int,
    timeout: Optional[float] = None,
) -> socket.socket:
    """Create an already-connected socket through the proxy (for tests / custom wiring)."""
    if not proxy.enabled:
        return socket.create_connection((dest_host, dest_port), timeout=timeout)
    import socks

    type_map = {"socks5": socks.SOCKS5, "socks4": socks.SOCKS4, "http": socks.HTTP}
    s = socks.socksocket()
    s.set_proxy(
        type_map[proxy.proxy_type],
        proxy.host,
        int(proxy.port),
        True,
        proxy.username or None,
        proxy.password or None,
    )
    if timeout is not None and timeout > 0:
        s.settimeout(timeout)
    s.connect((dest_host, dest_port))
    return s
