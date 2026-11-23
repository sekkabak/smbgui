"""Runtime configuration (env-overridable) including reliability knobs."""

from __future__ import annotations

import os
from dataclasses import dataclass, asdict, fields
from pathlib import Path
from typing import Any, Optional

from .proxy import ProxyConfig, proxy_from_env, resolve_proxy
from .resilience import RetryPolicy

ROOT = Path(__file__).resolve().parent.parent

# Hours-scale defaults for brutal corporate networks.
# 0 means "no timeout" / wait indefinitely at the socket layer.
DEFAULT_CONNECT_TIMEOUT = 3600.0       # 1 hour to establish session
DEFAULT_IO_TIMEOUT = 0.0               # 0 = infinite for reads/writes
DEFAULT_KEEPALIVE_SECONDS = 60.0
DEFAULT_MAX_RETRIES = 10
DEFAULT_BASE_DELAY = 2.0
DEFAULT_MAX_DELAY = 600.0              # 10 min between retries


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def data_dir() -> Path:
    raw = (os.environ.get("SMBGUI_DATA_DIR") or "").strip()
    path = Path(raw).expanduser() if raw else (ROOT / "data")
    path.mkdir(parents=True, exist_ok=True)
    return path


def web_dir() -> Path:
    return ROOT / "web"


def bind_host() -> str:
    return (os.environ.get("SMBGUI_HOST") or "127.0.0.1").strip()


def bind_port() -> int:
    try:
        return int(os.environ.get("SMBGUI_PORT") or "8787")
    except ValueError:
        return 8787


def parts_dir() -> Path:
    """Directory for resumable .part transfer files."""
    d = data_dir() / "parts"
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass
class ReliabilitySettings:
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    io_timeout: float = DEFAULT_IO_TIMEOUT  # 0 = none
    keepalive_seconds: float = DEFAULT_KEEPALIVE_SECONDS
    max_retries: int = DEFAULT_MAX_RETRIES
    base_delay: float = DEFAULT_BASE_DELAY
    max_delay: float = DEFAULT_MAX_DELAY
    jitter: float = 0.25
    retry_enabled: bool = True
    auto_reconnect: bool = True
    resume_enabled: bool = True
    proxy: ProxyConfig = None  # type: ignore

    def __post_init__(self):
        if self.proxy is None:
            self.proxy = proxy_from_env()

    def retry_policy(self) -> RetryPolicy:
        return RetryPolicy(
            max_retries=self.max_retries,
            base_delay=self.base_delay,
            max_delay=self.max_delay,
            jitter=self.jitter,
            enabled=self.retry_enabled,
        )

    def effective_connect_timeout(self) -> Optional[float]:
        """None means blocking forever for socket APIs that treat None that way."""
        if self.connect_timeout is None or self.connect_timeout <= 0:
            return None
        return float(self.connect_timeout)

    def effective_io_timeout(self) -> Optional[float]:
        if self.io_timeout is None or self.io_timeout <= 0:
            return None
        return float(self.io_timeout)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "connect_timeout": self.connect_timeout,
            "io_timeout": self.io_timeout,
            "keepalive_seconds": self.keepalive_seconds,
            "max_retries": self.max_retries,
            "base_delay": self.base_delay,
            "max_delay": self.max_delay,
            "jitter": self.jitter,
            "retry_enabled": self.retry_enabled,
            "auto_reconnect": self.auto_reconnect,
            "resume_enabled": self.resume_enabled,
            "proxy": self.proxy.to_dict() if self.proxy else ProxyConfig().to_dict(),
        }
        return d

    def update_from_dict(self, d: dict[str, Any]) -> None:
        for key in (
            "connect_timeout",
            "io_timeout",
            "keepalive_seconds",
            "max_retries",
            "base_delay",
            "max_delay",
            "jitter",
            "retry_enabled",
            "auto_reconnect",
            "resume_enabled",
        ):
            if key in d and d[key] is not None:
                setattr(self, key, type(getattr(self, key))(d[key]) if key not in ("retry_enabled", "auto_reconnect", "resume_enabled") else bool(d[key]))
        if "proxy" in d and isinstance(d["proxy"], dict):
            p = d["proxy"]
            self.proxy = ProxyConfig(
                enabled=bool(p.get("enabled", False)),
                proxy_type=p.get("proxy_type") or "socks5",
                host=p.get("host") or "",
                port=int(p.get("port") or 1080),
                username=p.get("username") or "",
                password=p.get("password") or "",
            )


def load_reliability_from_env() -> ReliabilitySettings:
    return ReliabilitySettings(
        connect_timeout=_float_env("SMBGUI_CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT),
        io_timeout=_float_env("SMBGUI_IO_TIMEOUT", DEFAULT_IO_TIMEOUT),
        keepalive_seconds=_float_env("SMBGUI_KEEPALIVE", DEFAULT_KEEPALIVE_SECONDS),
        max_retries=_int_env("SMBGUI_MAX_RETRIES", DEFAULT_MAX_RETRIES),
        base_delay=_float_env("SMBGUI_RETRY_BASE_DELAY", DEFAULT_BASE_DELAY),
        max_delay=_float_env("SMBGUI_RETRY_MAX_DELAY", DEFAULT_MAX_DELAY),
        jitter=_float_env("SMBGUI_RETRY_JITTER", 0.25),
        retry_enabled=os.environ.get("SMBGUI_RETRY_ENABLED", "1") not in ("0", "false", "False"),
        auto_reconnect=os.environ.get("SMBGUI_AUTO_RECONNECT", "1") not in ("0", "false", "False"),
        resume_enabled=os.environ.get("SMBGUI_RESUME_ENABLED", "1") not in ("0", "false", "False"),
        proxy=proxy_from_env(),
    )


# Process-wide mutable settings (updated via API)
settings = load_reliability_from_env()
