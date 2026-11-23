"""Retry / backoff / error classification for unstable SMB environments."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, asdict
from typing import Any, Callable, Optional, TypeVar

from .logging_util import setup_logging, log_event

logger = setup_logging()
T = TypeVar("T")

# NTSTATUS / Impacket strings that are typically transient
_RETRIABLE_SUBSTRINGS = (
    "timed out",
    "timeout",
    "connection reset",
    "broken pipe",
    "connection aborted",
    "connection refused",  # often transient behind flaky proxies
    "network is unreachable",
    "temporarily unavailable",
    "eof",
    "status_io_timeout",
    "status_connection_disconnected",
    "status_connection_reset",
    "status_network_name_deleted",
    "status_unexpected_network_error",
    "status_request_not_accepted",
    "status_no_logon_servers",
    "status_server_unavailable",
    "status_share_unavailable",
    "status_pipe_not_available",
    "status_pipe_busy",
    "status_pipe_closing",
    "status_user_session_deleted",
    "status_connection_disconnected",
    "socket",
    "errno 104",
    "errno 110",
    "errno 32",
    "errno 54",
    "errno 10054",
    "errno 10060",
)

_FATAL_SUBSTRINGS = (
    "status_logon_failure",
    "status_wrong_password",
    "status_account_locked_out",
    "status_account_disabled",
    "status_password_expired",
    "status_access_denied",
    "status_object_name_not_found",
    "status_no_such_file",
    "status_object_path_not_found",
    "status_bad_network_name",
    "status_logon_type_not_granted",
    "status_account_restriction",
    "status_path_not_covered",  # DFS referral required — not a transient network blip
    "not_browsable",
    "invalid_request",
    "authentication failed",
    "dfs_path_not_covered",
)


@dataclass
class RetryPolicy:
    max_retries: int = 8
    base_delay: float = 1.0
    max_delay: float = 300.0
    jitter: float = 0.25  # fraction of delay
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "RetryPolicy":
        d = d or {}
        return cls(
            max_retries=int(d.get("max_retries", 8)),
            base_delay=float(d.get("base_delay", 1.0)),
            max_delay=float(d.get("max_delay", 300.0)),
            jitter=float(d.get("jitter", 0.25)),
            enabled=bool(d.get("enabled", True)),
        )


def classify_error(exc: BaseException) -> str:
    """Return 'retriable' or 'fatal'."""
    msg = f"{type(exc).__name__}: {exc}".lower()
    # Fatal first — auth/access should never be retried forever
    for s in _FATAL_SUBSTRINGS:
        if s in msg:
            return "fatal"
    # Check structured code attribute
    code = str(getattr(exc, "code", "") or "").lower()
    if code in ("connect_failed", "smb_error", "timeout", "connection_error"):
        # connect_failed may be auth OR network — inspect message
        for s in _FATAL_SUBSTRINGS:
            if s in msg:
                return "fatal"
    for s in _RETRIABLE_SUBSTRINGS:
        if s in msg:
            return "retriable"
    # OSError subclasses without clear message: treat as retriable
    if isinstance(exc, (TimeoutError, ConnectionError, BrokenPipeError, ConnectionResetError, OSError)):
        return "retriable"
    # Default: retriable for unknown network-ish failures (quality over false fatal)
    if "status_" in msg or "smb" in msg or "socket" in msg:
        return "retriable"
    return "fatal"


def is_retriable(exc: BaseException) -> bool:
    return classify_error(exc) == "retriable"


def is_connection_dead_error(exc: BaseException) -> bool:
    msg = f"{exc}".lower()
    needles = (
        "connection reset",
        "broken pipe",
        "timed out",
        "timeout",
        "not connected",
        "connection aborted",
        "status_connection",
        "status_user_session_deleted",
        "errno 104",
        "errno 32",
        "eof",
    )
    return any(n in msg for n in needles)


def compute_backoff(attempt: int, policy: RetryPolicy) -> float:
    """attempt is 0-based (after first failure)."""
    delay = min(policy.max_delay, policy.base_delay * (2 ** attempt))
    if policy.jitter > 0:
        delay = delay * (1.0 + random.uniform(-policy.jitter, policy.jitter))
    return max(0.0, delay)


def with_retry(
    fn: Callable[[], T],
    policy: Optional[RetryPolicy] = None,
    *,
    on_retry: Optional[Callable[[int, BaseException, float], None]] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    operation: str = "smb_op",
) -> T:
    """Execute fn with exponential backoff + jitter on retriable errors."""
    policy = policy or RetryPolicy()
    if not policy.enabled:
        return fn()
    last: Optional[BaseException] = None
    attempts = policy.max_retries + 1
    for attempt in range(attempts):
        try:
            return fn()
        except BaseException as e:
            last = e
            if not is_retriable(e) or attempt >= policy.max_retries:
                raise
            delay = compute_backoff(attempt, policy)
            log_event(
                logger,
                "retry",
                action=operation,
                error=str(e),
                host="",
            )
            logger.info(
                "retry %s attempt=%s/%s delay=%.2fs err=%s",
                operation,
                attempt + 1,
                policy.max_retries,
                delay,
                e,
            )
            if on_retry:
                on_retry(attempt + 1, e, delay)
            sleep_fn(delay)
    assert last is not None
    raise last
