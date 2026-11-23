import time

import pytest

from app.resilience import (
    RetryPolicy,
    classify_error,
    compute_backoff,
    is_connection_dead_error,
    is_retriable,
    with_retry,
)


def test_classify_retriable_vs_fatal():
    assert classify_error(TimeoutError("timed out")) == "retriable"
    assert classify_error(ConnectionResetError("Connection reset by peer")) == "retriable"
    assert classify_error(Exception("SMB SessionError: STATUS_IO_TIMEOUT")) == "retriable"
    assert classify_error(Exception("STATUS_LOGON_FAILURE")) == "fatal"
    assert classify_error(Exception("STATUS_ACCESS_DENIED")) == "fatal"
    assert classify_error(Exception("STATUS_OBJECT_NAME_NOT_FOUND")) == "fatal"
    assert classify_error(Exception("STATUS_PATH_NOT_COVERED")) == "fatal"
    assert is_retriable(BrokenPipeError("broken pipe"))
    assert is_connection_dead_error(Exception("connection reset"))


def test_backoff_grows_and_caps():
    p = RetryPolicy(base_delay=1.0, max_delay=10.0, jitter=0.0)
    assert compute_backoff(0, p) == 1.0
    assert compute_backoff(1, p) == 2.0
    assert compute_backoff(2, p) == 4.0
    assert compute_backoff(10, p) == 10.0


def test_with_retry_respects_max_and_fatal(monkeypatch):
    sleeps = []
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        raise ConnectionResetError("connection reset")

    with pytest.raises(ConnectionResetError):
        with_retry(
            flaky,
            RetryPolicy(max_retries=3, base_delay=0.01, max_delay=0.05, jitter=0),
            sleep_fn=lambda d: sleeps.append(d),
        )
    assert calls["n"] == 4  # initial + 3 retries
    assert len(sleeps) == 3

    calls["n"] = 0

    def auth_fail():
        calls["n"] += 1
        raise Exception("STATUS_LOGON_FAILURE bad password")

    with pytest.raises(Exception):
        with_retry(auth_fail, RetryPolicy(max_retries=5, base_delay=0.01), sleep_fn=lambda d: None)
    assert calls["n"] == 1  # no retry on fatal


def test_with_retry_eventually_succeeds():
    state = {"n": 0}

    def flaky():
        state["n"] += 1
        if state["n"] < 3:
            raise TimeoutError("timed out")
        return "ok"

    assert with_retry(flaky, RetryPolicy(max_retries=5, base_delay=0.001, jitter=0), sleep_fn=lambda d: None) == "ok"
    assert state["n"] == 3
