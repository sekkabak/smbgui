import asyncio

import pytest

from app.activity import ActivityHub, ActivityEvent


def test_activity_snapshot_and_states():
    hub = ActivityHub()
    assert hub.snapshot()["state"] == "idle"
    hub.set("connecting", "connecting to 10.0.0.1…", host="10.0.0.1")
    snap = hub.snapshot()
    assert snap["state"] == "connecting"
    assert snap["busy"] is True
    assert "10.0.0.1" in snap["message"]
    hub.set("retrying", "retry 2/5 (connection reset) — backing off 4s", severity="warn")
    assert hub.snapshot()["severity"] == "warn"
    hub.set("reconnecting", "reconnecting…", severity="warn", host="h")
    hub.set("downloading", "downloading file.bin 37%", progress=37.0, path="share/file.bin")
    assert hub.snapshot()["progress"] == 37.0
    hub.error("boom", host="h")
    assert hub.snapshot()["state"] == "error" and hub.snapshot()["busy"] is False
    hub.idle()
    assert hub.snapshot()["state"] == "idle"
    hist = hub.history()
    assert len(hist) >= 5


@pytest.mark.asyncio
async def test_activity_subscribe_broadcast():
    hub = ActivityHub()
    loop = asyncio.get_running_loop()
    hub.set_loop(loop)
    q = hub.subscribe()
    # snapshot pushed on subscribe
    first = await asyncio.wait_for(q.get(), timeout=1)
    assert first["type"] == "status"
    hub.set("listing", "listing share/…", host="h", path="share/")
    msg = await asyncio.wait_for(q.get(), timeout=1)
    assert msg["state"] == "listing"
    hub.unsubscribe(q)


def test_api_status_endpoint_emits_on_connect():
    """Smoke via TestClient when Samba up — otherwise just unit hub."""
    import os, socket
    from fastapi.testclient import TestClient
    from app.main import app
    from app.activity import activity

    activity.idle("test-reset")
    try:
        with socket.create_connection(("127.0.0.1", 1445), timeout=0.5):
            samba = True
    except OSError:
        samba = False
    if not samba:
        activity.set("connecting", "connecting to example…", host="example")
        c = TestClient(app)
        r = c.get("/api/status")
        assert r.status_code == 200
        assert r.json()["state"] == "connecting"
        return

    c = TestClient(app)
    r = c.post(
        "/api/connect",
        json={"connection": "smbtest:TestPass123!@127.0.0.1:1445", "connect_timeout": 30},
    )
    assert r.status_code == 200
    st = c.get("/api/status").json()
    # after connect should be idle connected
    assert st["state"] in ("idle", "connecting", "listing")
    assert "message" in st
