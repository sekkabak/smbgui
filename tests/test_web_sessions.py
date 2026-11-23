"""Opaque UI session store — secrets stay server-side, not in GET URLs."""

from app.auth import credentials_from_fields
from app.web_sessions import WebSessionStore


def test_create_and_resolve_session():
    store = WebSessionStore()
    creds = credentials_from_fields(username="u", password="secret")
    sid = store.create(host="h1", port=445, creds=creds)
    assert sid
    got = store.get(sid)
    assert got is not None
    assert got.host == "h1"
    assert got.port == 445
    assert got.creds.password == "secret"
    assert got.creds.fingerprint() == creds.fingerprint()


def test_resolve_by_host():
    store = WebSessionStore()
    creds = credentials_from_fields(username="u", password="p")
    sid = store.create(host="Server.Lab", port=445, creds=creds)
    got = store.get_for_host(sid, "server.lab")
    assert got is not None
    assert store.get_for_host(sid, "other") is None


def test_revoke():
    store = WebSessionStore()
    creds = credentials_from_fields(guest=True)
    sid = store.create(host="h", port=445, creds=creds)
    store.revoke(sid)
    assert store.get(sid) is None
