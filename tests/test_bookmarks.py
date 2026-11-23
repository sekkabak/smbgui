from pathlib import Path

from app.bookmarks import BookmarkStore


def test_bookmarks_persist(tmp_path: Path):
    path = tmp_path / "bookmarks.json"
    store = BookmarkStore(path)
    bm = store.add_bookmark(label="lab", host="10.0.0.5", share="data", path="a/b", username="alice", domain="CORP")
    assert bm["id"]
    store2 = BookmarkStore(path)
    listed = store2.list_bookmarks()
    assert len(listed) == 1
    assert listed[0]["host"] == "10.0.0.5"
    assert store2.remove_bookmark(bm["id"]) is True
    assert store2.list_bookmarks() == []


def test_recent_dedupe(tmp_path: Path):
    store = BookmarkStore(tmp_path / "b.json")
    store.add_recent("h", 445, "u", "", "password")
    store.add_recent("h", 445, "u", "", "password")
    store.add_recent("h", 445, "u", "", "pth")
    recent = store.list_recent()
    assert len(recent) == 2
    assert recent[0]["auth_mode"] == "pth"
