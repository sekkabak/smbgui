import time
from pathlib import Path

from app.cache import SCHEMA_VERSION, CacheStore, ListingEntry


def test_put_get_memory_and_disk(tmp_path: Path):
    store = CacheStore(tmp_path, default_ttl=60)
    entries = [
        ListingEntry(name="a.txt", size=10, is_dir=False, mtime=1.0),
        ListingEntry(name="dir", size=0, is_dir=True, mtime=2.0),
    ]
    store.put("Host1", "share", "folder", "fp1", entries)
    got = store.get("host1", "share", "folder", "fp1")
    assert got is not None and len(got.entries) == 2

    store2 = CacheStore(tmp_path, default_ttl=60)
    got2 = store2.get("host1", "share", "folder", "fp1")
    assert got2 is not None
    assert [e.name for e in got2.entries] == ["a.txt", "dir"]
    assert (tmp_path / "cache_host1.db").exists()


def test_stale_flag(tmp_path: Path):
    store = CacheStore(tmp_path, default_ttl=1)
    store.put("h", "s", "", "fp", [ListingEntry("x", 0, False, 0)], ttl=1, fetched_at=time.time() - 5)
    got = store.get("h", "s", "", "fp", allow_stale=True)
    assert got is not None and got.stale is True
    assert store.get("h", "s", "", "fp", allow_stale=False) is None


def test_invalidate_path_and_parent(tmp_path: Path):
    store = CacheStore(tmp_path, default_ttl=60)
    store.put("h", "s", "a/b", "fp", [ListingEntry("f", 1, False, 0)])
    store.put("h", "s", "a", "fp", [ListingEntry("b", 0, True, 0)])
    store.put("h", "s", "", "fp", [ListingEntry("a", 0, True, 0)])
    store.invalidate("h", "s", "a/b", "fp")
    assert store.get("h", "s", "a/b", "fp") is None
    assert store.get("h", "s", "a", "fp") is None
    assert store.get("h", "s", "", "fp") is not None


def test_invalidate_subtree(tmp_path: Path):
    store = CacheStore(tmp_path, default_ttl=60)
    store.put("h", "s", "a", "fp", [ListingEntry("b", 0, True, 0)])
    store.put("h", "s", "a/b", "fp", [ListingEntry("c.txt", 1, False, 0)])
    store.put("h", "s", "a/b/d", "fp", [ListingEntry("e.txt", 1, False, 0)])
    store.invalidate_subtree("h", "s", "a", "fp")
    assert store.get("h", "s", "a", "fp") is None
    assert store.get("h", "s", "a/b", "fp") is None
    assert store.get("h", "s", "a/b/d", "fp") is None


def test_fts_search(tmp_path: Path):
    store = CacheStore(tmp_path, default_ttl=60)
    store.put(
        "h",
        "docs",
        "reports",
        "fp",
        [
            ListingEntry("Q1_report.pdf", 100, False, 0),
            ListingEntry("notes.txt", 20, False, 0),
            ListingEntry("budget_Q1.xlsx", 50, False, 0),
        ],
    )
    hits = store.search("h", "Q1", cred_fp="fp", use_fts=True)
    names = {h["name"] for h in hits}
    assert "Q1_report.pdf" in names
    assert "budget_Q1.xlsx" in names


def test_schema_version_v2(tmp_path: Path):
    store = CacheStore(tmp_path)
    store.put("h", "s", "", "fp", [ListingEntry("x", 0, False, 0)])
    status = store.status("h")
    assert status["hosts"]["h"]["schema_version"] == SCHEMA_VERSION
    assert status["hosts"]["h"]["fts_entries"] >= 1


def test_export_import(tmp_path: Path):
    store = CacheStore(tmp_path)
    store.put("h", "s", "p", "fp", [ListingEntry("z.txt", 3, False, 0)])
    blob = store.export_host("h")
    assert blob[:2] == b"PK"
    # import into new dir via same store after clear
    store.clear_host("h")
    assert store.get("h", "s", "p", "fp") is None
    info = store.import_host("h", blob)
    assert info["listings"] >= 1
    got = store.get("h", "s", "p", "fp")
    assert got is not None and got.entries[0].name == "z.txt"


def test_migration_v1_to_v2(tmp_path: Path):
    import sqlite3, json

    db = tmp_path / "cache_old.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version(version) VALUES (1);
        CREATE TABLE listings (
            share TEXT, path TEXT, cred_fp TEXT, entries_json TEXT,
            fetched_at REAL, ttl INTEGER,
            PRIMARY KEY (share, path, cred_fp)
        );
        """
    )
    conn.execute(
        "INSERT INTO listings VALUES (?,?,?,?,?,?)",
        ("s", "", "fp", json.dumps([{"name": "old.txt", "size": 1, "is_dir": False, "mtime": 0}]), time.time(), 60),
    )
    conn.commit()
    conn.close()
    # rename to expected pattern
    db.rename(tmp_path / "cache_mig.db")
    store = CacheStore(tmp_path)
    # opening triggers migration
    got = store.get("mig", "s", "", "fp")
    assert got is not None
    status = store.status("mig")
    assert status["hosts"]["mig"]["schema_version"] == 2
    hits = store.search("mig", "old", cred_fp="fp")
    assert any(h["name"] == "old.txt" for h in hits)
