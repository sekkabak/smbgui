import csv
import io
import json

from app.cache import ListingEntry
from app.export_listing import (
    CSV_COLUMNS,
    export_filename,
    normalize_format,
    rows_from_listing,
    to_csv,
    to_json,
)
import pytest


def _entries():
    return [
        ListingEntry(name="dir1", size=0, is_dir=True, mtime=100.0, atime=90.0, ctime=80.0, attributes=0x10),
        ListingEntry(name="a.txt", size=12, is_dir=False, mtime=200.0, atime=190.0, ctime=180.0, attributes=0x20),
    ]


def test_rows_and_json():
    rows = rows_from_listing("share", "path/sub", _entries())
    assert rows[0]["type"] == "dir"
    assert rows[1]["type"] == "file"
    assert rows[1]["size"] == 12
    assert "ARCHIVE" in rows[1]["attributes_human"] or rows[1]["attributes"] == 0x20
    data = json.loads(to_json(rows))
    assert len(data) == 2
    assert data[0]["name"] == "dir1"


def test_csv_well_formed():
    rows = rows_from_listing("s", "", _entries())
    text = to_csv(rows)
    # header present
    assert text.splitlines()[0] == ",".join(CSV_COLUMNS)
    reader = csv.DictReader(io.StringIO(text))
    got = list(reader)
    assert len(got) == 2
    assert got[1]["name"] == "a.txt"
    assert got[1]["type"] == "file"
    # quoting: name with comma
    rows2 = rows_from_listing("s", "", [ListingEntry(name="a,b.txt", size=1, is_dir=False, mtime=0)])
    text2 = to_csv(rows2)
    got2 = list(csv.DictReader(io.StringIO(text2)))
    assert got2[0]["name"] == "a,b.txt"


def test_normalize_format_and_filename():
    assert normalize_format("CSV") == "csv"
    assert normalize_format("json") == "json"
    with pytest.raises(ValueError):
        normalize_format("xml")
    fn = export_filename("testdata", "sub/dir", "csv")
    assert fn.startswith("testdata_sub_dir_listing_")
    assert fn.endswith(".csv")
