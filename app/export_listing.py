"""Export folder listings as CSV or JSON."""

from __future__ import annotations

import csv
import io
import json
import time
from typing import Any, Iterable, Optional

from .cache import ListingEntry, normalize_path
from .smb_client import ATTR_FLAGS


def attrs_human(attrs: int) -> str:
    return "|".join(name for flag, name in ATTR_FLAGS if attrs & flag)


def entry_row(
    share: str,
    path: str,
    entry: ListingEntry,
) -> dict[str, Any]:
    path = normalize_path(path)
    return {
        "share": share,
        "path": path,
        "name": entry.name,
        "type": "dir" if entry.is_dir else "file",
        "size": int(entry.size or 0),
        "mtime": float(entry.mtime or 0),
        "atime": float(getattr(entry, "atime", 0) or 0),
        "ctime": float(getattr(entry, "ctime", 0) or 0),
        "attributes": int(getattr(entry, "attributes", 0) or 0),
        "attributes_human": attrs_human(int(getattr(entry, "attributes", 0) or 0)),
        "fullpath": f"{share}/{path}/{entry.name}".replace("//", "/").strip("/"),
    }


CSV_COLUMNS = [
    "share",
    "path",
    "name",
    "type",
    "size",
    "mtime",
    "atime",
    "ctime",
    "attributes",
    "attributes_human",
    "fullpath",
]


def rows_from_listing(share: str, path: str, entries: Iterable[ListingEntry]) -> list[dict[str, Any]]:
    return [entry_row(share, path, e) for e in entries]


def to_json(rows: list[dict[str, Any]], *, pretty: bool = True) -> str:
    return json.dumps(rows, indent=2 if pretty else None, ensure_ascii=False)


def to_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore", quoting=csv.QUOTE_MINIMAL)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def export_filename(share: str, path: str, fmt: str) -> str:
    path = normalize_path(path)
    safe_share = "".join(c if c.isalnum() or c in "-_" else "_" for c in (share or "share"))
    safe_path = path.replace("/", "_") if path else "root"
    ts = time.strftime("%Y%m%d_%H%M%S")
    ext = "csv" if fmt == "csv" else "json"
    return f"{safe_share}_{safe_path}_listing_{ts}.{ext}"


def normalize_format(fmt: str) -> str:
    f = (fmt or "csv").strip().lower()
    if f not in ("csv", "json"):
        raise ValueError("format must be csv or json")
    return f
