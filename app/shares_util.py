"""Administrative / hidden share helpers."""

from __future__ import annotations

import re
from typing import Optional


# Well-known Windows admin shares
KNOWN_ADMIN_SHARES = {
    "ADMIN$",
    "C$",
    "D$",
    "E$",
    "F$",
    "G$",
    "H$",
    "I$",
    "J$",
    "K$",
    "L$",
    "M$",
    "N$",
    "O$",
    "P$",
    "Q$",
    "R$",
    "S$",
    "T$",
    "U$",
    "V$",
    "W$",
    "X$",
    "Y$",
    "Z$",
    "PRINT$",
    "FAX$",
}


def is_hidden_share(name: str) -> bool:
    """True if the share name ends with $ (Windows hidden/admin convention)."""
    n = (name or "").rstrip("\x00").strip()
    return bool(n) and n.endswith("$")


def is_ipc_share(name: str) -> bool:
    return (name or "").rstrip("\x00").strip().upper() == "IPC$"


def is_admin_share(name: str) -> bool:
    """
    Administrative share: well-known ADMIN$/drive$ or any $-suffixed share
    that is not IPC$ (IPC$ is special/non-filesystem).
    """
    n = (name or "").rstrip("\x00").strip()
    if not n or is_ipc_share(n):
        return False
    upper = n.upper()
    if upper in KNOWN_ADMIN_SHARES:
        return True
    return is_hidden_share(n)


def is_browsable_share(name: str) -> bool:
    """IPC$ is not a filesystem share — not browsable as directories/files."""
    return not is_ipc_share(name)


def drive_letter_from_admin_share(name: str) -> Optional[str]:
    """C$ → C, D$ → D; ADMIN$/IPC$/other → None."""
    n = (name or "").strip().upper()
    m = re.fullmatch(r"([A-Z])\$", n)
    if m:
        return m.group(1)
    return None


def admin_share_from_drive(drive: str) -> str:
    """C or C: → C$."""
    d = (drive or "").strip().upper().rstrip(":\\/")
    if not re.fullmatch(r"[A-Z]", d):
        raise ValueError(f"invalid drive letter: {drive!r}")
    return f"{d}$"


def classify_share(name: str) -> dict:
    """Return classification flags for API responses."""
    n = (name or "").rstrip("\x00").strip()
    return {
        "name": n,
        "is_hidden": is_hidden_share(n),
        "is_admin": is_admin_share(n),
        "is_ipc": is_ipc_share(n),
        "browsable": is_browsable_share(n),
        "drive_letter": drive_letter_from_admin_share(n),
    }
