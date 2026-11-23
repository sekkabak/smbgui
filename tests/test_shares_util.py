import pytest

from app.shares_util import (
    admin_share_from_drive,
    classify_share,
    drive_letter_from_admin_share,
    is_admin_share,
    is_browsable_share,
    is_hidden_share,
    is_ipc_share,
)


def test_hidden_and_admin_detection():
    assert is_hidden_share("C$")
    assert is_admin_share("C$")
    assert is_admin_share("ADMIN$")
    assert is_admin_share("secret$")  # $-suffix convention
    assert not is_admin_share("testdata")
    assert not is_hidden_share("testdata")


def test_ipc_special():
    assert is_ipc_share("IPC$")
    assert is_ipc_share("ipc$")
    assert not is_admin_share("IPC$")  # special, not filesystem admin
    assert not is_browsable_share("IPC$")
    assert is_browsable_share("C$")
    assert is_browsable_share("testdata")


def test_drive_mapping():
    assert drive_letter_from_admin_share("C$") == "C"
    assert drive_letter_from_admin_share("d$") == "D"
    assert drive_letter_from_admin_share("ADMIN$") is None
    assert admin_share_from_drive("C") == "C$"
    assert admin_share_from_drive("c:") == "C$"
    with pytest.raises(ValueError):
        admin_share_from_drive("CC")


def test_classify_share():
    c = classify_share("C$")
    assert c["is_admin"] and c["is_hidden"] and c["browsable"] and c["drive_letter"] == "C"
    ipc = classify_share("IPC$")
    assert ipc["is_ipc"] and not ipc["browsable"] and not ipc["is_admin"]
