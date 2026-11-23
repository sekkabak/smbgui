import os
from pathlib import Path

from app import config


def test_data_dir_default(tmp_path, monkeypatch):
    monkeypatch.delenv("SMBGUI_DATA_DIR", raising=False)
    # default points under package root /data — just ensure callable and exists
    d = config.data_dir()
    assert d.exists()
    assert d.is_dir()


def test_data_dir_env_override(tmp_path, monkeypatch):
    target = tmp_path / "custom-data"
    monkeypatch.setenv("SMBGUI_DATA_DIR", str(target))
    # reload path resolution
    d = config.data_dir()
    assert d == target
    assert d.exists()
