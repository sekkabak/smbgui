"""Path normalization hardening."""

import pytest

from app.cache import normalize_path


def test_normalize_basic():
    assert normalize_path(r"a\b\c") == "a/b/c"
    assert normalize_path("/a/b/") == "a/b"
    assert normalize_path("") == ""


def test_normalize_rejects_dotdot():
    with pytest.raises(ValueError):
        normalize_path("../etc/passwd")
    with pytest.raises(ValueError):
        normalize_path("foo/../bar")


def test_normalize_allows_dotdot_prefixed_names():
    assert normalize_path("..foo") == "..foo"


def test_normalize_rejects_wildcards():
    with pytest.raises(ValueError):
        normalize_path("*.txt")


def test_normalize_rejects_reserved_names():
    with pytest.raises(ValueError):
        normalize_path("CON")
    with pytest.raises(ValueError):
        normalize_path("foo/NUL.txt")


def test_paths_equal_ci():
    from app.cache import paths_equal

    assert paths_equal("Foo/Bar", "foo/bar")
    assert not paths_equal("a", "b")
