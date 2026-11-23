import os
import pytest

from app.auth import (
    credentials_from_fields,
    nt_hash_hex,
    parse_aes_key,
    parse_connection_string,
    parse_hash,
    parse_kerberos_options,
)


def test_parse_connection_basic():
    host, port, creds = parse_connection_string("alice:secret@10.0.0.5")
    assert host == "10.0.0.5"
    assert port == 445
    assert creds.username == "alice"
    assert creds.password == "secret"


def test_parse_connection_domain_and_port():
    host, port, creds = parse_connection_string(r"CORP\bob:p@ass@smb.lab:4445")
    assert host == "smb.lab"
    assert port == 4445
    assert creds.domain == "CORP"
    assert creds.username == "bob"
    assert creds.password == "p@ass"


def test_parse_connection_no_password():
    host, port, creds = parse_connection_string("alice@host")
    assert creds.username == "alice"
    assert creds.password == ""


def test_parse_connection_invalid():
    with pytest.raises(ValueError):
        parse_connection_string("not-a-conn")


def test_parse_hash_nt_only():
    lm, nt = parse_hash("8846f7eaee8fb117ad06bdd830b7586c")
    assert lm == "0" * 32
    assert nt == "8846f7eaee8fb117ad06bdd830b7586c"


def test_parse_hash_lm_nt():
    lm, nt = parse_hash("aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c")
    assert len(lm) == 32 and len(nt) == 32


def test_parse_hash_invalid():
    with pytest.raises(ValueError):
        parse_hash("deadbeef")


def test_guest_and_fingerprint():
    g = credentials_from_fields(guest=True)
    assert g.is_guest and g.auth_mode() == "guest"
    assert g.username == "Guest"
    p = credentials_from_fields(username="u", password="p")
    h = credentials_from_fields(username="u", hash_str=nt_hash_hex("p"))
    assert p.fingerprint() != h.fingerprint()
    assert h.auth_mode() == "pth"


def test_parse_connection_ipv6():
    host, port, creds = parse_connection_string("alice:secret@[::1]:1445")
    assert host == "::1"
    assert port == 1445
    assert creds.username == "alice"

    host, port, creds = parse_connection_string(r"CORP\bob:p@[2001:db8::1]")
    assert host == "2001:db8::1"
    assert port == 445
    assert creds.domain == "CORP"


def test_nt_hash_hex_known():
    assert nt_hash_hex("password") == "8846f7eaee8fb117ad06bdd830b7586c"


def test_kerberos_options_parsing():
    opts = parse_kerberos_options(
        use_kerberos=True,
        aes_key="a" * 32,
        kdc_host="dc.corp.local",
        dc_ip="10.0.0.1",
        ccache="/tmp/krb5cc",
    )
    assert opts.use_kerberos
    assert opts.aes_key == "a" * 32
    assert opts.kdc_host == "dc.corp.local"


def test_aes_key_validation():
    assert len(parse_aes_key("b" * 64)) == 64
    with pytest.raises(ValueError):
        parse_aes_key("not-hex")


def test_credentials_kerberos_mode():
    c = credentials_from_fields(
        username="alice",
        domain="CORP",
        password="x",
        use_kerberos=True,
        aes_key="c" * 32,
        kdc_host="dc.corp.local",
    )
    assert c.use_kerberos
    assert c.auth_mode() == "kerberos"
    assert c.display_user().startswith("krb:")
    assert "aes_key" not in c.public_dict() or c.public_dict()["has_aes_key"] is True


def test_kerberos_fingerprint_differs():
    a = credentials_from_fields(username="u", password="p", use_kerberos=True, kdc_host="dc1")
    b = credentials_from_fields(username="u", password="p", use_kerberos=True, kdc_host="dc2")
    assert a.fingerprint() != b.fingerprint()
