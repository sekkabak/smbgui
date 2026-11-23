"""Connection-string and credential parsing for SMB auth (password, PTH, guest, Kerberos)."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Credentials:
    """Parsed SMB credentials including optional Kerberos options."""

    username: str
    password: str = ""
    domain: str = ""
    lmhash: str = ""
    nthash: str = ""
    is_guest: bool = False
    # True when using a null session (anonymous): login("", "").
    # Guest account login uses username Guest — see credentials_from_fields(guest=True).
    is_anonymous: bool = False
    is_hash: bool = False
    # Kerberos
    use_kerberos: bool = False
    aes_key: str = ""
    kdc_host: str = ""
    dc_ip: str = ""
    ccache: str = ""  # path or empty → honor KRB5CCNAME
    # Optional CIFS SPN host override (e.g. "cifs/files01.corp.local" or "files01.corp.local").
    # Applied as SMBConnection remoteName for Kerberos ticket selection.
    spn: str = ""

    def fingerprint(self) -> str:
        """Stable short fingerprint for cache keys (no raw secrets in key)."""
        if self.is_guest:
            material = "guest" if not self.is_anonymous else "anonymous"
        elif self.use_kerberos:
            material = (
                f"{self.domain}\\{self.username}|krb|"
                f"{self.aes_key}|{self.kdc_host}|{self.ccache}|{self.lmhash}:{self.nthash}|p|{self.password}"
            )
        elif self.is_hash:
            material = f"{self.domain}\\{self.username}|h|{self.lmhash}:{self.nthash}"
        else:
            material = f"{self.domain}\\{self.username}|p|{self.password}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def display_user(self) -> str:
        if self.is_guest:
            return "guest"
        prefix = ""
        if self.use_kerberos:
            prefix = "krb:"
        if self.domain:
            return f"{prefix}{self.domain}\\{self.username}"
        return f"{prefix}{self.username or '(empty)'}"

    def auth_mode(self) -> str:
        if self.is_anonymous:
            return "anonymous"
        if self.is_guest:
            return "guest"
        if self.use_kerberos:
            return "kerberos"
        if self.is_hash:
            return "pth"
        return "password"

    def public_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "domain": self.domain,
            "guest": self.is_guest,
            "anonymous": self.is_anonymous,
            "is_hash": self.is_hash,
            "use_kerberos": self.use_kerberos,
            "kdc_host": self.kdc_host,
            "dc_ip": self.dc_ip,
            "ccache": bool(self.ccache or os.environ.get("KRB5CCNAME")),
            "has_aes_key": bool(self.aes_key),
            "spn": self.spn or "",
            "auth_mode": self.auth_mode(),
            "cred_fp": self.fingerprint(),
            "display_user": self.display_user(),
        }


# user[:secret]@host[:port] with optional DOMAIN\ prefix.
# Host may be a hostname, IPv4, or bracketed IPv6 ([::1] / [2001:db8::1]:445).
_CONN_RE = re.compile(
    r"^(?:(?P<domain>[^\\/@]+)\\)?(?P<user>[^:@]+)(?::(?P<secret>.*))?@"
    r"(?:\[(?P<ipv6>[^\]]+)\]|(?P<host>[^:\[\]]+))"
    r"(?::(?P<port>\d+))?$"
)


def parse_connection_string(conn: str) -> tuple[str, int, Credentials]:
    """
    Parse strings like:
      user:pass@server
      user:pass@server:445
      DOMAIN\\user:pass@server
      user@server
      user:pass@[::1]:445
    Returns (host, port, Credentials).
    """
    conn = (conn or "").strip()
    if not conn:
        raise ValueError("empty connection string")

    m = _CONN_RE.match(conn)
    if not m:
        raise ValueError(
            "invalid connection string; expected user:pass@host[:port], "
            "DOMAIN\\user:pass@host[:port], or user:pass@[ipv6]:port"
        )

    host = m.group("ipv6") or m.group("host")
    port = int(m.group("port") or 445)
    user = m.group("user") or ""
    domain = m.group("domain") or ""
    secret = m.group("secret")
    if secret is None:
        secret = ""

    creds = Credentials(username=user, password=secret, domain=domain)
    return host, port, creds


def spn_to_remote_name(spn: str) -> str:
    """Extract host from SPN like cifs/files01.corp.local@REALM or files01.corp.local."""
    s = (spn or "").strip()
    if not s:
        return ""
    if "@" in s:
        s = s.split("@", 1)[0]
    if "/" in s:
        s = s.split("/", 1)[1]
    return s.strip()


def parse_hash(hash_str: str) -> tuple[str, str]:
    """Accept NT hash alone (32 hex) or LM:NT. Empty LM becomes 32 zeros."""
    s = (hash_str or "").strip()
    if not s:
        raise ValueError("empty hash")

    if ":" in s:
        lm, nt = s.split(":", 1)
        lm = lm.strip()
        nt = nt.strip()
    else:
        lm = ""
        nt = s

    if lm and not re.fullmatch(r"[0-9a-fA-F]{32}", lm):
        raise ValueError("LM hash must be 32 hex characters")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", nt):
        raise ValueError("NT hash must be 32 hex characters")

    if not lm:
        lm = "0" * 32
    return lm.lower(), nt.lower()


def parse_aes_key(aes_key: str) -> str:
    """Validate AES128 (32 hex) or AES256 (64 hex) key."""
    s = (aes_key or "").strip().lower()
    if not s:
        return ""
    if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{64}", s):
        raise ValueError("AES key must be 32 (AES128) or 64 (AES256) hex characters")
    return s


@dataclass
class KerberosOptions:
    use_kerberos: bool = False
    aes_key: str = ""
    kdc_host: str = ""
    dc_ip: str = ""
    ccache: str = ""
    spn: str = ""


def parse_kerberos_options(
    use_kerberos: bool = False,
    aes_key: str = "",
    kdc_host: str = "",
    dc_ip: str = "",
    ccache: str = "",
    spn: str = "",
) -> KerberosOptions:
    """Parse/validate Kerberos-related connect options (no network I/O)."""
    opts = KerberosOptions(
        use_kerberos=bool(use_kerberos),
        aes_key=parse_aes_key(aes_key) if aes_key else "",
        kdc_host=(kdc_host or "").strip(),
        dc_ip=(dc_ip or "").strip(),
        ccache=(ccache or "").strip(),
        spn=(spn or "").strip(),
    )
    if opts.use_kerberos and opts.ccache and not os.path.exists(opts.ccache):
        # Allow non-existent path at parse time if env will supply; warn via flag
        pass
    return opts


def credentials_from_fields(
    username: str = "",
    password: str = "",
    domain: str = "",
    hash_str: Optional[str] = None,
    guest: bool = False,
    use_kerberos: bool = False,
    aes_key: str = "",
    kdc_host: str = "",
    dc_ip: str = "",
    ccache: str = "",
    spn: str = "",
) -> Credentials:
    """Build Credentials from discrete form fields.

    guest=True logs on as the Guest account (username Guest, empty password).
    For a null/anonymous session use username=\"\" with guest=False, or set
    anonymous via credentials_from_fields(username=\"\", password=\"\") — the
    SMB layer treats empty user without guest flag as normal login(\"\",\"\").
    """
    if guest:
        # Real Guest account (not null session). Servers may still map Guest→anonymous.
        return Credentials(username="Guest", password="", domain="", is_guest=True)

    username = (username or "").strip()
    domain = (domain or "").strip()
    if "\\" in username and not domain:
        domain, username = username.split("\\", 1)

    krb = parse_kerberos_options(
        use_kerberos=use_kerberos,
        aes_key=aes_key,
        kdc_host=kdc_host,
        dc_ip=dc_ip,
        ccache=ccache,
        spn=spn,
    )

    lm = nt = ""
    is_hash = False
    if hash_str:
        lm, nt = parse_hash(hash_str)
        is_hash = True

    return Credentials(
        username=username or "",
        password="" if is_hash and not use_kerberos else (password or ""),
        domain=domain,
        lmhash=lm,
        nthash=nt,
        is_hash=is_hash and not use_kerberos,
        use_kerberos=krb.use_kerberos,
        aes_key=krb.aes_key,
        kdc_host=krb.kdc_host,
        dc_ip=krb.dc_ip,
        ccache=krb.ccache,
        spn=krb.spn,
    )


def nt_hash_hex(password: str) -> str:
    """Compute NT hash (MD4 of UTF-16LE password) as lowercase hex."""
    try:
        from Cryptodome.Hash import MD4
    except ImportError:
        from Crypto.Hash import MD4  # type: ignore

    h = MD4.new()
    h.update(password.encode("utf-16le"))
    return h.hexdigest()
