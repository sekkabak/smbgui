# smbgui

Dark-theme **SMB file explorer** for authorized lab / admin use. FastAPI + Impacket `SMBConnection`, SQLite/FTS cache, WebSocket progress, bookmarks, multi-host sessions, bulk ops, folder zip, Kerberos, SOCKS proxy, and resumable transfers.

> **Authorized use only.** Point this only at hosts and credentials you are allowed to access.

## Security warnings

- The app is a **local operator tool**, not a multi-tenant SaaS. Anyone who can reach the HTTP port can use connected SMB sessions.
- After `POST /api/connect`, the UI stores an **HttpOnly cookie** (`smbgui_sid`) so **passwords / NTLM hashes / AES keys are not put in GET query strings**. Credentials remain in **server memory** for that opaque session.
- **Always publish to loopback** (`127.0.0.1`). Docker Compose does this by default. Do not expose `0.0.0.0` without your own auth reverse proxy.
- See [SECURITY.md](SECURITY.md).

## Feature matrix

| Feature | Status |
|--------|--------|
| Password / NTLM PTH (`nt` / `lm:nt`) / Guest account | ✅ |
| Kerberos (`kerberosLogin`, AES key, ccache/`KRB5CCNAME`, KDC/DC IP, optional SPN→remoteName) | ✅ (unit-wired; needs real KDC to live-verify) |
| Connection string `user:pass@host[:port]` / `DOMAIN\user:…` / IPv6 `[::1]:445` | ✅ |
| Multi-host session pool + host switcher | ✅ |
| List shares/dirs, upload/download, mkdir/rename/delete, copy/move, zip, properties, FTS | ✅ |
| Resumable transfers + background jobs | ✅ |
| SOCKS5/4 / HTTP CONNECT proxy (serialized Impacket socket patch) | ✅ |
| Administrative / hidden `-shares` + IPC$ handling | ✅ |
| Docker + Compose (127.0.0.1 publish) | ✅ |
| Full Windows redirector (leases, multi-channel, durable handles, full DFS, EA/ADS, CopyChunk) | ❌ **non-goal** |
| Traffic masquerading / EDR evasion | ❌ **intentionally out of scope** |

## Guest vs anonymous

- **Guest** (`guest=true`): logs on as the Windows **Guest** account (`Guest` / empty password). If that fails, the client falls back to a null session.
- **Anonymous / null session**: connect with empty username and password (not the Guest checkbox). Impacket `login("", "")`.
- Many servers map Guest and anonymous similarly; behavior depends on the target.

## Kerberos notes

1. Obtain a TGT (e.g. `getTGT.py CORP/alice:Password -dc-ip 10.0.0.10`) and set `KRB5CCNAME`, **or** supply password / NT hash / AES key with `use_kerberos=true`.
2. Set `kdc_host` and/or `dc_ip` for the KDC only.
3. Connect to the **file server** hostname/IP. TCP always goes to that host; `dc_ip` is **not** used as `remoteHost`.
4. Optional `spn` (e.g. `cifs/files01.corp.local`) overrides Kerberos `remoteName`.

## Quick start

```bash
cd smbgui
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# optional local Samba fixture (Linux)
./scripts/setup_samba.sh

PYTHONPATH=. uvicorn app.main:app --host 127.0.0.1 --port 8787
```

Open **http://127.0.0.1:8787**

Examples:

- Password: `smbtest:TestPass123!@127.0.0.1:1445`
- PTH: `smbtest@127.0.0.1:1445` + NT hash field
- IPv6: `user:pass@[::1]:445`

## Docker

```bash
docker compose up -d --build
```

| Variable | Default | Meaning |
|----------|---------|---------|
| `SMBGUI_DATA_DIR` | `<repo>/data` | Persistent cache + bookmarks |
| `SMBGUI_HOST` | `127.0.0.1` (container often `0.0.0.0` behind loopback publish) | Bind address |
| `SMBGUI_PORT` | `8787` | Listen port |

## Reliability

Retry with backoff, auto-reconnect, resumable `.part` downloads, upload resume with remote EOF query/set, SOCKS proxy. Knobs via env / `POST /api/reliability` / UI.

DFS `STATUS_PATH_NOT_COVERED` is **not** retried forever — connect to the concrete file server/share (full DFS referral following is a non-goal).

## Limitations (vs a Windows client)

- No dialect pinning, leases, multi-channel, durable handles.
- No full DFS referral chasing, EA/ADS, or CopyChunk.
- No complete NTSTATUS map (selected codes only).
- Long transfers hold the per-session Impacket lock for the duration of the SMB call; use background jobs for multi-hour work.
- Proxy support serializes Impacket’s process-wide socket monkeypatch under a lock (Impacket creates its own sockets).

## API auth after connect

| Style | Use |
|-------|-----|
| Browser UI | Cookie `smbgui_sid` after connect; GET queries carry `host` / `share` / `path` / optional `sid` only |
| Scripts | Still may pass password/hash on POST bodies or GET (discouraged for GET); or send `sid` from connect response |

Errors: `{ "error": { "code", "message" } }`

## License

MIT — see [LICENSE](LICENSE).
