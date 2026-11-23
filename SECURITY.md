# Security

## Authorized use only

smbgui is a lab / admin SMB file explorer built on Impacket. Use it only against
systems and credentials you are authorized to access. Misuse may violate law and
policy.

## Threat model (honest)

- The HTTP UI historically had **no login of its own**. After connect, the UI uses
  an **HttpOnly opaque session cookie** (`smbgui_sid`) so passwords / NTLM hashes /
  AES keys are **not** placed in GET query strings. Credentials still live in
  **server process memory** for the life of that session.
- There is still **no multi-user authn/authz** on the web UI. Anyone who can reach
  the listening port can drive SMB operations for whatever sessions exist.
- **Always bind to loopback** (`127.0.0.1`) unless you add your own reverse-proxy
  auth. Docker Compose publishes `127.0.0.1:8787` by design.
- Do not commit `.env`, ccache files, packet captures, or production hashes.

## Reporting

If you find a vulnerability in this repository, open a private report to the
maintainers (or a GitHub security advisory if enabled). Please do not file public
issues that include live credentials or customer data.
