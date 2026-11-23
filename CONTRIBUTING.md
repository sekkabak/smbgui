# Contributing

## Dev setup

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
PYTHONPATH=. pytest -q
```

Optional local Samba fixture: `./scripts/setup_samba.sh` (Linux) then e2e tests
against `127.0.0.1:1445`.

## Guidelines

- Prefer tests for auth, pooling, resume, and resilience behavior.
- Do not add EDR evasion / traffic masquerading features (explicit non-goal).
- Never commit secrets, `.env`, `*.ccache`, pcaps, or production hashes.
- Keep the UI bound to loopback in docs and Compose examples.
