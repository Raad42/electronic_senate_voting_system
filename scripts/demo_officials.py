#!/usr/bin/env python3
"""Demo accounts for the frontend: one official per role and state, plus a live view of their codes.

    .venv/bin/python scripts/demo_officials.py          # create the accounts (if needed), then show codes
    .venv/bin/python scripts/demo_officials.py codes    # just show the codes

Accounts are created with `app.manage` inside the auth container, exactly as a real official
would be. Passwords and TOTP secrets are kept in keys/demo/officials.json (keys/ is never
committed) so the codes can be shown here instead of in an authenticator app. Demo use only.

`multi.nsw` holds two roles (COUNT_OPERATOR and RECOUNT_DELEGATE for NSW) to show that a
session activates only one of them (Milestone 2 Section 2.3).
"""
import json
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

import pyotp

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "keys" / "demo" / "officials.json"
NSW, VIC = ("SEN2028", "NSW"), ("SEN2028", "VIC")
SA26, VIC26 = ("senate-2026", "SA"), ("senate-2026", "VIC")   # the election the frontend uses
ACCOUNTS = {
    "eo.sa": [("ELECTION_OFFICIAL", *SA26)],
    "co.sa": [("COUNT_OPERATOR", *SA26)],
    "rd.sa": [("RECOUNT_DELEGATE", *SA26)],
    "rd.vic26": [("RECOUNT_DELEGATE", *VIC26)],
    "multi.sa": [("COUNT_OPERATOR", *SA26), ("RECOUNT_DELEGATE", *SA26)],
    "eo.nsw": [("ELECTION_OFFICIAL", *NSW)],
    "eo.vic": [("ELECTION_OFFICIAL", *VIC)],
    "co.nsw": [("COUNT_OPERATOR", *NSW)],
    "co.vic": [("COUNT_OPERATOR", *VIC)],
    "rd.nsw": [("RECOUNT_DELEGATE", *NSW)],
    "rd.vic": [("RECOUNT_DELEGATE", *VIC)],
    "aud.demo": [("AUDITOR",)],
    "multi.nsw": [("COUNT_OPERATOR", *NSW), ("RECOUNT_DELEGATE", *NSW)],
}


def manage(*args: str, password: str | None = None) -> subprocess.CompletedProcess:
    stdin = f"{password}\n{password}\n" if password else ""
    return subprocess.run(["docker", "compose", "exec", "-T", "auth", "python", "-m", "app.manage", *args],
                          input=stdin, capture_output=True, text=True, cwd=ROOT)


def role_args(role: tuple) -> list[str]:
    name, *scope = role
    return ["--role", name] + (["--election", scope[0], "--state", scope[1]] if scope else [])


def create(username: str, roles: list[tuple]) -> dict | None:
    password = secrets.token_urlsafe(12)
    r = manage("create-official", "--username", username, *role_args(roles[0]), password=password)
    if r.returncode != 0:
        if "unique" in r.stderr.lower() or "duplicate" in r.stderr.lower():
            return None
        sys.exit(f"Could not create {username}:\n{r.stderr.strip()[-500:]}")
    for extra in roles[1:]:
        manage("add-role", "--username", username, *role_args(extra))
    secret = re.search(r"secret=([A-Z2-7]+)", r.stdout).group(1)
    return {"username": username, "password": password, "secret": secret,
            "roles": [f"{x[0]}" + (f" {x[2]}" if len(x) > 1 else "") for x in roles]}


def setup() -> None:
    store = json.loads(STORE.read_text()) if STORE.exists() else {}
    store = {k: v for k, v in store.items() if k in ACCOUNTS}
    for username, roles in ACCOUNTS.items():
        account = create(username, roles)
        if account:
            store[username] = account
            print(f"  created {username}")
        elif username in store:
            print(f"  {username} already exists")
        else:
            print(f"  {username} exists but its secret isn't in {STORE.relative_to(ROOT)}; "
                  "reset with `docker compose down -v` to recreate it")
    STORE.parent.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(store, indent=2))
    STORE.chmod(0o600)


def show_codes() -> None:
    if not STORE.exists():
        sys.exit("No demo accounts yet. Run: .venv/bin/python scripts/demo_officials.py")
    store = json.loads(STORE.read_text())
    print("\nSign in at /official and pick the role. Each code works once; wait for the next one to step up."
          "  Ctrl+C to stop.\n")
    print(f"  {'OPERATOR ID':<11} {'ROLES':<40} {'PASSWORD':<18} CODE")
    lines = len(store)
    try:
        while True:
            left = 30 - int(time.time()) % 30
            for a in store.values():
                print(f"\033[K  {a['username']:<11} {', '.join(a.get('roles', [])):<40} {a['password']:<18} "
                      f"\033[1m{pyotp.TOTP(a['secret']).now()}\033[0m")
            print(f"\033[K  next codes in {left:2d}s", end="", flush=True)
            time.sleep(1)
            print(f"\r\033[{lines}A", end="")
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    if sys.argv[1:] != ["codes"]:
        print("Creating demo officials...")
        setup()
    show_codes()
