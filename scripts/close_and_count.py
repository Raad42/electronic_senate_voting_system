#!/usr/bin/env python3
"""Closes voting and runs the count for one contest, signing in as the demo officials.
Use it during the demo after people have voted, so the recount screen has a result to work on.

    .venv/bin/python scripts/close_and_count.py                    # senate-2026 SA
    .venv/bin/python scripts/close_and_count.py --state VIC

It goes through Nginx with the same checks as the browser: password + one-time code sign-in,
CSRF token, and a fresh step-up code for START_COUNT. Needs scripts/demo_officials.py to have
created the accounts. (The frontend has no screen for these two steps yet.)
"""
import argparse
import json
import sys
import time
from pathlib import Path

import httpx
import pyotp

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://localhost:8443"
STORE = ROOT / "keys" / "demo" / "officials.json"
used_codes: dict[str, str] = {}


def code_for(account: dict) -> str:
    """The next one-time code this account has not used yet (each code works once)."""
    totp = pyotp.TOTP(account["secret"])
    while (code := totp.now()) == used_codes.get(account["username"]):
        time.sleep(1)
    used_codes[account["username"]] = code
    return code


def sign_in(account: dict, role: str) -> tuple[httpx.Client, str]:
    http = httpx.Client(base_url=BASE, verify=str(ROOT / "keys" / "nginx" / "ca.crt"), timeout=60)
    r = http.post("/api/auth/officials/login", json={"username": account["username"], "password": account["password"],
                                                     "otp": code_for(account), "role": role})
    if r.status_code != 200:
        sys.exit(f"{account['username']} could not sign in: {r.text}")
    return http, http.get("/api/auth/session").json()["csrfToken"]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--election", default="senate-2026")
    p.add_argument("--state", default="SA")
    a = p.parse_args()
    if not STORE.exists():
        sys.exit("No demo officials yet. Run: .venv/bin/python scripts/demo_officials.py")
    accounts = json.loads(STORE.read_text())
    suffix = a.state.lower()
    contest = {"election_id": a.election, "state": a.state}

    eo = accounts.get(f"eo.{suffix}")
    co = accounts.get(f"co.{suffix}")
    if not eo or not co:
        sys.exit(f"No demo officials eo.{suffix} / co.{suffix} in {STORE}")

    http, csrf = sign_in(eo, "ELECTION_OFFICIAL")
    r = http.post(f"/api/ballot/elections/{a.election}/contests/{a.state}/close", headers={"X-CSRF-Token": csrf})
    print(f"Close voting ({eo['username']}): {r.status_code} {r.json().get('status') or r.json().get('detail')}")

    http, csrf = sign_in(co, "COUNT_OPERATOR")
    print("Waiting for a fresh one-time code for the START_COUNT step-up...")
    r = http.post("/api/auth/officials/step-up", headers={"X-CSRF-Token": csrf},
                  json={"otp": code_for(co), "action": "START_COUNT", "resource": contest})
    if r.status_code != 200:
        sys.exit(f"Step-up failed: {r.text}")
    r = http.post("/api/count/counts", headers={"X-CSRF-Token": csrf}, json=contest)
    if r.status_code != 200:
        sys.exit(f"Count failed: {r.status_code} {r.text}")
    result = r.json()
    print(f"Count ({co['username']}): {result['formal_ballots']} formal ballots, quota {result['quota']}, "
          f"elected in order: {', '.join(result['elected'])}")
    print(f"Audit chain verified ({result['chain_verified']} entries). The recount phase is now open.")


if __name__ == "__main__":
    main()
