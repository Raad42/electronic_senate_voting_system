#!/usr/bin/env python3
"""End-to-end check of the endpoints the React frontend calls (frontend/src/api/client.ts),
through Nginx exactly as the browser calls them. Needs the stack running and the demo officials:

    docker compose up -d --build
    .venv/bin/python scripts/demo_officials.py          # once; Ctrl+C after the codes appear
    .venv/bin/python tests/e2e/frontend_contract_test.py

Uses the senate-2026 SA contest. It votes, closes voting, counts and runs a court-ordered
recount, so run it on a fresh stack (`docker compose down -v` first) for a clean demo after.
Prints PASS/FAIL per check; exit code 1 if anything failed.
"""
import json
import os
import sys
import time
from pathlib import Path

import httpx
import pyotp

ROOT = Path(__file__).resolve().parents[2]
BASE = os.getenv("SMOKE_BASE_URL", "https://localhost:8443")
CA = str(ROOT / "keys" / "nginx" / "ca.crt")
ELECTION, STATE = "senate-2026", "SA"
ACCOUNTS = json.loads((ROOT / "keys" / "demo" / "officials.json").read_text())
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        failures.append(name)
        if detail:
            print(f"        {detail[:300]}")


def client() -> httpx.Client:
    return httpx.Client(base_url=BASE, verify=CA, timeout=30)


def fresh_code(secret: str, last: str | None) -> str:
    """Each one-time code works once, so wait for the next one when needed."""
    totp = pyotp.TOTP(secret)
    while (code := totp.now()) == last:
        time.sleep(1)
    return code


LAST_CODE: dict[str, str] = {}   # per account: the server refuses a code it has already seen


class Official:
    def __init__(self, username: str, role: str):
        self.account = ACCOUNTS[username]
        self.http = client()
        self.csrf = ""
        r = self.login(role)
        check(f"{username} signs in as {role}", r.status_code == 200, r.text)

    def code(self) -> str:
        name = self.account["username"]
        LAST_CODE[name] = fresh_code(self.account["secret"], LAST_CODE.get(name))
        return LAST_CODE[name]

    def login(self, role: str) -> httpx.Response:
        r = self.http.post("/api/auth/officials/login", json={
            "username": self.account["username"], "password": self.account["password"],
            "otp": self.code(), "role": role})
        if r.status_code == 200:
            self.csrf = self.http.get("/api/auth/session").json()["csrfToken"]
        return r

    def post(self, path: str, body: dict | None = None, csrf: bool = True) -> httpx.Response:
        return self.http.post(path, json=body or {}, headers={"X-CSRF-Token": self.csrf} if csrf else {})


def authorise(voter: str, password: str, **extra) -> httpx.Response:
    return client().post("/api/auth/elector/authorisation",
                         json={"state": STATE, "voterId": voter, "password": password, "electionId": ELECTION, **extra})


def main() -> None:
    api = client()

    print("Voter flow (GR01, GR02)")
    config = api.get(f"/api/ballots/config?state={STATE}&electionId={ELECTION}").json()
    check("ballot config has the frontend shape",
          {"electionId", "state", "configurationVersion", "candidates"} <= set(config)
          and {"candidateId", "displayName", "party"} <= set(config["candidates"][0]), json.dumps(config))

    r = authorise("SA-0001", "sa-voter-0001")
    auth = r.json()
    check("voter gets an authorisation {authorisationToken, state, expiresAt}",
          r.status_code == 200 and {"authorisationToken", "state", "expiresAt"} <= set(auth), r.text)
    token = auth.get("authorisationToken", "")
    claims = json.loads(__import__("base64").urlsafe_b64decode(token.split(".")[1] + "=="))
    check("the authorisation carries no voter identity", "SA-0001" not in json.dumps(claims), json.dumps(claims))

    r = authorise("SA-0001", "sa-voter-0001")
    check("a second authorisation for the same voter is refused (409)",
          r.status_code == 409 and r.json()["error"]["code"] == "ALREADY_VOTED", r.text)
    r = authorise("SA-0001", "sa-voter-0001", electionId="made-up-election")
    check("an invented election id gets no extra authorisation (double-vote fix)", r.status_code == 404, r.text)
    r = authorise("SA-0002", "wrong-password")
    check("wrong password is refused with the generic message",
          r.status_code == 401 and r.json()["error"]["message"] == "Voter ID or password is incorrect", r.text)
    r = client().post("/api/auth/elector/authorisation", json={"state": STATE})
    check("no voter ID / password -> refused (422)", r.status_code == 422, r.text)

    ballot = {"authorisationToken": token, "electionId": ELECTION, "state": STATE,
              "selections": [{"candidateId": "CAND-063", "rank": 1}],
              "configurationVersion": config["configurationVersion"]}
    stale = api.post("/api/ballots", json={**ballot, "configurationVersion": "cfg-old"})
    check("a ballot for an old ballot-paper version is refused without using the authorisation",
          stale.status_code == 409 and stale.json()["error"]["code"] == "CONFIGURATION_CHANGED", stale.text)
    r = api.post("/api/ballots", json=ballot)
    receipt = r.json()
    check("single-choice ballot accepted {submissionId, status, submittedAt}",
          r.status_code in (200, 201) and receipt.get("status") == "ACCEPTED" and receipt.get("submissionId"), r.text)
    r = api.post("/api/ballots", json=ballot)
    check("replaying the authorisation is refused (409 AUTHORISATION_REPLAY)",
          r.status_code == 409 and r.json()["error"]["code"] == "AUTHORISATION_REPLAY", r.text)

    for n, choice in [(2, "CAND-063"), (3, "CAND-041"), (4, "CAND-041"), (5, "CAND-043")]:
        time.sleep(3)   # stay under Nginx's voting limit (20 a minute per address)
        t = authorise(f"SA-000{n}", f"sa-voter-000{n}").json()["authorisationToken"]
        ok = api.post("/api/ballots", json={**ballot, "authorisationToken": t,
                                            "selections": [{"candidateId": choice, "rank": 1}]}).status_code
        check(f"SA-000{n} votes", ok in (200, 201))

    print("Officials: session, CSRF, close, count")
    eo = Official("eo.sa", "ELECTION_OFFICIAL")
    session = eo.http.get("/api/auth/session").json()
    check("session has the frontend shape {role, sessionExpiresAt, scope{state, electionId, countId}}",
          session.get("role") == "ELECTION_OFFICIAL" and session["scope"]["state"] == STATE
          and session["scope"]["electionId"] == ELECTION and "sessionExpiresAt" in session, json.dumps(session))
    r = eo.post(f"/api/ballot/elections/{ELECTION}/contests/{STATE}/close", csrf=False)
    check("a state-changing request without the CSRF token is refused", r.status_code == 403, r.text)
    r = eo.post(f"/api/ballot/elections/{ELECTION}/contests/{STATE}/close")
    check("election official closes voting", r.status_code == 200, r.text)

    co = Official("co.sa", "COUNT_OPERATOR")
    contest = {"election_id": ELECTION, "state": STATE}
    r = co.post("/api/auth/officials/step-up", {"otp": co.code(), "action": "START_COUNT", "resource": contest})
    check("count operator steps up", r.status_code == 200, r.text)
    r = co.post("/api/count/counts", contest)
    check("count runs", r.status_code == 200, r.text)

    print("Recount screen (GR03)")
    exclusion = {"electionId": ELECTION, "state": STATE, "candidateId": "CAND-041", "recountPhase": "OPEN",
                 "exclusionGround": "COURT_ORDER", "supportingEvidenceId": "HC-2026-17"}
    r = co.post("/api/recount/exclusions", {**exclusion, "stepUpCode": "000000"})
    check("a count operator cannot enter an exclusion (403)", r.status_code == 403, r.text)

    rd = Official("rd.sa", "RECOUNT_DELEGATE")
    r = rd.post("/api/recount/exclusions", {**exclusion, "candidateId": "CAND-052", "stepUpCode": "000000"})
    check("VIC candidate CAND-052 is rejected for the SA delegate",
          r.status_code == 200 and r.json()["status"] == "REJECTED", r.text)
    r = rd.post("/api/recount/exclusions", {**exclusion, "supportingEvidenceId": "HC-0000-00", "stepUpCode": "000000"})
    check("unverifiable evidence is rejected", r.status_code == 200 and r.json()["status"] == "REJECTED", r.text)
    r = rd.post("/api/recount/exclusions", {**exclusion, "exclusionGround": "OTHER", "stepUpCode": "000000"})
    check("a non-court ground is rejected", r.status_code == 200 and r.json()["status"] == "REJECTED", r.text)

    valid = pyotp.TOTP(rd.account["secret"])
    wrong = next(c for c in ("000000", "111111", "222222") if not valid.verify(c, valid_window=1))
    r = rd.post("/api/recount/exclusions", {**exclusion, "stepUpCode": wrong})
    check("a wrong step-up code ends the session (401)", r.status_code == 401, r.text)
    r = rd.http.get("/api/auth/session")
    check("...and the session stays ended", r.status_code == 401, r.text)

    rd = Official("rd.sa", "RECOUNT_DELEGATE")
    r = rd.post("/api/recount/exclusions", {**exclusion, "stepUpCode": rd.code()})
    body = r.json()
    check("court-ordered exclusion is APPROVED with exclusionId and auditEventId",
          r.status_code == 200 and body.get("status") == "APPROVED" and body.get("exclusionId")
          and body.get("auditEventId"), r.text)
    check("CAND-041 is not elected in the recount", "CAND-041" not in body.get("elected", ["CAND-041"]), r.text)

    print("Audit page (GR05)")
    r = rd.http.get("/api/audit/events?limit=50")
    check("only an AUDITOR can read the audit log (403)", r.status_code == 403, r.text)
    aud = Official("aud.demo", "AUDITOR")
    r = aud.http.get("/api/audit/events?limit=50")
    data = r.json()
    fields = {"eventId", "eventType", "actorType", "actorId", "resourceId", "electionId", "state", "countId",
              "timestamp", "previousHash", "eventHash"}
    check("audit events have the frontend shape and chainStatus VALID",
          r.status_code == 200 and data.get("chainStatus") == "VALID" and data["events"]
          and fields <= set(data["events"][0]), r.text[:300])
    check("newest event first", data["events"][0]["eventType"] in ("RECOUNT_EXECUTED", "STEP_UP_SATISFIED")
          or data["events"][0]["eventId"] > data["events"][-1]["eventId"])

    print("Rate limiting (GR04)")
    burst = [client().post("/api/auth/elector/authorisation",
                           json={"state": STATE, "voterId": "SA-0099", "password": "x"}) for _ in range(40)]
    limited = [r for r in burst if r.status_code == 429]
    check("a burst of authorisation requests is rate limited (429)", bool(limited))
    if limited:
        check("429 has the JSON error shape and Retry-After",
              limited[0].json()["error"]["code"] == "RATE_LIMITED" and limited[0].headers.get("Retry-After") == "60",
              limited[0].text)

    print("\nALL PASSED" if not failures else f"\n{len(failures)} FAILED: {failures}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
