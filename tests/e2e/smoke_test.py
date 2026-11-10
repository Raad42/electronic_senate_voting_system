#!/usr/bin/env python3
"""End-to-end check of the running stack, through Nginx exactly as a browser would call it.

    docker compose down -v && docker compose up -d --build   # fresh databases
    .venv/bin/python tests/e2e/smoke_test.py

Creates officials (via `docker compose exec auth python -m app.manage`), runs a whole election
(nominations, party order, open, vote, close, count, court-ordered recount, audit verify) and
checks the Milestone 2 controls on the way. Prints PASS/FAIL per check; exit code 1 if anything
failed. SMOKE_BASE_URL and SMOKE_COMPOSE_PROJECT point it at another stack.
"""
import base64
import email.utils
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

import httpx
import jwt
import pyotp
from cryptography.hazmat.primitives import serialization

from common.audit_chain import canonical  # same canonical JSON the server verifies

ROOT = Path(__file__).resolve().parents[2]
BASE = os.getenv("SMOKE_BASE_URL", "https://localhost:8443")
COMPOSE = ["docker", "compose"] + (["-p", os.environ["SMOKE_COMPOSE_PROJECT"]] if os.getenv("SMOKE_COMPOSE_PROJECT") else [])
CA = str(ROOT / "keys" / "nginx" / "ca.crt")
ELECTION = "SEN2028"
NSW = {"election_id": ELECTION, "state": "NSW"}
VIC = {"election_id": ELECTION, "state": "VIC"}
api = httpx.Client(base_url=BASE, verify=CA, timeout=30)
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def call(client: httpx.Client, method: str, path: str, **kwargs) -> httpx.Response:
    """Retries on Nginx's rate-limit 429 so the smoke test itself is not blocked by it."""
    for _ in range(10):
        r = client.request(method, path, **kwargs)
        if r.status_code != 429 or "Too many failed" in r.text:
            return r
        time.sleep(3)
    return r


def check_clock(max_skew: float = 15) -> None:
    """TOTP codes only last 30 seconds, so the containers' clock must match this computer's.
    Docker Desktop's VM clock drifts after the Mac sleeps."""
    server = email.utils.parsedate_to_datetime(api.get("/api/ballot/health").headers["date"]).timestamp()
    skew = server - time.time()
    if abs(skew) > max_skew:
        sys.exit(
            f"Docker's clock is {abs(skew):.0f}s {'behind' if skew < 0 else 'ahead of'} this computer, so 6-digit "
            "codes will be rejected.\nFix: restart Docker Desktop (or run: "
            "docker run --rm --privileged alpine hwclock -s), then try again."
        )


def wait_until_ready(timeout: float = 90) -> None:
    """Containers report "Started" a few seconds before the services accept requests."""
    deadline = time.time() + timeout
    paths = ("/api/auth/health", "/api/ballot/health", "/api/count/health",
             "/api/recount/health", "/api/audit/health")
    while time.time() < deadline:
        try:
            if all(api.get(p).status_code == 200 for p in paths):
                check_clock()
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    sys.exit(f"Services not ready after {timeout:.0f}s - check `docker compose ps` and `docker compose logs`")


def manage(*args: str, password: str | None = None) -> str:
    stdin = f"{password}\n{password}\n" if password else ""
    return subprocess.run([*COMPOSE, "exec", "-T", "auth", "python", "-m", "app.manage", *args],
                          input=stdin, capture_output=True, text=True, cwd=ROOT, check=True).stdout


class Official:
    """One browser: its own cookie jar, holding the HttpOnly session cookie."""

    def __init__(self, *roles: tuple):
        first = roles[0][0]
        self.username = f"{first.split('_')[0].lower()}.{secrets.token_hex(3)}"
        self.password = secrets.token_urlsafe(16)
        out = manage("create-official", "--username", self.username, *self._scope(roles[0]), password=self.password)
        for extra in roles[1:]:
            manage("add-role", "--username", self.username, *self._scope(extra))
        self.totp = pyotp.TOTP(re.search(r"secret=([A-Z2-7]+)", out).group(1))
        self.last_code = None
        self.csrf = None
        self.client = httpx.Client(base_url=BASE, verify=CA, timeout=30)

    @staticmethod
    def _scope(role: tuple) -> list[str]:
        name, *scope = role
        return ["--role", name] + (["--election", scope[0], "--state", scope[1]] if scope else [])

    def code(self) -> str:
        """A valid code different from the last one used (the server blocks reuse)."""
        now = time.time()
        for offset in (0, 30, -30):
            c = self.totp.at(now + offset)
            if c != self.last_code:
                self.last_code = c
                return c

    def login(self, role: str, otp: str | None = None) -> httpx.Response:
        r = call(self.client, "POST", "/api/auth/officials/login",
                 json={"username": self.username, "password": self.password, "otp": otp or self.code(), "role": role})
        if r.status_code == 200:
            self.csrf = r.json()["csrfToken"]
        return r

    def get(self, path: str) -> httpx.Response:
        return call(self.client, "GET", path)

    def post(self, path: str, json: dict | None = None, csrf: bool = True) -> httpx.Response:
        headers = {"X-CSRF-Token": self.csrf} if csrf and self.csrf else {}
        return call(self.client, "POST", path, json=json or {}, headers=headers)

    def step_up(self, action: str, resource: dict, otp: str | None = None) -> httpx.Response:
        return self.post("/api/auth/officials/step-up", {"otp": otp or self.code(), "action": action, "resource": resource})


def contest_path(contest: dict, suffix: str) -> str:
    return f"/api/ballot/elections/{contest['election_id']}/contests/{contest['state']}/{suffix}"


def elector_token(voter_id: str, password: str, state: str) -> httpx.Response:
    return call(api, "POST", "/api/auth/electors/authorise",
                json={"voter_id": voter_id, "password": password, "state": state, "election_id": ELECTION})


def vote(token: str, marks: dict, **kwargs) -> httpx.Response:
    return call(api, "POST", "/api/ballot/ballots", headers={"Authorization": f"Bearer {token}"},
                **({"json": marks} if marks is not None else {}), **kwargs)


def set_up_contest(eo: Official, contest: dict, order: list[str]) -> None:
    eo.step_up("COMMIT_NOMINATIONS", contest)
    eo.post(contest_path(contest, "nominations/commit"))
    eo.step_up("FIX_PARTY_ORDER", contest)
    eo.post(contest_path(contest, "party-order"), {"group_order": order})
    eo.post(contest_path(contest, "open"))


def main() -> int:
    wait_until_ready()
    print("Setup")
    eo_nsw = Official(("ELECTION_OFFICIAL", ELECTION, "NSW"))
    eo_vic = Official(("ELECTION_OFFICIAL", ELECTION, "VIC"))
    co_nsw = Official(("COUNT_OPERATOR", ELECTION, "NSW"), ("RECOUNT_DELEGATE", ELECTION, "NSW"))
    rd_nsw = Official(("RECOUNT_DELEGATE", ELECTION, "NSW"))
    rd_vic = Official(("RECOUNT_DELEGATE", ELECTION, "VIC"))
    auditor = Official(("AUDITOR",))
    locked = Official(("AUDITOR",))

    print("Official authentication (Sections 2.3, 2.5)")
    r = eo_nsw.login("COUNT_OPERATOR")
    check("sign-in with a role the official doesn't hold is refused", r.status_code == 401, r.text)
    r = eo_nsw.login("ELECTION_OFFICIAL")
    cookie = r.headers.get("set-cookie", "")
    check("password + one-time code opens a session", r.status_code == 200, r.text)
    check("session cookie is HttpOnly, Secure, SameSite=Strict",
          all(flag in cookie.lower() for flag in ("httponly", "secure", "samesite=strict")) and "__Host-" in cookie,
          cookie)
    claims = jwt.decode(eo_nsw.client.cookies.get("__Host-sv_session"), options={"verify_signature": False})
    check("official token carries the Table 8 claims",
          {"operatorId", "role", "scope", "mfaSatisfied", "stepUpAssertion", "sessionId"} <= set(claims)
          and claims["iss"] == "aec-auth" and claims["aud"] == "senate-voting-api", str(claims))
    for o, role in ((eo_vic, "ELECTION_OFFICIAL"), (co_nsw, "COUNT_OPERATOR"), (rd_nsw, "RECOUNT_DELEGATE"),
                    (rd_vic, "RECOUNT_DELEGATE"), (auditor, "AUDITOR")):
        o.login(role)
    r = eo_nsw.post(contest_path(NSW, "nominations/commit"), csrf=False)
    check("state-changing request without the CSRF token is refused", r.status_code == 403, r.text)

    print("Contest set-up (Tables 6 and 7)")
    r = eo_nsw.post(contest_path(NSW, "open"))
    check("voting can't open before nominations and party order are fixed", r.status_code == 409, r.text)
    r = eo_nsw.post(contest_path(NSW, "nominations/commit"))
    check("COMMIT_NOMINATIONS without step-up is refused", r.status_code == 403 and "step-up" in r.text, r.text)
    eo_nsw.step_up("FIX_PARTY_ORDER", NSW)
    r = eo_nsw.post(contest_path(NSW, "nominations/commit"))
    check("step-up for another action is refused (mismatch)", r.status_code == 403 and "different" in r.text, r.text)
    eo_nsw.step_up("COMMIT_NOMINATIONS", VIC)
    r = eo_nsw.post(contest_path(VIC, "nominations/commit"))
    check("NSW election official cannot act on VIC (scope)", r.status_code == 403 and "scope" in r.text, r.text)
    r = eo_nsw.step_up("COMMIT_NOMINATIONS", NSW)
    check("step-up assertion lasts two minutes", 110 <= r.json()["stepUpAssertion"]["expiresAt"] - time.time() <= 125,
          r.text)
    r = eo_nsw.post(contest_path(NSW, "nominations/commit"))
    check("NSW nominations committed with a bound step-up", r.status_code == 200, r.text)
    eo_nsw.step_up("FIX_PARTY_ORDER", NSW)
    r = eo_nsw.post(contest_path(NSW, "party-order"), {"group_order": ["B", "A", "C"]})
    check("party order fixed", r.status_code == 200, r.text)
    paper = call(api, "GET", f"/api/ballot/elections/{ELECTION}/contests/NSW").json()
    check("ballot paper follows the fixed order", [g["code"] for g in paper["groups"]] == ["B", "A", "C"], str(paper))
    r = eo_nsw.post(contest_path(NSW, "open"))
    check("opening voting needs no step-up (not irreversible)", r.status_code == 200, r.text)
    set_up_contest(eo_vic, VIC, ["A", "B"])

    print("GR01 / GR02 electors (Section 2.2)")
    bad = [elector_token("NSW-0001", "wrong-password", "NSW"), elector_token("NSW-9999", "whatever", "NSW"),
           elector_token("NSW-0001", "jane-citizen-2028", "VIC")]
    check("wrong password, unknown voter and wrong state get one generic 401",
          all(r.status_code == 401 for r in bad) and len({r.text for r in bad}) == 1, str([r.text for r in bad]))
    statuses = [elector_token("NSW-0002", "wrong", "NSW").status_code for _ in range(7)]
    check("electors are never locked out (Section 4.4)", 429 not in statuses, str(statuses))
    voters = {"NSW-0001": "jane-citizen-2028", "NSW-0002": "alex-nguyen-2028", "NSW-0003": "sam-smith-2028"}
    tokens = {}
    for vid, pw in voters.items():
        r = elector_token(vid, pw, "NSW")
        tokens[vid] = r.json().get("ballot_token")
        check(f"{vid} receives a voting authorisation", r.status_code == 200, r.text)
    claims = jwt.decode(tokens["NSW-0001"], options={"verify_signature": False})
    check("capability carries only the envelope, nonce and state (Table 5)",
          set(claims) == {"iss", "aud", "iat", "nbf", "exp", "principalType", "authorisationNonce", "state"}
          and len(claims["authorisationNonce"]) == 32, str(claims))
    r = elector_token("NSW-0001", "jane-citizen-2028", "NSW")
    check("second request: 'vote already recorded' (409)", r.status_code == 409 and "already recorded" in r.text, r.text)

    ballots = {
        "NSW-0001": {"above_the_line": ["B", "A"]},
        "NSW-0002": {"above_the_line": ["B", "C"]},
        "NSW-0003": {"below_the_line": ["NSW-A1", "NSW-B1", "NSW-C1", "NSW-A2", "NSW-B2", "NSW-C2"]},
    }
    receipts = []
    for vid, marks in ballots.items():
        r = vote(tokens[vid], marks)
        check(f"{vid} casts a ballot", r.status_code == 201, r.text)
        receipts.append(r.json().get("receipt"))
    r = vote(tokens["NSW-0001"], {"above_the_line": ["A"]})
    check("replayed authorisation refused (nonce already used)", r.status_code == 409, r.text)
    r = call(eo_nsw.client, "POST", "/api/ballot/ballots", json={"above_the_line": ["A"]})
    check("an official session cannot vote", r.status_code == 401, r.text)

    vic = elector_token("VIC-0001", "riley-brown-2028", "VIC").json()["ballot_token"]
    r = vote(vic, {"above_the_line": ["C"]})
    check("ballot for a group not in the voter's state refused", r.status_code == 422, r.text)
    r = vote(vic, {"above_the_line": ["A"], "elector_id": "VIC-0001"})
    check("extra identifying field refused", r.status_code == 422, r.text)
    deep = '{"above_the_line": ' + "[" * 5000 + "]" * 5000 + "}"
    r = vote(vic, None, content=deep)
    check("deeply nested JSON rejected without a 500", r.status_code in (400, 413, 422), str(r.status_code))
    r = vote(vic, None, content="x" * 100_000)
    check("oversized body rejected", r.status_code == 413, str(r.status_code))

    r = auditor.get("/api/ballot/ballots/by-elector/NSW-0001")
    check("QUERY_BALLOT_BY_ELECTOR_ID denied, even for an auditor", r.status_code == 403, r.text)

    print("Internal surface")
    for path in ("/api/ballot/internal/ballots/SEN2028/NSW", "/api/count/internal/recounts",
                 "/api/auth/internal/sessions/check", "/api/pdp/internal/decide"):
        r = co_nsw.get(path)
        check(f"{path} not reachable from outside", r.status_code == 404, str(r.status_code))
    r = api.get("/api/ballot/docs")
    check("API docs hidden in production", r.status_code == 404, str(r.status_code))

    print("Count (GR05, Figure 2)")
    co_nsw.step_up("START_COUNT", NSW)
    r = co_nsw.post("/api/count/counts", NSW)
    check("count refused while voting is open", r.status_code == 409, r.text)
    r = eo_nsw.post(contest_path(NSW, "close"))
    check("election official closes NSW", r.status_code == 200, r.text)
    r = vote(vic, {"above_the_line": ["A"]})
    check("a VIC vote still works while VIC is open", r.status_code == 201, r.text)
    r = co_nsw.post("/api/count/counts", NSW)
    count = r.json()
    check("count operator runs the NSW count with a bound step-up", r.status_code == 200, r.text)
    check("count elected 2 senators from 3 ballots", len(count.get("elected", [])) == 2 and count.get("formal_ballots") == 3,
          str(count.get("elected")))
    check("audit chain verified before the result was released", (count.get("chain_verified") or 0) > 0, str(count))
    published = call(api, "GET", f"/api/ballot/elections/{ELECTION}/receipts/NSW").json()["receipts"]
    check("every voter receipt appears in the published list", set(receipts) <= set(published))

    print("One active role per session (Section 2.3)")
    co_nsw.step_up("ENTER_MANUAL_EXCLUSION", {**NSW, "candidates": [count["elected"][0]]})
    r = co_nsw.post("/api/recount/recounts", {
        "election_id": ELECTION, "state": "NSW", "excluded_candidates": [count["elected"][0]],
        "court_order_ref": "X", "issued_on": "2028-11-02", "grounds_signature": "eA=="})
    check("a COUNT_OPERATOR session can't enter exclusions, though the official also holds RECOUNT_DELEGATE",
          r.status_code == 403 and "recount delegate" in r.text, r.text)

    print("GR03 recount")
    court = serialization.load_pem_private_key((ROOT / "keys/offline/court.key").read_bytes(), None)
    winner = count["elected"][0]
    document = {"court_order_ref": "HCA-2028-17", "election_id": ELECTION, "state": "NSW",
                "excluded_candidates": [winner], "issued_on": "2028-11-02"}
    body = {**{k: document[k] for k in ("election_id", "state", "excluded_candidates", "court_order_ref", "issued_on")},
            "grounds_signature": base64.b64encode(court.sign(canonical(document))).decode()}
    rd_vic.step_up("ENTER_MANUAL_EXCLUSION", {**NSW, "candidates": [winner]})
    r = rd_vic.post("/api/recount/recounts", body)
    check("VIC delegate cannot recount NSW", r.status_code == 403 and "scope" in r.text, r.text)
    wider = [winner, "NSW-C1"]
    rd_nsw.step_up("ENTER_MANUAL_EXCLUSION", {**NSW, "candidates": wider})
    r = rd_nsw.post("/api/recount/recounts", {**body, "excluded_candidates": wider})
    check("exclusion wider than the court order refused", r.status_code == 403 and "signature" in r.text, r.text)
    rd_nsw.step_up("ENTER_MANUAL_EXCLUSION", {**NSW, "candidates": [winner]})
    r = rd_nsw.post("/api/recount/recounts", body)
    recount = r.json()
    check("NSW delegate runs court-ordered recount", r.status_code == 200, r.text)
    check("excluded candidate is not elected in recount", winner not in recount.get("elected", [winner]),
          str(recount.get("elected")))
    r = rd_nsw.post("/api/recount/recounts", body)
    check("step-up assertion is single use", r.status_code == 403 and "already used" in r.text, r.text)

    print("Sessions and revocation (Table 11)")
    r = co_nsw.step_up("START_COUNT", NSW, otp="000000")
    check("failed step-up ends the session", r.status_code == 401, r.text)
    r = co_nsw.get("/api/auth/officials/session")
    check("...and the session stays ended", r.status_code == 401, r.text)
    stolen = eo_vic.client.cookies.get("__Host-sv_session")
    r = eo_vic.post("/api/auth/officials/logout")
    check("logout succeeds", r.status_code == 200, r.text)
    eo_vic.client.cookies.clear()
    eo_vic.client.cookies.set("__Host-sv_session", stolen)  # e.g. a copy taken before logout
    r = eo_vic.post(contest_path(VIC, "close"))
    check("a logged-out session's cookie no longer works (revoked server-side)", r.status_code == 401, r.text)

    print("Audit (GR05, Table 13)")
    r = eo_nsw.get("/api/audit/verify")
    check("only an AUDITOR can verify the audit log", r.status_code == 403, r.text)
    r = auditor.get("/api/audit/verify")
    check("auditor verifies an unbroken, signed chain", r.status_code == 200 and r.json().get("ok"), r.text)
    events = auditor.get("/api/audit/events?limit=500").json()["events"]
    kinds = {e["event_type"] for e in events}
    for needed in ("OPERATOR_AUTHENTICATED", "OPERATOR_MFA_FAILED", "STEP_UP_ISSUED", "STEP_UP_SATISFIED",
                   "STEP_UP_MISMATCH", "SESSION_INVALIDATED", "NOMINATIONS_COMMITTED", "PARTY_ORDER_FIXED",
                   "VOTING_OPENED", "VOTING_CLOSED", "AUTHORISATION_ISSUED", "AUTHORISATION_REFUSED_ALREADY_VOTED",
                   "AUTHORISATION_REFUSED_INVALID_CREDENTIALS", "AUTHORISATION_CONSUMED",
                   "AUTHORISATION_REPLAY_REFUSED", "BALLOT_ACCEPTED", "QUERY_REFUSED", "AUTHORISATION_DENIED",
                   "COUNT_STARTED", "COUNT_EXECUTED", "EXCLUSION_REFUSED", "EXCLUSION_ENTERED", "RECOUNT_EXECUTED"):
        check(f"audit log contains {needed}", needed in kinds)
    linking = [e for e in events if e["family"] == "AuthorisationRecord"
               and {"nonce", "ballotReference"} & set(e["detail"])]
    check("no AuthorisationRecord carries a nonce or ballot reference", not linking, str(linking[:1]))
    check("timestamps are kept to the minute", all(e["recorded_at"].endswith(":00+00:00") for e in events))

    print("GR04 official lockout")
    statuses = [locked.login("AUDITOR", otp="000000").status_code for _ in range(6)]
    check("official locked after 5 failed attempts", statuses[-1] == 429, str(statuses))

    print(f"\n{'ALL PASSED' if not failures else f'{len(failures)} FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
