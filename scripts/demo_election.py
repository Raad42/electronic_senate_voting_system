#!/usr/bin/env python3
"""Step-by-step demo of an election, showing what each part of the system sees and stores.

    docker compose down -v && docker compose up -d     # fresh databases
    .venv/bin/python scripts/demo_election.py

It shows that the electoral roll knows WHO voted, the ballot box knows WHAT was voted, and
nothing joins the two (GR02). Only after the election closes does the Count service decrypt
the ballots and add them up.
"""
import subprocess
import sys
import time
from pathlib import Path

import jwt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "e2e"))
from smoke_test import ELECTION, NSW, Official, api, call, contest_path, elector_token, vote, wait_until_ready  # noqa: E402

BOLD, DIM, GREEN, CYAN, RESET = "\033[1m", "\033[2m", "\033[32m", "\033[36m", "\033[0m"

VOTERS = [
    ("NSW-0001", "jane-citizen-2028", "Jane Citizen", {"above_the_line": ["B", "A"]}),
    ("NSW-0002", "alex-nguyen-2028", "Alex Nguyen", {"above_the_line": ["A", "C"]}),
    ("NSW-0003", "sam-smith-2028", "Sam Smith",
     {"below_the_line": ["NSW-B1", "NSW-A1", "NSW-C1", "NSW-U1", "NSW-A2", "NSW-B2"]}),
]


def heading(text: str) -> None:
    print(f"\n{BOLD}{CYAN}== {text} =={RESET}")


def pause() -> None:
    if sys.stdin.isatty():
        input(f"{DIM}   (press Enter to continue){RESET}")
    else:
        time.sleep(0.5)


def sql(db: str, query: str) -> str:
    """Read a database directly, as an investigator with full access would."""
    return subprocess.run(
        ["docker", "compose", "exec", "-T", f"{db}_db", "psql", "-U", "owner", "-d", db, "-c", query],
        capture_output=True, text=True, cwd=ROOT,
    ).stdout.rstrip()


def main() -> None:
    print("Waiting for services to start...")
    wait_until_ready()
    paper = call(api, "GET", f"/api/ballot/elections/{ELECTION}/contests/NSW").json()
    if paper.get("status") != "nominations":
        sys.exit("Needs fresh databases: docker compose down -v && docker compose up -d")
    names = {c["id"]: c["name"] for c in paper["candidates"]}
    groups = {g["code"]: g["name"] for g in paper["groups"]}

    heading("1. The NSW ballot paper")
    for g in paper["groups"]:
        print(f"   Group {g['code']}  {g['name']:<16} " + ", ".join(names[c] for c in g["candidates"]))
    ungrouped = [c["name"] for c in paper["candidates"] if not c["group"]]
    print(f"   Ungrouped         {', '.join(ungrouped)}")
    pause()

    heading("2. Election official commits nominations, fixes party order and opens voting")
    eo = Official(("ELECTION_OFFICIAL", ELECTION, "NSW"))
    co = Official(("COUNT_OPERATOR", ELECTION, "NSW"))
    eo.login("ELECTION_OFFICIAL")
    co.login("COUNT_OPERATOR")
    eo.step_up("COMMIT_NOMINATIONS", NSW)
    eo.post(contest_path(NSW, "nominations/commit"))
    eo.step_up("FIX_PARTY_ORDER", NSW)
    eo.post(contest_path(NSW, "party-order"), {"group_order": [g["code"] for g in paper["groups"]]})
    r = eo.post(contest_path(NSW, "open"))
    print(f"   {GREEN}{r.json()}{RESET}  (password + 6-digit code; a fresh step-up code for each irreversible action)")
    pause()

    receipts = {}
    for elector_id, password, person, marks in VOTERS:
        heading(f"3. {person} ({elector_id}) votes")
        token = elector_token(elector_id, password, "NSW").json()["ballot_token"]
        claims = jwt.decode(token, options={"verify_signature": False})
        print(f"   Roll check passed. Ballot token contains: {claims}")
        print(f"   {DIM}No name or voter ID in the token - only a random one-use nonce and the state.{RESET}")
        if "above_the_line" in marks:
            shown = ", ".join(f"{i}={groups[c]}" for i, c in enumerate(marks["above_the_line"], 1))
        else:
            shown = ", ".join(f"{i}={names[c]}" for i, c in enumerate(marks["below_the_line"], 1))
        print(f"   Marks the ballot: {shown}")
        r = vote(token, marks)
        receipts[person] = r.json()["receipt"]
        print(f"   {GREEN}Accepted. Receipt: {receipts[person]}{RESET}")
        again = vote(token, marks)
        print(f"   Tries to vote again with the same token -> {again.status_code} {again.json()['detail']}")
        pause()

    heading("4. What the ELECTORAL ROLL stores (only Auth can reach this database)")
    print(sql("roll", "SELECT elector_id, election_id FROM issuances ORDER BY elector_id"))
    print(f"   {DIM}Who has voted - but no time, no nonce, nothing about the ballot.{RESET}")
    pause()

    heading("5. What the BALLOT BOX stores (only Ballot can reach this database)")
    print(sql("ballot", "SELECT ballot_id, state, left(ciphertext, 40) || '...' AS sealed_ballot FROM ballots"))
    print(f"   {DIM}Encrypted to the Count service's key. No voter, no time. The Ballot service itself"
          f" cannot read these.{RESET}")
    print(f"   {DIM}There is no column on either side that links a person to a row here.{RESET}")
    pause()

    heading("6. Election closes, count officer runs the count")
    eo.post(contest_path(NSW, "close"))
    co.step_up("START_COUNT", NSW)
    result = co.post("/api/count/counts", NSW).json()
    print(f"   {result['formal_ballots']} ballots decrypted, quota = {result['quota']} for {result['seats']} seats")
    for rnd in result["rounds"]:
        tallies = ", ".join(f"{names[c]} {float(eval_fraction(v)):.2f}" for c, v in rnd["tallies"].items()
                            if eval_fraction(v) > 0)
        print(f"   Round {rnd['number']}: {rnd['action']:<7} {names.get(rnd['candidate'], ''):<18} [{tallies}]")
    print(f"   {GREEN}{BOLD}Elected: {', '.join(names[c] for c in result['elected'])}{RESET}")
    print(f"   Result fingerprint (in audit log): {result['result_sha256'][:16]}...")
    pause()

    heading("7. Voters check their ballot was counted")
    published = set(call(api, "GET", f"/api/ballot/elections/{ELECTION}/receipts/NSW").json()["receipts"])
    for person, receipt in receipts.items():
        print(f"   {person}: receipt {receipt[:8]}... {'is in the published list' if receipt in published else 'MISSING'}")
    print(f"   {DIM}The receipt proves the ballot is in the box, not how it was marked.{RESET}")

    heading("8. Audit log")
    print(sql("audit", "SELECT seq, left(hash, 12) AS hash, body::json->>'family' AS family, "
                       "body::json->>'event_type' AS event, body::json->>'actor' AS actor FROM events ORDER BY seq"))


def eval_fraction(text: str) -> float:
    num, _, den = text.partition("/")
    return int(num) / int(den or 1)


if __name__ == "__main__":
    main()
