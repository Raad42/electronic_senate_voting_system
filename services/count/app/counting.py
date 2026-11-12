"""
Author: Raad
Edits:

Fetches a closed contest's sealed ballots from the Ballot service, decrypts them with the
Count key and runs STV. Shared by the public count endpoint and the internal recount one.

After every count or recount the audit chain is re-verified before the result is released
(Milestone 2 Figure 2): if verification fails the result is withheld and the failure reported.

Requirements:
    GR02 - ballots are only ever decrypted here, with the Count service's private key
    GR05 - the audit chain is checked again before any result is released

Run:
    docker compose up -d --build
    .venv/bin/python scripts/close_and_count.py
    This script closes voting and then calls the count

Usage example:
    outcome = run_count("senate-2026", "SA")
    release_or_withhold(outcome, "co.sa")

Output:
    Releases the result with the quota, who got elected, each round, a SHA-256 hash of the
    result and how many audit entries were checked
    If the audit chain is broken the result is held back and reported instead
"""
import hashlib
import json
import logging
from dataclasses import asdict
from typing import Any

import httpx
from fastapi import HTTPException, status

from common.ballot_crypto import BallotDecryptError, contest_aad, decrypt_ballot
from common.clients import audit, service_client
from common.keys import load_private
from common.settings import get_settings

from app.stv import count_stv, expand_ballot

log = logging.getLogger("senate.count")


def _ballot_service(method: str, path: str) -> dict[str, Any]:
    try:
        with service_client(get_settings().ballot_url, "ballot") as client:
            r = client.request(method, path)
    except httpx.HTTPError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Ballot service unavailable") from None
    if r.status_code in (404, 409):
        raise HTTPException(r.status_code, r.json().get("detail", "Contest not ready"))
    if r.status_code != 200:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Ballot service error")
    return r.json()


def contest_status(election_id: str, state: str) -> str:
    return _ballot_service("GET", f"/internal/contests/{election_id}/{state}")["status"]


def mark_counted(election_id: str, state: str) -> None:
    """Publishing the result opens the recount phase."""
    _ballot_service("POST", f"/internal/contests/{election_id}/{state}/counted")


def run_count(election_id: str, state: str, excluded: set[str] | None = None) -> dict[str, Any]:
    contest = _ballot_service("GET", f"/internal/contests/{election_id}/{state}")
    sealed = _ballot_service("GET", f"/internal/ballots/{election_id}/{state}")["ballots"]

    groups = {g["code"]: g["candidates"] for g in contest["groups"]}
    candidates = [c["id"] for c in contest["candidates"]]
    key = load_private("count_ballot.key")
    aad = contest_aad(election_id, state)

    preferences, unreadable = [], 0
    for blob in sealed:
        try:
            preferences.append(expand_ballot(decrypt_ballot(blob, key, aad), groups))
        except BallotDecryptError:
            unreadable += 1

    try:
        result = count_stv(candidates, preferences, contest["seats"], excluded)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None

    outcome = {
        "election_id": election_id,
        "state": state,
        "ballots_received": len(sealed),
        "unreadable_ballots": unreadable,
        **asdict(result),
    }
    # Fingerprint of the full result, recorded in the audit log so it can be re-checked later.
    outcome["result_sha256"] = hashlib.sha256(
        json.dumps(outcome, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return outcome


def release_or_withhold(outcome: dict[str, Any], actor: str) -> dict[str, Any]:
    """Figure 2: verify the chain; publish if intact, otherwise withhold and report."""
    chain = audit.verify_chain()
    if not chain.get("ok"):
        audit.try_record("CountRecord", "RESULT_WITHHELD", actor, {
            "electionId": outcome["election_id"], "contestState": outcome["state"],
            "reason": f"audit chain verification failed at entry {chain.get('first_bad_seq')}",
        })
        # Reported to the Electoral Commissioner outside the system (Section 1.3).
        log.critical("INTEGRITY FAILURE: audit chain broken at %s; result withheld", chain.get("first_bad_seq"))
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "Audit chain verification failed; the result has been withheld and reported")
    return {**outcome, "chain_verified": chain.get("checked")}
