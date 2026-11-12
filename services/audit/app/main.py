"""
Author: Raad
Edits:

Audit service (GR05): append-only, hash-chained, signed event log.

Records come in families (Milestone 2 Table 13) and each family may only carry its own fields,
so no record can put an elector's enrolment next to a nonce or a ballot reference (GR02).
Timestamps are kept to the minute: records that share no field could otherwise be matched up
by precise time (Section 2.7).

Appends are serialised with a Postgres advisory lock so two events can never claim the same
place in the chain. The database user has INSERT and SELECT only (see db/audit).

Requirements:
    GR02 - record families share no field, so no event links a voter to a ballot
    GR05 - the log is append-only, hash-chained and signed, and only an auditor can read or verify it

Run:
    docker compose up -d --build
    docker compose exec audit_db psql -U owner -d audit -c "DELETE FROM events WHERE seq=1;"

Usage example:
    Sign in as aud.demo and open the Audit page, which loads the latest 50 events

Output:
    Shows the latest events with chain status VALID
    Other roles are refused since only an auditor can read the log
    The DELETE above fails with "audit events are append-only"
"""
import json
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import Depends, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import Connection, text

from common.app_factory import create_app
from common.audit_chain import GENESIS_HASH, build_entry, canonical, verify_chain
from common.db import transaction_dependency
from common.keys import load_private, load_public
from common.security import Official, authorise, require_service
from common.settings import get_settings

app = create_app("Audit service")
DB = Annotated[Connection, Depends(transaction_dependency(lambda: get_settings().database_url))]
CHAIN_LOCK = 0x5E4A7E  # any constant; one lock for the single chain

# The only fields each family may carry. Elector-related families share none.
FAMILIES: dict[str, set[str]] = {
    "AuthorisationRecord": {"enrolmentId", "electionId", "state"},   # never a nonce or ballot reference
    "NonceRecord": {"nonce", "reason"},                              # never an enrolment
    "BallotRecord": {"ballotReference"},                             # never an enrolment or nonce
    "OperatorRecord": {"role", "action", "resource", "reason", "groupOrder"},
    "CountRecord": {"electionId", "contestState", "elected", "quota", "formalBallots", "resultSha256",
                    "excludedCandidates", "courtOrderRef", "issuedOn", "reason"},
    "ServiceRecord": {"serviceId", "certificateFingerprint"},
    "QueryRecord": {"requesterId", "query"},
}


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    family: str = Field(max_length=32)
    event_type: str = Field(pattern=r"^[A-Z][A-Z_]{2,63}$")
    actor: str = Field(min_length=1, max_length=64)
    detail: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _family_fields(self) -> "EventIn":
        allowed = FAMILIES.get(self.family)
        if allowed is None:
            raise ValueError("unknown record family")
        extra = set(self.detail) - allowed
        if extra:
            raise ValueError(f"{self.family} cannot carry {sorted(extra)}")
        return self


def _minute() -> str:
    return datetime.now(timezone.utc).replace(second=0, microsecond=0).isoformat()


@app.post("/internal/events", status_code=201)
def append_event(
    event: EventIn,
    db: DB,
    caller: dict = Depends(require_service("auth", "ballot", "count", "recount", "pdp")),
) -> dict[str, Any]:
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": CHAIN_LOCK})
    head = db.execute(text("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1")).first()
    seq = head.seq + 1 if head else 1
    body = {
        "seq": seq,
        "recorded_at": _minute(),
        "service": caller["iss"],  # from the verified service token, not from the request body
        "family": event.family,
        "event_type": event.event_type,
        "actor": event.actor,
        "detail": event.detail,
    }
    entry = build_entry(head.hash if head else GENESIS_HASH, body, load_private("audit_signing.key"))
    db.execute(
        text("""INSERT INTO events (seq, body, prev_hash, hash, signature)
                VALUES (:seq, :body, :prev, :hash, :sig)"""),
        {"seq": seq, "body": canonical(body).decode(), "prev": entry["prev_hash"],
         "hash": entry["hash"], "sig": entry["signature"]},
    )
    return {"seq": seq, "hash": entry["hash"]}


def _verify(db: Connection) -> dict[str, Any]:
    rows = (
        {"seq": r.seq, "body": json.loads(r.body), "prev_hash": r.prev_hash, "hash": r.hash, "signature": r.signature}
        for r in db.execute(text("SELECT seq, body, prev_hash, hash, signature FROM events ORDER BY seq"))
    )
    result = verify_chain(rows, load_public("audit_signing.pub"))
    return {"ok": result.ok, "checked": result.checked, "first_bad_seq": result.first_bad_seq, "reason": result.reason}


@app.get("/internal/verify", dependencies=[Depends(require_service("count", "recount"))])
def internal_verify(db: DB) -> dict[str, Any]:
    """Figure 2: Count and Recount re-check the chain before publishing a result."""
    return _verify(db)


SERVICES = {"auth", "ballot", "count", "recount", "audit", "pdp"}


def _actor_type(actor: str) -> str:
    if actor in ("elector", "anonymous"):
        return "ELECTOR"
    if actor in SERVICES:
        return "SERVICE"
    return "OFFICIAL"


def _resource_id(family: str, detail: dict[str, Any]) -> str:
    """What the event was about, without ever exposing an elector-to-ballot link."""
    if family == "BallotRecord":
        return "ballot"            # the reference is in `detail` for auditors; not a lookup key
    if family == "NonceRecord":
        return "voting-authorisation"
    if family == "QueryRecord":
        return "ballot-identity-lookup"
    if detail.get("courtOrderRef"):
        return str(detail["courtOrderRef"])
    if detail.get("resultSha256"):
        return f"result-{str(detail['resultSha256'])[:12]}"
    resource = detail.get("resource")
    if isinstance(resource, dict) and resource.get("election_id"):
        return f"{resource.get('election_id')}/{resource.get('state')}"
    return str(detail.get("action") or family)


def _frontend_event(seq: int, body: dict[str, Any], prev_hash: str, hash_: str, signature: str) -> dict[str, Any]:
    """AuditEvent in frontend/src/types/api.ts, plus the original fields (detail, family, signature)."""
    detail = body.get("detail") or {}
    resource = detail.get("resource") if isinstance(detail.get("resource"), dict) else {}
    election = detail.get("electionId") or resource.get("election_id")
    state = detail.get("contestState") or detail.get("state") or resource.get("state")
    return {
        # frontend contract
        "eventId": f"audit-{seq:06d}",
        "eventType": body["event_type"],
        "actorType": _actor_type(body["actor"]),
        "actorId": body["actor"],
        "resourceId": _resource_id(body["family"], detail),
        "electionId": election,
        "state": state,
        "countId": f"count-{election}-{state}" if body["family"] == "CountRecord" and election and state else None,
        "timestamp": body["recorded_at"],
        "previousHash": prev_hash,
        "eventHash": hash_,
        # original fields
        "seq": seq, **body, "prev_hash": prev_hash, "hash": hash_, "signature": signature,
    }


@app.get("/events")
def list_events(
    official: Official,
    db: DB,
    after_seq: int | None = Query(None, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    """With after_seq: oldest first from that point (paging). Without: the newest `limit` events,
    newest first, as the audit page shows them. chainStatus covers the WHOLE chain."""
    authorise("READ_AUDIT_LOG", official, {})
    if after_seq is None:
        sql = "SELECT seq, body, prev_hash, hash, signature FROM events ORDER BY seq DESC LIMIT :l"
        params: dict[str, Any] = {"l": limit}
    else:
        sql = "SELECT seq, body, prev_hash, hash, signature FROM events WHERE seq > :a ORDER BY seq LIMIT :l"
        params = {"a": after_seq, "l": limit}
    rows = db.execute(text(sql), params).all()
    chain = _verify(db)
    return {
        "events": [_frontend_event(r.seq, json.loads(r.body), r.prev_hash, r.hash, r.signature) for r in rows],
        "chainStatus": "VALID" if chain["ok"] else "INVALID",
        "chain": chain,
    }


@app.get("/verify")
def verify(official: Official, db: DB) -> dict[str, Any]:
    authorise("VERIFY_AUDIT_LOG", official, {})
    return _verify(db)
