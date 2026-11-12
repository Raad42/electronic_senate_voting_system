"""
Author: Raad
Edits:

Hash-chain logic for the tamper-evident audit log (GR05).

Each entry stores hash = SHA-256(prev_hash || canonical(body)) and an Ed25519 signature
over that hash. Editing, deleting or re-ordering any entry breaks every hash after it,
and forging a new chain needs the Audit service's private key.

Requirements:
    GR05 - any edit, deletion or re-ordering of the audit log is detected

Run:
    python -m pytest tests/test_audit_chain.py -v

Usage example:
    verify_chain(rows, public_key)
    rows[4]["body"]["event_type"] = "EDITED"
    verify_chain(rows, public_key)

Output:
    With 12 untouched events the check passes and all 12 are checked
    After editing event 5 it fails at event 5 with "entry contents were changed"
"""
import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS_HASH = "0" * 64


def canonical(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def entry_hash(prev_hash: str, body: dict[str, Any]) -> str:
    return hashlib.sha256(prev_hash.encode() + canonical(body)).hexdigest()


def sign_hash(hash_hex: str, key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.sign(bytes.fromhex(hash_hex))).decode()


def signature_valid(hash_hex: str, signature_b64: str, key: Ed25519PublicKey) -> bool:
    try:
        key.verify(base64.b64decode(signature_b64), bytes.fromhex(hash_hex))
        return True
    except (InvalidSignature, ValueError):
        return False


def build_entry(prev_hash: str, body: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, str]:
    h = entry_hash(prev_hash, body)
    return {"prev_hash": prev_hash, "hash": h, "signature": sign_hash(h, key)}


@dataclass
class ChainCheck:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None


def verify_chain(rows: Iterable[dict[str, Any]], key: Ed25519PublicKey) -> ChainCheck:
    """rows: dicts with seq, prev_hash, hash, signature, body; ordered by seq ascending."""
    expected_prev = GENESIS_HASH
    expected_seq = None
    checked = 0
    for row in rows:
        seq = row["seq"]
        if expected_seq is not None and seq != expected_seq:
            return ChainCheck(False, checked, seq, f"gap in sequence (expected {expected_seq})")
        if row["prev_hash"] != expected_prev:
            return ChainCheck(False, checked, seq, "prev_hash does not match previous entry")
        if entry_hash(row["prev_hash"], row["body"]) != row["hash"]:
            return ChainCheck(False, checked, seq, "entry contents were changed")
        if not signature_valid(row["hash"], row["signature"], key):
            return ChainCheck(False, checked, seq, "signature invalid")
        expected_prev = row["hash"]
        expected_seq = seq + 1
        checked += 1
    return ChainCheck(True, checked)
