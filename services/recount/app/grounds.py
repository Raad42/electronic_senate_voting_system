"""
Author: Raad
Edits:

Verified exclusion grounds (GR03).

A court order (or the authority acting for it) signs the exclusion with the court key.
The recount only proceeds if that signature checks out against court.pub AND the signed
contest matches both the request and the delegate's own scope. The delegate cannot invent,
widen or retarget an exclusion.

Signed document (canonical JSON, see common.audit_chain.canonical):
    {"court_order_ref": "...", "election_id": "...", "state": "...",
     "excluded_candidates": ["sorted", "ids"], "issued_on": "YYYY-MM-DD"}

Requirements:
    GR03 - an exclusion only goes ahead with a genuine court signature for this exact contest

Run:
    python -m pytest tests/test_grounds.py -v

Usage example:
    verified_court_order("HC-2026-17")
    verified_court_order("HC-9999")

Output:
    HC-2026-17 comes back as a valid court order for senate-2026 in SA excluding CAND-041
    HC-9999 raises GroundsInvalid as it isn't a registered court order
"""
import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature

from common.audit_chain import canonical
from common.keys import load_public
from common.settings import get_settings


class GroundsInvalid(ValueError):
    pass


def grounds_document(court_order_ref: str, election_id: str, state: str,
                     excluded: list[str], issued_on: str) -> dict[str, Any]:
    return {
        "court_order_ref": court_order_ref,
        "election_id": election_id,
        "state": state,
        "excluded_candidates": sorted(excluded),
        "issued_on": issued_on,
    }


def verify_grounds(document: dict[str, Any], signature_b64: str) -> None:
    try:
        load_public("court.pub").verify(base64.b64decode(signature_b64, validate=True), canonical(document))
    except (InvalidSignature, ValueError):
        raise GroundsInvalid("Exclusion grounds signature is not valid") from None


# --------------------------------------------------------------------------- court order register
# The frontend sends only a supporting-evidence id (the court order reference). The Recount
# service looks that id up in a register of court orders, keys/recount/court_orders.json, and
# re-verifies the court's signature on every use, so editing the register file does not help:
# an entry without a valid court signature is refused.
REGISTER_FILE = "court_orders.json"


def find_court_order(order_ref: str) -> dict[str, Any] | None:
    path = get_settings().keys_dir / REGISTER_FILE
    if not path.is_file():
        return None
    try:
        orders = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    entry = orders.get(order_ref) if isinstance(orders, dict) else None
    return entry if isinstance(entry, dict) else None


def verified_court_order(order_ref: str) -> dict[str, Any]:
    """The signed document for this order, or GroundsInvalid if it is unknown or not genuine."""
    entry = find_court_order(order_ref)
    if entry is None:
        raise GroundsInvalid(f"Supporting evidence {order_ref} is not a registered court order")
    try:
        document = grounds_document(entry["court_order_ref"], entry["election_id"], entry["state"],
                                    list(entry["excluded_candidates"]), entry["issued_on"])
        signature = entry["grounds_signature"]
    except (KeyError, TypeError):
        raise GroundsInvalid(f"Court order {order_ref} is malformed") from None
    if document["court_order_ref"] != order_ref:
        raise GroundsInvalid(f"Court order {order_ref} is malformed")
    verify_grounds(document, signature)
    return document
