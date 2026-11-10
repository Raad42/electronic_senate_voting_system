#!/usr/bin/env python3
"""Plays the role of the court: signs exclusion grounds with keys/offline/court.key and prints
the JSON body a recount delegate submits to POST /api/recount/recounts.

    python scripts/sign_exclusion.py --order "HCA-2028-17" --election SEN2028 --state NSW \
        --exclude NSW-B1 --issued-on 2028-11-02
"""
import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))
from common.audit_chain import canonical  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--order", required=True, help="court order reference")
    p.add_argument("--election", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--exclude", required=True, action="append", help="candidate id (repeatable)")
    p.add_argument("--issued-on", required=True, help="YYYY-MM-DD")
    p.add_argument("--key", type=Path, default=ROOT / "keys" / "offline" / "court.key")
    p.add_argument("--register", action="store_true",
                   help="add the signed order to keys/recount/court_orders.json, so the frontend can use "
                        "--order as its supporting evidence id (read on every request; no restart needed)")
    a = p.parse_args()

    document = {
        "court_order_ref": a.order,
        "election_id": a.election,
        "state": a.state,
        "excluded_candidates": sorted(a.exclude),
        "issued_on": a.issued_on,
    }
    key = serialization.load_pem_private_key(a.key.read_bytes(), password=None)
    signature = base64.b64encode(key.sign(canonical(document))).decode()
    if a.register:
        register_file = ROOT / "keys" / "recount" / "court_orders.json"
        register = json.loads(register_file.read_text()) if register_file.exists() else {}
        register[a.order] = {**document, "ground": "COURT_ORDER", "grounds_signature": signature}
        register_file.write_text(json.dumps(register, indent=2))
        print(f"Registered {a.order} in {register_file.relative_to(ROOT)}", file=sys.stderr)
    print(json.dumps({
        "election_id": a.election,
        "state": a.state,
        "excluded_candidates": document["excluded_candidates"],
        "court_order_ref": a.order,
        "issued_on": a.issued_on,
        "grounds_signature": signature,
    }, indent=2))


if __name__ == "__main__":
    main()
