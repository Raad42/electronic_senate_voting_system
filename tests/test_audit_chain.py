from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.audit_chain import GENESIS_HASH, build_entry, verify_chain

KEY = Ed25519PrivateKey.generate()


def make_chain(n: int) -> list[dict]:
    rows, prev = [], GENESIS_HASH
    for seq in range(1, n + 1):
        body = {"seq": seq, "event_type": "count.started", "actor": "co.lee", "detail": {"state": "NSW"}}
        entry = build_entry(prev, body, KEY)
        rows.append({"seq": seq, "body": body, **entry})
        prev = entry["hash"]
    return rows


def test_valid_chain():
    result = verify_chain(make_chain(5), KEY.public_key())
    assert result.ok and result.checked == 5


def test_edited_entry_detected():
    rows = make_chain(5)
    rows[2]["body"]["detail"]["state"] = "VIC"
    result = verify_chain(rows, KEY.public_key())
    assert not result.ok and result.first_bad_seq == 3


def test_deleted_entry_detected():
    rows = make_chain(5)
    del rows[1]
    result = verify_chain(rows, KEY.public_key())
    assert not result.ok and result.first_bad_seq == 3


def test_rebuilt_chain_without_key_detected():
    """An attacker recomputes every hash after editing, but cannot sign with the audit key."""
    rows = make_chain(3)
    rows[0]["body"]["actor"] = "intruder"
    attacker = Ed25519PrivateKey.generate()
    prev = GENESIS_HASH
    for row in rows:
        row.update(build_entry(prev, row["body"], attacker))
        prev = row["hash"]
    result = verify_chain(rows, KEY.public_key())
    assert not result.ok and result.reason == "signature invalid"
