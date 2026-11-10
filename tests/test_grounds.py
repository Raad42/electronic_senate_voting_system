import base64

import pytest
from cryptography.hazmat.primitives import serialization

from common.audit_chain import canonical
from conftest import load_module

grounds = load_module("services/recount/app/grounds.py")


def court_sign(keys_root, document) -> str:
    key = serialization.load_pem_private_key((keys_root / "offline" / "court.key").read_bytes(), None)
    return base64.b64encode(key.sign(canonical(document))).decode()


def test_valid_grounds(as_service, keys_root):
    as_service("recount")
    doc = grounds.grounds_document("HCA-1", "SEN2028", "NSW", ["NSW-B1"], "2028-11-02")
    grounds.verify_grounds(doc, court_sign(keys_root, doc))


def test_widened_exclusion_rejected(as_service, keys_root):
    as_service("recount")
    signed = grounds.grounds_document("HCA-1", "SEN2028", "NSW", ["NSW-B1"], "2028-11-02")
    sig = court_sign(keys_root, signed)
    widened = grounds.grounds_document("HCA-1", "SEN2028", "NSW", ["NSW-B1", "NSW-A1"], "2028-11-02")
    retargeted = grounds.grounds_document("HCA-1", "SEN2028", "VIC", ["NSW-B1"], "2028-11-02")
    for doc in (widened, retargeted):
        with pytest.raises(grounds.GroundsInvalid):
            grounds.verify_grounds(doc, sig)


def test_garbage_signature_rejected(as_service):
    as_service("recount")
    doc = grounds.grounds_document("HCA-1", "SEN2028", "NSW", ["NSW-B1"], "2028-11-02")
    with pytest.raises(grounds.GroundsInvalid):
        grounds.verify_grounds(doc, "not-a-signature")
