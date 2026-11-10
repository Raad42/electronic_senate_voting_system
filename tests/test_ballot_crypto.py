import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from common.ballot_crypto import BallotDecryptError, contest_aad, decrypt_ballot, encrypt_ballot

KEY = X25519PrivateKey.generate()
BALLOT = {"above_the_line": ["B", "A", "C"]}
AAD = contest_aad("SEN2028", "NSW")


def test_round_trip():
    assert decrypt_ballot(encrypt_ballot(BALLOT, KEY.public_key(), AAD), KEY, AAD) == BALLOT


def test_same_ballot_encrypts_differently():
    assert encrypt_ballot(BALLOT, KEY.public_key(), AAD) != encrypt_ballot(BALLOT, KEY.public_key(), AAD)


def test_moved_to_other_contest_fails():
    blob = encrypt_ballot(BALLOT, KEY.public_key(), AAD)
    with pytest.raises(BallotDecryptError):
        decrypt_ballot(blob, KEY, contest_aad("SEN2028", "VIC"))


def test_tampered_or_wrong_key_fails():
    blob = encrypt_ballot(BALLOT, KEY.public_key(), AAD)
    raw = bytearray(base64.b64decode(blob))
    raw[-1] ^= 1
    with pytest.raises(BallotDecryptError):
        decrypt_ballot(base64.b64encode(raw).decode(), KEY, AAD)
    with pytest.raises(BallotDecryptError):
        decrypt_ballot(blob, X25519PrivateKey.generate(), AAD)
    with pytest.raises(BallotDecryptError):
        decrypt_ballot("not base64!!", KEY, AAD)
