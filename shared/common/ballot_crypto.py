"""Ballot encryption (GR02).

Ballots are sealed to the COUNT service's X25519 public key, so the Ballot service and its
database only ever hold ciphertext they cannot read. Scheme: ephemeral X25519 key exchange
-> HKDF-SHA256 -> AES-256-GCM. The election and state are bound in as associated data, so a
ciphertext moved to another contest fails to decrypt.

Wire format (base64): ephemeral_public(32) || nonce(12) || ciphertext+tag
"""
import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"senate-ballot-v1"


class BallotDecryptError(Exception):
    pass


def contest_aad(election_id: str, state: str) -> bytes:
    return f"{election_id}|{state}".encode()


def _derive(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(shared)


def encrypt_ballot(payload: dict[str, Any], recipient: X25519PublicKey, aad: bytes) -> str:
    ephemeral = X25519PrivateKey.generate()
    key = _derive(ephemeral.exchange(recipient))
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    eph_pub = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(eph_pub + nonce + ciphertext).decode()


def decrypt_ballot(blob: str, private: X25519PrivateKey, aad: bytes) -> dict[str, Any]:
    try:
        raw = base64.b64decode(blob, validate=True)
        eph_pub, nonce, ciphertext = raw[:32], raw[32:44], raw[44:]
        key = _derive(private.exchange(X25519PublicKey.from_public_bytes(eph_pub)))
        return json.loads(AESGCM(key).decrypt(nonce, ciphertext, aad))
    except Exception as exc:  # any failure = unreadable ballot
        raise BallotDecryptError(type(exc).__name__) from None
