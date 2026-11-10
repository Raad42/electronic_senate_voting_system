import base64
import json
import os
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_ballot(payload: dict[str, Any], election_id: str) -> tuple[str, bytes, bytes]:
    key_b64 = os.environ.get("BALLOT_ENCRYPTION_KEY_B64")
    if not key_b64:
        raise RuntimeError("BALLOT_ENCRYPTION_KEY_B64 is not configured")
    key = base64.urlsafe_b64decode(key_b64 + "=" * (-len(key_b64) % 4))
    if len(key) != 32:
        raise RuntimeError("BALLOT_ENCRYPTION_KEY_B64 must decode to 32 bytes")
    iv = secrets.token_bytes(12)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ciphertext = AESGCM(key).encrypt(iv, plaintext, election_id.encode())
    return os.environ.get("BALLOT_ENCRYPTION_KEY_ID", "ballot-key-1"), iv, ciphertext
