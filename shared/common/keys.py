"""Loads key files from the service's own keys folder.

Layout written by scripts/gen_keys.py (each service only gets what it needs):
    auth_signing.key / auth_signing.pub   Ed25519, signs session + ballot tokens (key: auth only)
    service.key                           Ed25519, this service's own service-token key
    services/<name>.pub                   public keys of services allowed to call us
    count_ballot.key / count_ballot.pub   X25519, ballots are sealed to this (key: count only)
    audit_signing.key / audit_signing.pub Ed25519, signs audit entries (key: audit only)
    court.pub                             Ed25519, verifies exclusion grounds (recount)
    tls/ca.crt, tls/service.crt, tls/service.key
"""
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from common.settings import get_settings


class KeyMissing(RuntimeError):
    pass


def key_path(name: str) -> Path:
    path = get_settings().keys_dir / name
    if not path.is_file():
        raise KeyMissing(f"Key file not available to this service: {name}")
    return path


@lru_cache
def load_private(name: str):
    return serialization.load_pem_private_key(key_path(name).read_bytes(), password=None)


@lru_cache
def load_public(name: str):
    return serialization.load_pem_public_key(key_path(name).read_bytes())


def load_service_public(service: str):
    if not service.isalpha():
        raise KeyMissing("Invalid service name")
    return load_public(f"services/{service}.pub")


def clear_cache() -> None:
    load_private.cache_clear()
    load_public.cache_clear()
