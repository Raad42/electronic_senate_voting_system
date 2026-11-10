#!/usr/bin/env python3
"""Generates every signing key, encryption key and TLS certificate, then gives each service
a folder with ONLY the keys it needs (least privilege). Docker mounts keys/<service>/ at
/run/keys inside that service's container.

    python scripts/gen_keys.py            # writes ./keys (refuses to overwrite)
    python scripts/gen_keys.py --force    # regenerate everything

keys/offline/court.key is the court's signing key for exclusion grounds. It is NOT mounted
into any container; in a real deployment it would never be on the server at all.
"""
import argparse
import base64
import datetime
import json
import ipaddress
import shutil
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERVICES = ("auth", "ballot", "count", "recount", "audit", "pdp")

# What each service receives besides its own service.key and TLS files.
NEEDS = {
    # Ballot, Count, Recount and Audit confirm official sessions with Auth (server-side sessions).
    "auth":    {"files": ["auth_signing.key", "auth_signing.pub"], "callers": ["ballot", "count", "recount", "audit"]},
    "ballot":  {"files": ["auth_signing.pub", "count_ballot.pub"], "callers": ["count"]},
    "count":   {"files": ["auth_signing.pub", "count_ballot.key"], "callers": ["recount"]},
    "recount": {"files": ["auth_signing.pub", "court.pub"], "callers": []},
    "audit":   {"files": ["auth_signing.pub", "audit_signing.key", "audit_signing.pub"],
                "callers": ["auth", "ballot", "count", "recount", "pdp"]},
    "pdp":     {"files": [], "callers": ["auth", "ballot", "count", "recount", "audit"]},
}

PEM = serialization.Encoding.PEM
PKCS8 = serialization.PrivateFormat.PKCS8
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
NO_PW = serialization.NoEncryption()


def _private_pem(key) -> bytes:
    return key.private_bytes(PEM, PKCS8, NO_PW)


def _public_pem(key) -> bytes:
    return key.public_key().public_bytes(PEM, SPKI)


def _write(path: Path, data: bytes, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600 if private else 0o644)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Senate Voting (dev)"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Senate Voting Dev CA")).issuer_name(_name("Senate Voting Dev CA"))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_cert(ca_key, ca_cert, cn: str, dns: list[str]):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    names = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn)).issuer_name(ca_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=397))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                       critical=False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def generate(out: Path) -> None:
    shared: dict[str, bytes] = {}
    for name in ("auth_signing", "audit_signing", "court"):
        k = Ed25519PrivateKey.generate()
        shared[f"{name}.key"], shared[f"{name}.pub"] = _private_pem(k), _public_pem(k)
    k = X25519PrivateKey.generate()
    shared["count_ballot.key"], shared["count_ballot.pub"] = _private_pem(k), _public_pem(k)

    service_keys = {}
    for svc in SERVICES:
        k = Ed25519PrivateKey.generate()
        service_keys[svc] = (_private_pem(k), _public_pem(k))

    ca_key, ca_cert = _make_ca()
    ca_pem = ca_cert.public_bytes(PEM)

    for svc in SERVICES:
        folder = out / svc
        for f in NEEDS[svc]["files"]:
            _write(folder / f, shared[f], private=f.endswith(".key"))
        _write(folder / "service.key", service_keys[svc][0], private=True)
        for caller in NEEDS[svc]["callers"]:
            _write(folder / "services" / f"{caller}.pub", service_keys[caller][1])
        key, cert = _make_cert(ca_key, ca_cert, svc, [svc, "localhost"])
        _write(folder / "tls" / "ca.crt", ca_pem)
        _write(folder / "tls" / "service.crt", cert.public_bytes(PEM))
        _write(folder / "tls" / "service.key", _private_pem(key), private=True)

    # Nginx: public HTTPS certificate + client certificate for mTLS to the services.
    key, cert = _make_cert(ca_key, ca_cert, "localhost", ["localhost"])
    _write(out / "nginx" / "server.crt", cert.public_bytes(PEM))
    _write(out / "nginx" / "server.key", _private_pem(key), private=True)
    key, cert = _make_cert(ca_key, ca_cert, "nginx", ["nginx"])
    _write(out / "nginx" / "client.crt", cert.public_bytes(PEM))
    _write(out / "nginx" / "client.key", _private_pem(key), private=True)
    _write(out / "nginx" / "ca.crt", ca_pem)

    _write(out / "offline" / "court.key", shared["court.key"], private=True)
    _write(out / "offline" / "ca.key", _private_pem(ca_key), private=True)
    _write(out / "offline" / "ca.crt", ca_pem)

    # Demo court orders for the frontend's recount screen (supporting evidence ids). Each is
    # signed with the court key; the Recount service re-verifies the signature on every use.
    court_key = serialization.load_pem_private_key(shared["court.key"], password=None)
    register = {order["court_order_ref"]: sign_order(court_key, **order) for order in DEMO_COURT_ORDERS}
    _write(out / "recount" / "court_orders.json", json.dumps(register, indent=2).encode())


# (court order ref, election, state, excluded candidates, issued on)
DEMO_COURT_ORDERS = [
    {"court_order_ref": "HC-2026-17", "election_id": "senate-2026", "state": "SA",
     "excluded_candidates": ["CAND-041"], "issued_on": "2026-11-02"},
    {"court_order_ref": "HC-2026-18", "election_id": "senate-2026", "state": "VIC",
     "excluded_candidates": ["CAND-052"], "issued_on": "2026-11-02"},
]


def sign_order(court_key, court_order_ref: str, election_id: str, state: str,
               excluded_candidates: list[str], issued_on: str) -> dict:
    """A court-order register entry: the signed grounds document plus its signature."""
    document = {
        "court_order_ref": court_order_ref,
        "election_id": election_id,
        "state": state,
        "excluded_candidates": sorted(excluded_candidates),
        "issued_on": issued_on,
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {**document, "ground": "COURT_ORDER",
            "grounds_signature": base64.b64encode(court_key.sign(canonical)).decode()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "keys")
    parser.add_argument("--force", action="store_true", help="delete and regenerate existing keys")
    args = parser.parse_args()
    if args.out.exists() and any(args.out.iterdir()):
        if not args.force:
            sys.exit(f"{args.out} already has keys. Use --force to replace them (invalidates all tokens and ballots).")
        shutil.rmtree(args.out)
    generate(args.out)
    print(f"Keys written to {args.out}")


if __name__ == "__main__":
    main()
