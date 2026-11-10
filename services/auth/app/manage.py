"""Admin commands run inside the auth container (the only place that can reach the auth DB).

    docker compose exec auth python -m app.manage create-official \
        --username eo.nsw --role ELECTION_OFFICIAL --election SEN2028 --state NSW
    docker compose exec auth python -m app.manage create-official --username aud.kim --role AUDITOR
    docker compose exec auth python -m app.manage add-role \
        --username eo.nsw --role COUNT_OPERATOR --election SEN2028 --state NSW

An official may hold several roles, but signs in to one at a time (Milestone 2 Section 2.3).
Every role except AUDITOR is scoped to one election and one state.

The password is prompted for (never passed on the command line) and the TOTP secret is
printed once as an otpauth:// URI to add to an authenticator app.
"""
import argparse
import getpass
import sys

import pyotp
from argon2 import PasswordHasher
from sqlalchemy import text

from common.db import get_engine
from common.settings import get_settings

ROLES = ("ELECTION_OFFICIAL", "COUNT_OPERATOR", "RECOUNT_DELEGATE", "AUDITOR")
STATES = ("NSW", "VIC", "QLD", "WA", "SA", "TAS", "ACT", "NT")


def _check_scope(args: argparse.Namespace) -> None:
    if args.role != "AUDITOR" and not (args.election and args.state):
        sys.exit(f"{args.role} must be scoped with --election and --state")
    if args.role == "AUDITOR" and (args.election or args.state):
        sys.exit("AUDITOR is read-only across the audit log and takes no scope")


def _add_role(conn, args: argparse.Namespace) -> None:
    conn.execute(
        text("""INSERT INTO official_roles (username, role, scope_election, scope_state)
                VALUES (:u, :r, :e, :s)"""),
        {"u": args.username, "r": args.role, "e": args.election, "s": args.state},
    )


def create_official(args: argparse.Namespace) -> None:
    _check_scope(args)
    password = getpass.getpass("Password (min 12 characters): ")
    if len(password) < 12 or password != getpass.getpass("Repeat password: "):
        sys.exit("Passwords must match and be at least 12 characters")

    secret = pyotp.random_base32()
    with get_engine(get_settings().database_url).begin() as conn:
        conn.execute(
            text("INSERT INTO officials (username, password_hash, totp_secret) VALUES (:u, :p, :t)"),
            {"u": args.username, "p": PasswordHasher().hash(password), "t": secret},
        )
        _add_role(conn, args)
    print(f"Created {args.role} '{args.username}'.")
    print("Add this to an authenticator app (shown once):")
    print(pyotp.TOTP(secret).provisioning_uri(name=args.username, issuer_name="Senate Voting"))


def add_role(args: argparse.Namespace) -> None:
    _check_scope(args)
    with get_engine(get_settings().database_url).begin() as conn:
        _add_role(conn, args)
    print(f"Added {args.role} to '{args.username}'.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.manage")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, func in (("create-official", create_official), ("add-role", add_role)):
        p = sub.add_parser(name)
        p.add_argument("--username", required=True)
        p.add_argument("--role", required=True, choices=ROLES)
        p.add_argument("--election")
        p.add_argument("--state", choices=STATES)
        p.set_defaults(func=func)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
