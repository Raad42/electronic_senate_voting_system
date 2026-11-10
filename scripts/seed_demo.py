"""Seed disposable local databases with one elector and one polling election."""

from pathlib import Path
import os

import psycopg
from argon2 import PasswordHasher


ROOT = Path(__file__).resolve().parents[1]
PORTS = {"roll": 5541, "ballot": 5543}
PASSWORDS = {"roll": "ROLL_DB_SUPERUSER_PASSWORD", "ballot": "BALLOT_DB_SUPERUSER_PASSWORD"}


def env_values() -> dict[str, str]:
    values: dict[str, str] = {}
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    values.update({key: value for key, value in os.environ.items() if value})
    return values


def connect(database: str, values: dict[str, str]) -> psycopg.Connection:
    password = values.get(PASSWORDS[database])
    if not password:
        raise RuntimeError(f"{PASSWORDS[database]} is not set")
    return psycopg.connect(
        host="127.0.0.1",
        port=PORTS[database],
        dbname=database,
        user="postgres",
        password=password,
        autocommit=True,
    )


def seed_roll(values: dict[str, str]) -> None:
    password_hash = PasswordHasher().hash("demo-password")
    with connect("roll", values) as conn:
        conn.execute(
            "INSERT INTO roll.enrolment (enrolment_id, state, password_hash) "
            "VALUES ('ELECTOR-001', 'SA', %s) "
            "ON CONFLICT (enrolment_id) DO UPDATE SET state = EXCLUDED.state, password_hash = EXCLUDED.password_hash",
            (password_hash,),
        )


def seed_ballot(values: dict[str, str]) -> None:
    candidates = [
        ("11111111-1111-4111-8111-111111111111", "Candidate 041"),
        ("22222222-2222-4222-8222-222222222222", "Candidate 052"),
        ("33333333-3333-4333-8333-333333333333", "Candidate 063"),
    ]
    with connect("ballot", values) as conn:
        conn.execute(
            "INSERT INTO election.election (election_id, state) VALUES ('SENATE-2026', 'SA') "
            "ON CONFLICT (election_id) DO NOTHING"
        )
        phase = conn.execute(
            "SELECT phase::text FROM election.election WHERE election_id = 'SENATE-2026'"
        ).fetchone()[0]
        if phase == "NOMINATIONS":
            for candidate_id, name in candidates:
                conn.execute(
                    "INSERT INTO election.candidate (candidate_id, election_id, name, position_in_group) "
                    "VALUES (%s, 'SENATE-2026', %s, 1) ON CONFLICT (candidate_id) DO NOTHING",
                    (candidate_id, name),
                )
            for next_phase in ("NOMINATIONS_COMMITTED", "ORDER_FIXED", "POLLING"):
                conn.execute("UPDATE election.election SET phase = %s WHERE election_id = 'SENATE-2026'", (next_phase,))
        elif phase in {"NOMINATIONS_COMMITTED", "ORDER_FIXED"}:
            for next_phase in (("ORDER_FIXED", "POLLING") if phase == "NOMINATIONS_COMMITTED" else ("POLLING",)):
                conn.execute("UPDATE election.election SET phase = %s WHERE election_id = 'SENATE-2026'", (next_phase,))
        elif phase != "POLLING":
            raise RuntimeError(f"SENATE-2026 is in {phase}; reset the ballot database before reseeding")


def main() -> None:
    values = env_values()
    seed_roll(values)
    seed_ballot(values)
    print("Seeded development data:")
    print("  enrolmentId: ELECTOR-001")
    print("  password:    demo-password")
    print("  electionId:  SENATE-2026")
    print("  state:       SA")
    print("  phase:       POLLING")


if __name__ == "__main__":
    main()
