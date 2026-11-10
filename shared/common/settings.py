"""Configuration read from environment variables (prefix SV_) and key files.

Production is the default: a service only relaxes anything when SV_ENVIRONMENT is
explicitly set to "development" or "test". Secrets are never given defaults.
"""
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SV_", extra="ignore")

    environment: Literal["production", "development", "test"] = "production"
    service_name: Literal["auth", "ballot", "count", "recount", "audit", "pdp"]

    # Each service only receives the connection strings for the databases it owns.
    database_url: str | None = None
    roll_database_url: str | None = None  # auth service only

    # Folder holding ONLY the keys this service needs (see scripts/gen_keys.py).
    keys_dir: Path = Path("/run/keys")

    # Internal service locations (https when tls_enabled).
    audit_url: str = "https://audit:8443"
    pdp_url: str = "https://pdp:8443"
    ballot_url: str = "https://ballot:8443"
    count_url: str = "https://count:8443"
    auth_url: str = "https://auth:8443"

    tls_enabled: bool = True
    port: int = 8443

    # Milestone 2, Tables 4 and 11.
    token_issuer: str = "aec-auth"
    session_idle_minutes: int = 30
    session_absolute_hours: int = 8
    stepup_seconds: int = 120
    ballot_token_minutes: int = 15
    service_token_seconds: int = 60

    login_max_failures: int = 5
    login_lockout_minutes: int = 15

    # Elections Auth will issue voting authorisations for. Auth cannot see the ballot database,
    # so without this list a voter could ask for one authorisation per made-up election id.
    active_elections: str = "senate-2026,SEN2028"
    default_election_id: str = "senate-2026"

    max_body_bytes: int = 64_000
    http_timeout_seconds: float = 5.0

    @model_validator(mode="after")
    def _production_rules(self) -> "Settings":
        if self.environment == "production" and not self.tls_enabled:
            raise ValueError("SV_TLS_ENABLED must be true in production")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def active_election_ids(self) -> set[str]:
        return {e.strip() for e in self.active_elections.split(",") if e.strip()}

    def scheme_url(self, url: str) -> str:
        """Lets development run without TLS by swapping https:// for http://."""
        return url if self.tls_enabled else url.replace("https://", "http://", 1)


@lru_cache
def get_settings() -> Settings:
    return Settings()
