"""Strict request models. Fixed shape (no free-form dicts), so hostile JSON such as deep nesting
or unexpected fields is rejected before any processing.

Formality follows the Senate "savings" rules: voters are INSTRUCTED to number at least 6
boxes above the line or 12 below, but a ballot stays formal with at least 1 above or 6 below.
"""
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

ATL_MIN, ATL_INSTRUCTED = 1, 6
BTL_MIN, BTL_INSTRUCTED = 6, 12
MAX_PREFS = 200

GroupCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{1,2}$")]  # A, B, ... AA
CandidateId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,32}$")]


class BallotSubmission(BaseModel):
    """Lists are in preference order: first item = 1, second = 2, ..."""
    model_config = ConfigDict(extra="forbid")

    above_the_line: list[GroupCode] | None = Field(default=None, max_length=MAX_PREFS)
    below_the_line: list[CandidateId] | None = Field(default=None, max_length=MAX_PREFS)

    @model_validator(mode="after")
    def _one_section(self) -> "BallotSubmission":
        atl, btl = self.above_the_line, self.below_the_line
        if bool(atl) == bool(btl):
            raise ValueError("Vote either above the line or below the line, not both or neither")
        prefs = atl or btl
        if len(set(prefs)) != len(prefs):
            raise ValueError("Each box can only be numbered once")
        if atl and len(atl) < ATL_MIN:
            raise ValueError(f"Number at least {ATL_INSTRUCTED} boxes above the line")
        if btl and len(btl) < BTL_MIN:
            raise ValueError(f"Number at least {BTL_INSTRUCTED} boxes below the line")
        return self


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidateId: CandidateId
    rank: int = Field(ge=1, le=MAX_PREFS)


class RankedBallot(BaseModel):
    """Frontend contract (frontend/src/api/client.ts: submitBallot).

    Simplification agreed for the prototype: the frontend ballot ranks candidates directly, and
    one ranked candidate is a formal vote. Ranks must run 1, 2, 3 ... with no gaps or repeats.
    """
    model_config = ConfigDict(extra="forbid")
    authorisationToken: str = Field(min_length=1, max_length=4096)
    electionId: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    state: str = Field(pattern=r"^(NSW|VIC|QLD|WA|SA|TAS|ACT|NT)$")
    selections: list[Selection] = Field(min_length=1, max_length=MAX_PREFS)
    configurationVersion: str = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def _ranks(self) -> "RankedBallot":
        ranks = sorted(s.rank for s in self.selections)
        if ranks != list(range(1, len(ranks) + 1)):
            raise ValueError("Ranks must be numbered 1, 2, 3 ... with no gaps or repeats")
        ids = [s.candidateId for s in self.selections]
        if len(set(ids)) != len(ids):
            raise ValueError("Each candidate can only be ranked once")
        return self

    def preferences(self) -> list[str]:
        return [s.candidateId for s in sorted(self.selections, key=lambda s: s.rank)]


class PartyOrder(BaseModel):
    """FIX_PARTY_ORDER: every group of the contest, in ballot-paper order."""
    model_config = ConfigDict(extra="forbid")
    group_order: list[GroupCode] = Field(min_length=1, max_length=MAX_PREFS)


def check_against_contest(ballot: BallotSubmission, group_codes: set[str], candidate_ids: set[str]) -> None:
    """Every mark must refer to a group or candidate in THIS state's contest."""
    if ballot.above_the_line:
        unknown = set(ballot.above_the_line) - group_codes
    else:
        unknown = set(ballot.below_the_line or []) - candidate_ids
    if unknown:
        raise ValueError("Ballot refers to groups or candidates not in this contest")
