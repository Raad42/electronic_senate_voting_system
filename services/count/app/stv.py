"""
Author: Raad
Edits:

Single Transferable Vote counting. Pure Python: no I/O, no randomness, exact fractions.

Simplified Senate-style STV:
  - Droop quota: floor(formal ballots / (seats + 1)) + 1
  - Surpluses transferred with the Weighted Inclusive Gregory Method: every paper in the
    elected candidate's pile carries on at weight x (surplus / candidate total)
  - When nobody reaches quota, the lowest candidate is excluded and all their papers move on
  - Court-ordered exclusions (recounts) are removed from every ballot before counting starts
  - Ties: lowest total in the most recent earlier round where they differed, then
    candidate order on the ballot paper (deterministic and reproducible)

This is a teaching implementation. The real AEC rules (bulk exclusion, last-parcel
transfers, rounding to whole votes) differ in detail; document any differences you keep.

Requirements:
    GR03 - a court-ordered exclusion is applied before counting, so the recount changes the result
    GR05 - the count uses exact fractions, so the same ballots always give the same result

Run:
    python -m pytest tests/test_stv.py -v

Usage example:
    ballots = [["A", "B"]] * 5 + [["C"]] * 4
    count_stv(["A", "B", "C"], ballots, seats=1)
    count_stv(["A", "B", "C"], ballots, seats=1, excluded={"A"})

Output:
    First count: the quota is 5 and A wins
    In the recount A is excluded, so A's 5 ballots move to B and B wins in round 1
"""
from dataclasses import dataclass, field
from fractions import Fraction


@dataclass
class Round:
    number: int
    action: str  # "elect", "exclude", "fill"
    candidate: str | None
    tallies: dict[str, str]  # candidate -> total as a string (exact fraction)
    exhausted: str


@dataclass
class StvResult:
    seats: int
    quota: int
    formal_ballots: int
    elected: list[str]
    excluded_by_order: list[str]
    rounds: list[Round] = field(default_factory=list)


@dataclass
class _Paper:
    prefs: tuple[str, ...]
    weight: Fraction
    pos: int = 0


def count_stv(
    candidates: list[str],
    ballots: list[list[str]],
    seats: int,
    excluded: set[str] | None = None,
) -> StvResult:
    if seats < 1:
        raise ValueError("seats must be at least 1")
    excluded_by_order = set(excluded or ())
    unknown = excluded_by_order - set(candidates)
    if unknown:
        raise ValueError(f"excluded candidates not in contest: {sorted(unknown)}")

    order = {c: i for i, c in enumerate(candidates)}
    continuing = [c for c in candidates if c not in excluded_by_order]
    papers: list[_Paper] = []
    for ballot in ballots:
        seen: set[str] = set()
        prefs = []
        for c in ballot:
            if c in order and c not in excluded_by_order and c not in seen:
                prefs.append(c)
                seen.add(c)
        if prefs:
            papers.append(_Paper(tuple(prefs), Fraction(1)))

    formal = len(papers)
    quota = formal // (seats + 1) + 1
    elected: list[str] = []
    rounds: list[Round] = []
    history: list[dict[str, Fraction]] = []
    piles: dict[str, list[_Paper]] = {c: [] for c in candidates}
    exhausted = Fraction(0)

    def place(paper: _Paper) -> None:
        nonlocal exhausted
        while paper.pos < len(paper.prefs) and paper.prefs[paper.pos] not in continuing:
            paper.pos += 1
        if paper.pos < len(paper.prefs):
            piles[paper.prefs[paper.pos]].append(paper)
        else:
            exhausted += paper.weight

    def tallies() -> dict[str, Fraction]:
        return {c: sum((p.weight for p in piles[c]), Fraction(0)) for c in continuing}

    def record(action: str, candidate: str | None, t: dict[str, Fraction]) -> None:
        rounds.append(Round(len(rounds) + 1, action, candidate,
                            {c: str(v) for c, v in t.items()}, str(exhausted)))

    def tie_key(c: str, t: dict[str, Fraction]):
        # Earlier-round totals, newest first, then ballot-paper order.
        return (t[c], *[h.get(c, Fraction(0)) for h in reversed(history)], order[c])

    for paper in papers:
        place(paper)

    while len(elected) < seats and continuing:
        t = tallies()
        if len(continuing) <= seats - len(elected):
            for c in sorted(continuing, key=lambda c: (-t[c], order[c])):
                elected.append(c)
                record("fill", c, t)
            continuing.clear()
            break

        reached = [c for c in continuing if t[c] >= quota]
        if reached:
            winner = max(reached, key=lambda c: (t[c], *[h.get(c, 0) for h in reversed(history)], -order[c]))
            elected.append(winner)
            continuing.remove(winner)
            surplus = t[winner] - quota
            transfer_value = surplus / t[winner] if t[winner] else Fraction(0)
            record("elect", winner, t)
            moving, piles[winner] = piles[winner], []
            for paper in moving:
                paper.weight *= transfer_value
                if paper.weight:
                    place(paper)
        else:
            loser = min(continuing, key=lambda c: tie_key(c, t))
            continuing.remove(loser)
            excluded_by_order.add(loser)
            record("exclude", loser, t)
            moving, piles[loser] = piles[loser], []
            for paper in moving:
                place(paper)
        history.append(t)

    return StvResult(
        seats=seats,
        quota=quota,
        formal_ballots=formal,
        elected=elected,
        excluded_by_order=sorted(excluded or ()),
        rounds=rounds,
    )


def expand_ballot(marks: dict, groups: dict[str, list[str]]) -> list[str]:
    """Turn a decrypted ballot into a candidate preference list.

    Above the line: each numbered group expands to its candidates in ballot-paper order.
    Below the line: the candidate list is used as is.
    """
    if marks.get("above_the_line"):
        prefs: list[str] = []
        for code in marks["above_the_line"]:
            prefs.extend(groups.get(code, []))
        return prefs
    return list(marks.get("below_the_line") or [])
