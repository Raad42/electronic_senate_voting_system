import pytest

from conftest import load_module

stv = load_module("services/count/app/stv.py")


def test_majority_single_seat():
    r = stv.count_stv(["A", "B", "C"], [["A"]] * 6 + [["B"]] * 3 + [["C"]] * 2, seats=1)
    assert r.quota == 6 and r.elected == ["A"]


def test_exclusion_transfers_preferences():
    # Nobody has quota (5). C is excluded and C's votes go to B, so B wins.
    ballots = [["A"]] * 4 + [["B"]] * 3 + [["C", "B"]] * 2
    r = stv.count_stv(["A", "B", "C"], ballots, seats=1)
    assert r.elected == ["B"]
    assert [x.action for x in r.rounds][0] == "exclude"


def test_surplus_transfer_elects_running_mate():
    # Quota for 2 seats of 10 ballots = 4. A has 7 (surplus 3, all to A2); A2 then beats B.
    ballots = [["A", "A2"]] * 7 + [["B"]] * 2 + [["C"]] * 1
    r = stv.count_stv(["A", "A2", "B", "C"], ballots, seats=2)
    assert r.quota == 4
    assert r.elected == ["A", "A2"]


def test_court_exclusion_changes_result():
    ballots = [["A", "B"]] * 5 + [["C"]] * 4
    assert stv.count_stv(["A", "B", "C"], ballots, seats=1).elected == ["A"]
    recount = stv.count_stv(["A", "B", "C"], ballots, seats=1, excluded={"A"})
    assert recount.elected == ["B"]
    assert recount.excluded_by_order == ["A"]


def test_unknown_exclusion_rejected():
    with pytest.raises(ValueError):
        stv.count_stv(["A", "B"], [["A"]], seats=1, excluded={"Z"})


def test_exhausted_ballots_and_fill_remaining_seats():
    r = stv.count_stv(["A", "B", "C"], [["A"]] * 3 + [["B"]] * 1, seats=2)
    assert set(r.elected) == {"A", "B"}


def test_ignores_unknown_and_duplicate_preferences():
    r = stv.count_stv(["A", "B"], [["Z", "A", "A", "B"]] * 3, seats=1)
    assert r.formal_ballots == 3 and r.elected == ["A"]


def test_result_is_deterministic():
    ballots = [["A", "B"], ["B", "A"], ["C", "A"], ["C", "B"]] * 5
    runs = {tuple(stv.count_stv(["A", "B", "C"], ballots, seats=2).elected) for _ in range(5)}
    assert len(runs) == 1


def test_expand_above_the_line():
    groups = {"A": ["A1", "A2"], "B": ["B1", "B2"]}
    assert stv.expand_ballot({"above_the_line": ["B", "A"]}, groups) == ["B1", "B2", "A1", "A2"]
    assert stv.expand_ballot({"below_the_line": ["A2", "B1"]}, groups) == ["A2", "B1"]
