import pytest
from pydantic import ValidationError

from conftest import load_module

schemas = load_module("services/ballot/app/schemas.py")
Ballot = schemas.BallotSubmission


def test_valid_above_and_below_the_line():
    Ballot(above_the_line=["A"])
    Ballot(below_the_line=["NSW-A1", "NSW-A2", "NSW-B1", "NSW-B2", "NSW-C1", "NSW-C2"])


@pytest.mark.parametrize("body", [
    {},                                                         # nothing marked
    {"above_the_line": ["A"], "below_the_line": ["X"] * 6},     # both sections
    {"above_the_line": ["A", "A"]},                             # duplicate number
    {"below_the_line": ["a", "b", "c"]},                        # fewer than 6 below
    {"above_the_line": ["A"], "voter": "Jane"},                 # extra field
    {"above_the_line": ["a; DROP TABLE"]},                      # bad group code
    {"above_the_line": [{"nested": ["deep"]}]},                 # wrong type
    {"above_the_line": ["A"] * 201},                            # too many
])
def test_rejected(body):
    with pytest.raises(ValidationError):
        Ballot(**body)


def test_marks_must_belong_to_this_contest():
    with pytest.raises(ValueError):
        schemas.check_against_contest(Ballot(above_the_line=["Z"]), {"A", "B"}, set())
    schemas.check_against_contest(Ballot(above_the_line=["B", "A"]), {"A", "B"}, set())
