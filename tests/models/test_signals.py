"""Tests for the per-vulnerability signal models."""

import json

import pytest
from pydantic import ValidationError

from maat_vuln.models import (
    CvssSignal,
    CvssValue,
    EpssSignal,
    KevSignal,
    Signals,
)

EPSS = EpssSignal(
    probability=0.42,
    percentile=0.97,
    model_version="v2025.03.14",
    score_date="2026-10-19",
)
CVSS = CvssValue(
    version="3.1", base_score=9.8, vector=None, source="vulnerability-lookup"
)


@pytest.mark.parametrize(
    ("signals", "dumped"),
    [
        (Signals(), {}),
        (Signals(epss=None, cvss=None), {"epss": None, "cvss": None}),
        (
            Signals(kev=KevSignal(in_kev=False), epss=EPSS),
            {
                "kev": {"in_kev": False},
                "epss": {
                    "probability": 0.42,
                    "percentile": 0.97,
                    "model_version": "v2025.03.14",
                    "score_date": "2026-10-19",
                },
            },
        ),
    ],
)
def test_absent_and_null_survive_round_trip(signals, dumped):
    """Not computed is dropped, no result is null, both round-trip."""
    text = signals.model_dump_json()
    assert json.loads(text) == dumped
    assert Signals.model_validate_json(text) == signals


def test_unknown_fields_are_rejected():
    """Output is strict."""
    with pytest.raises(ValidationError):
        Signals.model_validate({"kev": {"in_kev": True, "extra": 1}})


@pytest.mark.parametrize("probability", [-0.01, 1.01])
def test_epss_probability_out_of_range_is_rejected(probability):
    """EPSS probabilities lie in [0, 1]."""
    with pytest.raises(ValidationError):
        EPSS.model_validate(EPSS.model_dump() | {"probability": probability})


def test_cvss_score_out_of_range_is_rejected():
    """CVSS base scores lie in [0, 10]."""
    with pytest.raises(ValidationError):
        CvssValue(version="3.1", base_score=11, vector=None, source="input")


def test_cvss_signal_needs_a_value():
    """A CVSS signal without values is null, not an empty list."""
    with pytest.raises(ValidationError):
        CvssSignal(values=[], selected=CVSS)
