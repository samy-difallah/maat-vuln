"""Tests for the decision and report output models."""

import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from maat_vuln.models import (
    SCHEMA_VERSION,
    Decision,
    Explanation,
    FindingKey,
    Flag,
    KevSignal,
    PolicyRef,
    Report,
    Signals,
    Summary,
)

SNAPSHOT_ID = "a" * 64

DECISION = Decision(
    finding_key=FindingKey(id="CVE-2024-0001", component=None),
    priority="P1",
    rule_id="p1.kev",
    flags=[Flag.EPSS_MISSING],
    explanation=Explanation(
        rule="vulnerability is in KEV",
        thresholds={},
        signals=Signals(kev=KevSignal(in_kev=True), epss=None),
    ),
    policy_id="maat-default",
    policy_version=1,
    snapshot_id=SNAPSHOT_ID,
)

SUMMARY = Summary(P1=1, P2=0, P3=0, P4=0, unscored=0)


def make_report(**overrides):
    """Build a valid report, with some fields replaced."""
    fields = {
        "generated_at": datetime(2026, 10, 19, 12, tzinfo=UTC),
        "maat_version": "0.1.0",
        "policy": PolicyRef(id="maat-default", version=1),
        "snapshot_id": SNAPSHOT_ID,
        "decisions": [DECISION],
        "summary": SUMMARY,
    } | overrides
    return Report.model_validate(fields)


def test_report_round_trips():
    """A dumped report validates back to an equal report."""
    report = make_report()
    assert Report.model_validate_json(report.model_dump_json()) == report


def test_schema_version_is_dumped():
    """The default schema_version is part of every report."""
    assert make_report().model_dump()["schema_version"] == SCHEMA_VERSION


def test_generated_at_is_utc():
    """Timestamps are converted to UTC and dumped in RFC 3339."""
    paris = timezone(timedelta(hours=2))
    report = make_report(generated_at=datetime(2026, 10, 19, 14, tzinfo=paris))
    assert json.loads(report.model_dump_json())["generated_at"] == (
        "2026-10-19T12:00:00Z"
    )


def test_naive_generated_at_is_rejected():
    """A timestamp without a time zone is ambiguous."""
    with pytest.raises(ValidationError):
        make_report(generated_at=datetime(2026, 10, 19, 12))


@pytest.mark.parametrize("snapshot_id", ["a" * 63, "A" * 64, "g" * 64])
def test_bad_snapshot_id_is_rejected(snapshot_id):
    """Snapshot IDs are lowercase SHA-256 hex digests."""
    with pytest.raises(ValidationError):
        make_report(snapshot_id=snapshot_id)


@pytest.mark.parametrize(
    "override", [{"priority": "P5"}, {"flags": ["not_a_flag"]}]
)
def test_unknown_priority_or_flag_is_rejected(override):
    """Priorities and flags come from closed lists."""
    with pytest.raises(ValidationError):
        Decision.model_validate(DECISION.model_dump() | override)


def test_unscored_decision_has_null_priority():
    """An unscored decision dumps its priority as null."""
    decision = DECISION.model_copy(update={"priority": None})
    assert json.loads(decision.model_dump_json())["priority"] is None


def test_summary_needs_every_priority():
    """Summary keys are fixed, zero counts included."""
    with pytest.raises(ValidationError):
        Summary.model_validate({"P1": 1})
