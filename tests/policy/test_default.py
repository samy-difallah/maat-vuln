"""Tests for the default policy maat-default v1."""

from datetime import date

import pytest

from maat_vuln.models import (
    CvssValue,
    EpssSignal,
    FindingKey,
    Flag,
    KevSignal,
    Signals,
)
from maat_vuln.policy import (
    CVSS_HIGH,
    CVSS_LOW_CAP,
    EPSS_LIKELY,
    EPSS_WATCH,
    POLICY_ID,
    POLICY_VERSION,
    decide,
    select_cvss,
    sort_decisions,
)

SNAPSHOT_ID = "a" * 64
CVE_KEY = FindingKey(id="CVE-2024-0001", component=None)


def cvss_value(score, version="3.1", source="input"):
    """Build a CVSS value."""
    return CvssValue(
        version=version, base_score=score, vector=None, source=source
    )


def epss_signal(probability):
    """Build an EPSS signal."""
    return EpssSignal(
        probability=probability,
        percentile=0.5,
        model_version="v2025.03.14",
        score_date=date(2026, 10, 20),
    )


def make_signals(kev=False, epss=None, cvss=None):
    """Build the signals of a CVE pivot; ``None`` means not in the feed."""
    return Signals(
        kev=KevSignal(in_kev=kev),
        epss=epss and epss_signal(epss),
        cvss=cvss and select_cvss([cvss_value(cvss)]),
    )


@pytest.mark.parametrize(
    ("kev", "epss", "cvss", "priority", "rule_id"),
    [
        (True, None, None, "P1", "p1.kev"),
        (True, 0.0001, 1.0, "P1", "p1.kev"),
        (False, EPSS_LIKELY, CVSS_LOW_CAP, "P2", "p2.epss_likely"),
        (False, 0.9, None, "P2", "p2.epss_likely"),
        (False, 0.9, 3.9, "P3", "p3.epss_capped_low_cvss"),
        (False, EPSS_WATCH, 1.0, "P3", "p3.watch"),
        (False, 0.0001, CVSS_HIGH, "P3", "p3.watch"),
        (False, None, CVSS_HIGH, "P3", "p3.watch"),
        (False, 0.0099, 6.9, "P4", "p4.low"),
        (False, None, 1.0, "P4", "p4.low"),
        (False, 0.0001, None, "P4", "p4.low"),
        (False, None, None, None, "none.unscored"),
    ],
)
def test_first_matching_rule_sets_priority(kev, epss, cvss, priority, rule_id):
    """Each rule matches at its boundaries; missing data never caps."""
    decision = decide(CVE_KEY, make_signals(kev, epss, cvss), SNAPSHOT_ID)
    assert (decision.priority, decision.rule_id) == (priority, rule_id)


def test_decision_carries_policy_and_explanation():
    """The decision names the policy, rule text, thresholds and signals."""
    signals = make_signals(epss=0.5, cvss=9.8)
    decision = decide(CVE_KEY, signals, SNAPSHOT_ID)
    assert decision.policy_id == POLICY_ID
    assert decision.policy_version == POLICY_VERSION
    assert decision.snapshot_id == SNAPSHOT_ID
    assert decision.finding_key == CVE_KEY
    assert decision.flags == []
    assert decision.explanation.rule == (
        "EPSS probability ≥ 0.10 and not (CVSS < 4.0)"
    )
    assert decision.explanation.thresholds == {
        "EPSS_LIKELY": 0.10,
        "CVSS_LOW_CAP": 4.0,
    }
    assert decision.explanation.signals == signals


@pytest.mark.parametrize(
    ("key", "signals", "flags"),
    [
        (
            CVE_KEY,
            make_signals(epss=0.5),
            [Flag.CVSS_MISSING],
        ),
        (
            CVE_KEY,
            Signals(kev=KevSignal(in_kev=False), epss=epss_signal(0.5)),
            [Flag.CVSS_LOOKUP_FAILED],
        ),
        (
            CVE_KEY,
            make_signals(cvss=5.0),
            [Flag.EPSS_MISSING],
        ),
        (
            CVE_KEY,
            Signals(
                kev=KevSignal(in_kev=False),
                epss=epss_signal(0.5),
                cvss=select_cvss([cvss_value(5.0, version="2.0")]),
            ),
            [Flag.CVSS_LEGACY],
        ),
        (
            CVE_KEY,
            make_signals(),
            [Flag.CVSS_MISSING, Flag.EPSS_MISSING, Flag.UNSCORED],
        ),
        (
            FindingKey(id="GHSA-AAAA-BBBB-CCCC", component=None),
            Signals(),
            [
                Flag.CVSS_MISSING,
                Flag.EPSS_MISSING,
                Flag.UNRESOLVED_ID,
                Flag.UNSCORED,
            ],
        ),
        (
            FindingKey(id="GHSA-AAAA-BBBB-CCCC", component=None),
            Signals(cvss=select_cvss([cvss_value(9.0)])),
            [Flag.EPSS_MISSING, Flag.UNRESOLVED_ID],
        ),
    ],
)
def test_flags_name_each_missing_signal(key, signals, flags):
    """Each missing signal raises its flag, in ``Flag`` order."""
    assert decide(key, signals, SNAPSHOT_ID).flags == flags


def test_select_cvss_prefers_newest_version():
    """A newer CVSS version wins over a higher score."""
    values = [
        cvss_value(9.0, version="2.0"),
        cvss_value(5.0, version="3.1"),
        cvss_value(8.0, version="3.0"),
        cvss_value(4.0, version="4.0"),
    ]
    signal = select_cvss(values)
    assert signal.selected == values[3]
    assert signal.values == values


def test_select_cvss_breaks_version_tie_on_highest_score():
    """Within a version, the highest score wins, then the first one."""
    first = cvss_value(7.5)
    values = [
        cvss_value(5.0),
        first,
        cvss_value(7.5, source="vulnerability-lookup"),
    ]
    assert select_cvss(values).selected is first


def make_decision(key_id="CVE-2024-0001", component=None, **signals):
    """Decide on a finding built from its key and signals."""
    key = FindingKey(id=key_id, component=component)
    return decide(key, make_signals(**signals), SNAPSHOT_ID)


def test_sort_decisions_follows_report_order():
    """Priority, then EPSS and CVSS descending, then finding key."""
    expected = [
        make_decision(kev=True),
        make_decision(epss=0.9, cvss=5.0),
        make_decision(epss=0.5, cvss=9.0),
        make_decision(epss=0.5, cvss=5.0),
        make_decision(epss=0.5),
        make_decision(epss=EPSS_WATCH),
        make_decision(cvss=9.0),
        make_decision(epss=0.001, cvss=1.0),
        make_decision(key_id="CVE-2024-0001"),
        make_decision(key_id="CVE-2024-0001", component="pkg:pypi/a@1"),
        make_decision(key_id="CVE-2024-0002"),
    ]
    assert sort_decisions(reversed(expected)) == expected
