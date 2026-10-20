"""Default policy ``maat-default`` v1: rules, flags and CVSS selection."""

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from pydantic import MISSING

from maat_vuln.models import (
    CVE_PATTERN,
    CvssSignal,
    CvssValue,
    Decision,
    EpssSignal,
    Explanation,
    FindingKey,
    Flag,
    KevSignal,
    Priority,
    Signals,
)

POLICY_ID = "maat-default"
# Changing any threshold below increments the policy version.
POLICY_VERSION = 1

EPSS_LIKELY = 0.10
EPSS_WATCH = 0.01
CVSS_HIGH = 7.0
CVSS_LOW_CAP = 4.0

# Provisional: the selection order may change, keep it in one place.
CVSS_VERSION_ORDER = ("4.0", "3.1", "3.0", "2.0")
LEGACY_CVSS_VERSION = "2.0"


def select_cvss(values: list[CvssValue]) -> CvssSignal:
    """Select the newest CVSS version, then its highest base score.

    On equal scores the first value wins, as ``max`` keeps it.
    """
    selected = max(
        values,
        key=lambda value: (
            -CVSS_VERSION_ORDER.index(value.version),
            value.base_score,
        ),
    )
    return CvssSignal(values=values, selected=selected)


@dataclass(frozen=True)
class Rule:
    """Policy rule: when ``matches`` holds, the finding gets ``priority``.

    ``matches`` receives the KEV status, the EPSS probability and the
    selected CVSS base score; ``None`` means the value is unknown.
    """

    id: str
    priority: Priority | None
    condition: str
    thresholds: dict[str, float]
    matches: Callable[[bool, float | None, float | None], bool]


P1_KEV = Rule(
    id="p1.kev",
    priority="P1",
    condition="vulnerability is in KEV",
    thresholds={},
    matches=lambda kev, epss, cvss: kev,
)
P2_EPSS_LIKELY = Rule(
    id="p2.epss_likely",
    priority="P2",
    condition=(
        f"EPSS probability ≥ {EPSS_LIKELY:.2f}"
        f" and not (CVSS < {CVSS_LOW_CAP:.1f})"
    ),
    thresholds={"EPSS_LIKELY": EPSS_LIKELY, "CVSS_LOW_CAP": CVSS_LOW_CAP},
    # An unknown CVSS does not cap: missing data never lowers a priority.
    matches=lambda kev, epss, cvss: (
        epss is not None
        and epss >= EPSS_LIKELY
        and (cvss is None or cvss >= CVSS_LOW_CAP)
    ),
)
P3_EPSS_CAPPED_LOW_CVSS = Rule(
    id="p3.epss_capped_low_cvss",
    priority="P3",
    condition=(
        f"EPSS probability ≥ {EPSS_LIKELY:.2f} but CVSS < {CVSS_LOW_CAP:.1f}"
    ),
    thresholds={"EPSS_LIKELY": EPSS_LIKELY, "CVSS_LOW_CAP": CVSS_LOW_CAP},
    matches=lambda kev, epss, cvss: (
        epss is not None
        and epss >= EPSS_LIKELY
        and cvss is not None
        and cvss < CVSS_LOW_CAP
    ),
)
P3_WATCH = Rule(
    id="p3.watch",
    priority="P3",
    condition=(
        f"EPSS probability ≥ {EPSS_WATCH:.2f} or CVSS ≥ {CVSS_HIGH:.1f}"
    ),
    thresholds={"EPSS_WATCH": EPSS_WATCH, "CVSS_HIGH": CVSS_HIGH},
    matches=lambda kev, epss, cvss: (
        (epss is not None and epss >= EPSS_WATCH)
        or (cvss is not None and cvss >= CVSS_HIGH)
    ),
)
P4_LOW = Rule(
    id="p4.low",
    priority="P4",
    condition="at least one signal available",
    thresholds={},
    matches=lambda kev, epss, cvss: (
        kev or epss is not None or cvss is not None
    ),
)
NONE_UNSCORED = Rule(
    id="none.unscored",
    priority=None,
    condition="no KEV, EPSS or CVSS data",
    thresholds={},
    matches=lambda kev, epss, cvss: True,
)

RULES = (
    P1_KEV,
    P2_EPSS_LIKELY,
    P3_EPSS_CAPPED_LOW_CVSS,
    P3_WATCH,
    P4_LOW,
    NONE_UNSCORED,
)


def _epss(signals: Signals) -> EpssSignal | None:
    """EPSS signal, or ``None`` when absent or not in the feed."""
    return signals.epss if isinstance(signals.epss, EpssSignal) else None


def _cvss(signals: Signals) -> CvssValue | None:
    """Selected CVSS value, or ``None`` when absent or not found."""
    if isinstance(signals.cvss, CvssSignal):
        return signals.cvss.selected
    return None


def _flags(
    finding_key: FindingKey, signals: Signals, priority: Priority | None
) -> list[Flag]:
    """Data-quality flags, in ``Flag`` order for a stable output."""
    resolved = CVE_PATTERN.fullmatch(finding_key.id) is not None
    cvss = _cvss(signals)
    # Without a CVE pivot no lookup runs, so an absent CVSS is not a
    # failure; with one, absent means the lookup failed.
    lookup_failed = resolved and signals.cvss is MISSING
    raised = {
        Flag.CVSS_MISSING: cvss is None and not lookup_failed,
        Flag.CVSS_LOOKUP_FAILED: lookup_failed,
        Flag.EPSS_MISSING: _epss(signals) is None,
        Flag.CVSS_LEGACY: (
            cvss is not None and cvss.version == LEGACY_CVSS_VERSION
        ),
        Flag.UNRESOLVED_ID: not resolved,
        Flag.UNSCORED: priority is None,
    }
    return [flag for flag in Flag if raised[flag]]


def decide(
    finding_key: FindingKey, signals: Signals, snapshot_id: str
) -> Decision:
    """Apply the first matching rule to a finding's signals."""
    kev = isinstance(signals.kev, KevSignal) and signals.kev.in_kev
    epss = _epss(signals)
    cvss = _cvss(signals)
    rule = next(
        rule
        for rule in RULES
        if rule.matches(
            kev,
            epss.probability if epss else None,
            cvss.base_score if cvss else None,
        )
    )
    return Decision(
        finding_key=finding_key,
        priority=rule.priority,
        rule_id=rule.id,
        flags=_flags(finding_key, signals, rule.priority),
        explanation=Explanation(
            rule=rule.condition,
            thresholds=rule.thresholds,
            signals=signals,
        ),
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        snapshot_id=snapshot_id,
    )


def _sort_key(
    decision: Decision,
) -> tuple[bool, str, float, float, str, bool, str]:
    """Priority, then EPSS and CVSS descending, then finding key."""
    signals = decision.explanation.signals
    epss = _epss(signals)
    cvss = _cvss(signals)
    key = decision.finding_key
    return (
        decision.priority is None,
        decision.priority or "",
        -epss.probability if epss else 1,
        -cvss.base_score if cvss else 1,
        key.id,
        key.component is not None,
        key.component or "",
    )


def sort_decisions(decisions: Iterable[Decision]) -> list[Decision]:
    """Sort decisions in report order (design §4)."""
    return sorted(decisions, key=_sort_key)
