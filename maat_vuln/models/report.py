"""Output contract: decisions and the report that carries them."""

from datetime import UTC
from enum import StrEnum
from typing import Annotated, Literal, get_args

from pydantic import AfterValidator, AwareDatetime, Field

from maat_vuln.models.finding import FindingKey
from maat_vuln.models.input import SCHEMA_VERSION
from maat_vuln.models.signals import OutputModel, Signals

Priority = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
# Most urgent first: the sort order, and P1-P4 by position.
PRIORITIES: tuple[Priority, ...] = get_args(Priority)

SHA256_PATTERN = r"^[0-9a-f]{64}$"

SnapshotId = Annotated[str, Field(pattern=SHA256_PATTERN)]

UtcDatetime = Annotated[
    AwareDatetime, AfterValidator(lambda value: value.astimezone(UTC))
]

Count = Annotated[int, Field(ge=0)]


class Flag(StrEnum):
    """Data-quality flag attached to a decision."""

    CVSS_MISSING = "cvss_missing"
    CVSS_LOOKUP_FAILED = "cvss_lookup_failed"
    EPSS_MISSING = "epss_missing"
    CVSS_LEGACY = "cvss_legacy"
    UNRESOLVED_ID = "unresolved_id"
    UNSCORED = "unscored"


class Explanation(OutputModel):
    """Why a rule matched: its condition, thresholds and signal values."""

    rule: str
    thresholds: dict[str, float]
    signals: Signals


class Decision(OutputModel):
    """Priority given to one finding, with the rule that set it."""

    finding_key: FindingKey
    priority: Priority | None
    rule_id: str
    flags: list[Flag]
    explanation: Explanation
    policy_id: str
    policy_version: int
    snapshot_id: SnapshotId


class PolicyRef(OutputModel):
    """Policy a report was computed with."""

    id: str
    version: int


class Summary(OutputModel):
    """Number of decisions per priority, ``unscored`` for no priority."""

    CRITICAL: Count
    HIGH: Count
    MEDIUM: Count
    LOW: Count
    unscored: Count


class Report(OutputModel):
    """Top-level output document: sorted decisions and their summary."""

    schema_version: str = SCHEMA_VERSION
    generated_at: UtcDatetime
    maat_version: str
    policy: PolicyRef
    snapshot_id: SnapshotId
    decisions: list[Decision]
    summary: Summary
