"""Data contract: input findings and output report."""

from maat_vuln.models.finding import (
    CVE_PATTERN,
    Component,
    CvssInput,
    Finding,
    FindingKey,
    Provenance,
    VulnId,
    merge_findings,
)
from maat_vuln.models.input import SCHEMA_VERSION, FindingsInput
from maat_vuln.models.report import (
    SHA256_PATTERN,
    Decision,
    Explanation,
    Flag,
    PolicyRef,
    Priority,
    Report,
    SnapshotId,
    Summary,
    UtcDatetime,
)
from maat_vuln.models.signals import (
    CvssSignal,
    CvssValue,
    EpssSignal,
    KevSignal,
    OutputModel,
    Signals,
)

__all__ = [
    "CVE_PATTERN",
    "SCHEMA_VERSION",
    "SHA256_PATTERN",
    "Component",
    "CvssInput",
    "CvssSignal",
    "CvssValue",
    "Decision",
    "EpssSignal",
    "Explanation",
    "Finding",
    "FindingKey",
    "FindingsInput",
    "Flag",
    "KevSignal",
    "OutputModel",
    "PolicyRef",
    "Priority",
    "Provenance",
    "Report",
    "Signals",
    "SnapshotId",
    "Summary",
    "UtcDatetime",
    "VulnId",
    "merge_findings",
]
