"""Data contract: input findings and output report."""

from maat_vuln.models.finding import (
    CVE_PATTERN,
    Component,
    CvssInput,
    Finding,
    FindingKey,
    Provenance,
    merge_findings,
)
from maat_vuln.models.input import SCHEMA_VERSION, FindingsInput
from maat_vuln.models.report import (
    Decision,
    Explanation,
    Flag,
    PolicyRef,
    Priority,
    Report,
    Summary,
)
from maat_vuln.models.signals import (
    CvssSignal,
    CvssValue,
    EpssSignal,
    KevSignal,
    Signals,
)

__all__ = [
    "CVE_PATTERN",
    "SCHEMA_VERSION",
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
    "PolicyRef",
    "Priority",
    "Provenance",
    "Report",
    "Signals",
    "Summary",
    "merge_findings",
]
