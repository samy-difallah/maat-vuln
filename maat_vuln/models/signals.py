"""Per-vulnerability signals resolved from the snapshot.

A field left at ``MISSING`` was not computed and is dropped on dump; a
``None`` field was looked up without result and is dumped as ``null``.
"""

from datetime import date
from typing import Annotated, Literal

from pydantic import MISSING, BaseModel, ConfigDict, Field

from maat_vuln.models.finding import CvssScore, CvssVersion

Probability = Annotated[float, Field(ge=0, le=1)]


class OutputModel(BaseModel):
    """Base of the output contract, which is strict."""

    model_config = ConfigDict(extra="forbid")


class KevSignal(OutputModel):
    """CISA KEV status; the details are absent when not in KEV."""

    in_kev: bool
    date_added: date | MISSING = MISSING
    due_date: date | MISSING = MISSING
    known_ransomware_campaign_use: bool | MISSING = MISSING


class EpssSignal(OutputModel):
    """FIRST EPSS score of a vulnerability."""

    probability: Probability
    percentile: Probability
    model_version: str
    score_date: date


class CvssValue(OutputModel):
    """CVSS value with its provenance."""

    version: CvssVersion
    base_score: CvssScore
    vector: str | None
    source: Literal["input", "vulnerability-lookup"]


class CvssSignal(OutputModel):
    """Every known CVSS value and the one selected by the policy."""

    values: list[CvssValue] = Field(min_length=1)
    selected: CvssValue


class Signals(OutputModel):
    """KEV, EPSS and CVSS signals of one vulnerability."""

    kev: KevSignal | MISSING = MISSING
    epss: EpssSignal | MISSING | None = MISSING
    cvss: CvssSignal | MISSING | None = MISSING
