"""Finding input contract: normalization, CVE pivot, finding key, merge."""

import re
from collections.abc import Iterable
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

VulnId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, to_upper=True, min_length=1),
]

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

CvssVersion = Literal["4.0", "3.1", "3.0", "2.0"]
CvssScore = Annotated[float, Field(ge=0, le=10)]


class Component(BaseModel):
    """Software component a vulnerability was found in."""

    purl: str | None = None
    bom_ref: str | None = None
    name: str | None = None
    version: str | None = None

    @property
    def key(self) -> str | None:
        """Identify the component: purl, bom-ref, name@version, then name."""
        if self.purl or self.bom_ref:
            return self.purl or self.bom_ref
        if self.name and self.version:
            return f"{self.name}@{self.version}"
        return self.name or None


class CvssInput(BaseModel):
    """CVSS value supplied by the input."""

    model_config = ConfigDict(frozen=True)

    version: CvssVersion
    base_score: CvssScore
    vector: str | None = None


class Provenance(BaseModel):
    """Tool that reported a finding."""

    model_config = ConfigDict(frozen=True)

    tool: str | None = None
    tool_version: str | None = None
    original_id: str | None = None


class FindingKey(BaseModel):
    """Identity of a finding: pivot ID and component key."""

    model_config = ConfigDict(frozen=True)

    id: str
    component: str | None


def _cve_order(vuln_id: str) -> tuple[int, int]:
    """Sort key of a CVE ID by year then number, not lexically."""
    _, year, number = vuln_id.split("-")
    return int(year), int(number)


class Finding(BaseModel):
    """Vulnerability reported on a component, as given in the input.

    After validation, ``id`` is the pivot ID (a CVE whenever one is known)
    and ``aliases`` holds every other ID, sorted and deduplicated.
    """

    id: VulnId
    aliases: list[VulnId] = []
    component: Component | None = None
    cvss: list[CvssInput] = []
    sources: list[Provenance] = []

    def model_post_init(self, context: object, /) -> None:
        """Make the CVE pivot the ID and move the other IDs to aliases."""
        ids = {self.id, *self.aliases}
        cves = [i for i in ids if CVE_PATTERN.fullmatch(i)]
        if not CVE_PATTERN.fullmatch(self.id) and cves:
            self.id = min(cves, key=_cve_order)
        self.aliases = sorted(ids - {self.id})

    @property
    def key(self) -> FindingKey:
        """Key that identifies, and merges, findings."""
        return FindingKey(
            id=self.id,
            component=self.component.key if self.component else None,
        )

    def merged_with(self, other: Self) -> Self:
        """Union this finding with another one of the same key."""
        return self.model_copy(
            update={
                "aliases": sorted({*self.aliases, *other.aliases}),
                "cvss": list(dict.fromkeys([*self.cvss, *other.cvss])),
                "sources": list(
                    dict.fromkeys([*self.sources, *other.sources])
                ),
            }
        )


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Merge findings that share a key, in first-seen order.

    Aliases, CVSS values and sources are unioned; the first finding's
    component is kept.
    """
    merged: dict[FindingKey, Finding] = {}
    for finding in findings:
        key = finding.key
        merged[key] = (
            merged[key].merged_with(finding) if key in merged else finding
        )
    return list(merged.values())
