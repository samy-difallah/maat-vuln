"""Finding input contract: normalization, CVE pivot, finding key, merge."""

import re
from collections.abc import Iterable
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
)

CVE_PREFIX = "CVE-"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


def _check_cve(vuln_id: str) -> str:
    """Reject an ID that claims to be a CVE but is not well-formed.

    Raises:
        ValueError: the ID starts with ``CVE-`` but is no CVE ID.
    """
    # A typo or a file name would otherwise pass as a non-CVE ID and
    # come out unscored, as if the feeds had nothing on it.
    if vuln_id.startswith(CVE_PREFIX) and not CVE_PATTERN.fullmatch(vuln_id):
        msg = f"malformed CVE ID {vuln_id}, expected CVE-YYYY-NNNN"
        raise ValueError(msg)
    return vuln_id


VulnId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, to_upper=True, min_length=1),
    AfterValidator(_check_cve),
]

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


class Finding(BaseModel):
    """Vulnerability reported on a component, as given in the input.

    After validation, ``id`` is the pivot ID (the CVE when exactly one is
    known) and ``aliases`` holds every other ID, sorted and deduplicated.
    """

    id: VulnId
    aliases: list[VulnId] = []
    component: Component | None = None
    cvss: list[CvssInput] = []
    sources: list[Provenance] = []

    def model_post_init(self, context: object, /) -> None:
        """Make the CVE pivot the ID and move the other IDs to aliases.

        A non-CVE ID with several CVE aliases stays the ID, until
        :meth:`per_cve` splits the finding.
        """
        ids = {self.id, *self.aliases}
        cves = [i for i in ids if CVE_PATTERN.fullmatch(i)]
        if not CVE_PATTERN.fullmatch(self.id) and len(cves) == 1:
            self.id = cves[0]
        self.aliases = sorted(ids - {self.id})

    def per_cve(self) -> list[Self]:
        """Split an advisory covering several CVEs into one finding each.

        Each CVE gets its own KEV and EPSS signals instead of hiding
        behind one pivot. CVSS values are dropped: nothing tells which
        CVE they score, so each CVE's own are looked up.
        """
        cves = [a for a in self.aliases if CVE_PATTERN.fullmatch(a)]
        # A lone CVE alias is already the pivot: CVE aliases here are two
        # or more.
        if CVE_PATTERN.fullmatch(self.id) or not cves:
            return [self]
        others = sorted({self.id, *self.aliases} - set(cves))
        return [
            self.model_copy(update={"id": cve, "aliases": others, "cvss": []})
            for cve in cves
        ]

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
    """Split advisories per CVE, then merge findings that share a key.

    Merged findings keep their first-seen order: aliases, CVSS values
    and sources are unioned; the first finding's component is kept.
    """
    merged: dict[FindingKey, Finding] = {}
    for finding in (part for f in findings for part in f.per_cve()):
        key = finding.key
        merged[key] = (
            merged[key].merged_with(finding) if key in merged else finding
        )
    return list(merged.values())
