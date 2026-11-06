"""Grype JSON input: the matches of a Grype report."""

from typing import get_args

from pydantic import BaseModel, Field, JsonValue

from maat_vuln.models import (
    Component,
    CvssInput,
    CvssVersion,
    Finding,
    Provenance,
)

MATCHES_KEY = "matches"
CVE_PREFIX = "CVE-"


class _Descriptor(BaseModel):
    """Grype release that wrote the report."""

    version: str | None = None


class _Metrics(BaseModel):
    """Scores of one CVSS value."""

    base_score: float = Field(alias="baseScore")


class _Cvss(BaseModel):
    """CVSS value given by one source."""

    version: str
    vector: str | None = None
    metrics: _Metrics

    def value(self) -> CvssInput | None:
        """The value as input, or None for a CVSS version Maat ignores."""
        if self.version not in get_args(CvssVersion):
            return None
        return CvssInput(
            version=self.version,
            base_score=self.metrics.base_score,
            vector=self.vector or None,
        )


class _Vulnerability(BaseModel):
    """Vulnerability record: the matched one or a related one."""

    id: str
    cvss: list[_Cvss] = []

    def is_cve(self) -> bool:
        """Whether the record is a CVE."""
        return self.id.upper().startswith(CVE_PREFIX)


class _Artifact(BaseModel):
    """Package the vulnerability was found in."""

    name: str | None = None
    version: str | None = None
    purl: str | None = None


class _Match(BaseModel):
    """Vulnerability matched against a package."""

    vulnerability: _Vulnerability
    related: list[_Vulnerability] = Field([], alias="relatedVulnerabilities")
    artifact: _Artifact = _Artifact()


class _Report(BaseModel):
    """The parts of a Grype report that findings are read from."""

    matches: list[_Match]
    descriptor: _Descriptor = _Descriptor()


def _cvss(records: list[_Vulnerability]) -> list[CvssInput]:
    """CVSS values of the records, each kept once, first seen first."""
    # Grype often repeats a value across the records of one CVE.
    return list(
        dict.fromkeys(
            value
            for record in records
            for cvss in record.cvss
            if (value := cvss.value()) is not None
        )
    )


class GrypeAdapter:
    """Reads the matches of a Grype JSON report."""

    name = "grype"

    def detect(self, document: JsonValue) -> bool:
        """Recognize a JSON object with a top-level ``matches`` key."""
        return isinstance(document, dict) and MATCHES_KEY in document

    def parse(self, document: JsonValue) -> list[Finding]:
        """Read one finding per match, or per CVE of a distro advisory.

        Raises:
            ValidationError: the report or one of its findings is invalid.
        """
        report = _Report.model_validate(document)
        tool_version = report.descriptor.version
        findings = []
        for match in report.matches:
            artifact = match.artifact
            # Grype writes an empty string for a missing purl, name...
            component = Component(
                purl=artifact.purl or None,
                name=artifact.name or None,
                version=artifact.version or None,
            )
            source = Provenance(
                tool=self.name,
                tool_version=tool_version,
                original_id=match.vulnerability.id,
            )
            cves: dict[str, list[_Vulnerability]] = {}
            for record in match.related:
                if record.is_cve():
                    cves.setdefault(record.id.upper(), []).append(record)
            if not match.vulnerability.is_cve() and len(cves) > 1:
                # An advisory covering several CVEs: each needs its own
                # pivot, or only the lowest one's signals would be read.
                findings.extend(
                    Finding(
                        id=cve,
                        component=component,
                        cvss=_cvss(records),
                        sources=[source],
                    )
                    for cve, records in cves.items()
                )
                continue
            findings.append(
                Finding(
                    id=match.vulnerability.id,
                    aliases=[record.id for record in match.related],
                    component=component,
                    cvss=_cvss([match.vulnerability, *match.related]),
                    sources=[source],
                )
            )
        return findings


ADAPTER = GrypeAdapter()
