"""Trivy JSON input: the vulnerabilities of a Trivy report."""

from pydantic import BaseModel, Field, JsonValue

from maat_vuln.models import Component, CvssInput, Finding, Provenance

SCHEMA_VERSION_KEY = "SchemaVersion"
CVSS_31_PREFIX = "CVSS:3.1/"


class _TrivyInfo(BaseModel):
    """Trivy release that wrote the report."""

    version: str | None = Field(None, alias="Version")


class _PkgIdentifier(BaseModel):
    """Identifiers of the vulnerable package."""

    purl: str | None = Field(None, alias="PURL")


class _Cvss(BaseModel):
    """CVSS values given by one source, at most one per CVSS version."""

    v2_vector: str | None = Field(None, alias="V2Vector")
    v2_score: float | None = Field(None, alias="V2Score")
    v3_vector: str | None = Field(None, alias="V3Vector")
    v3_score: float | None = Field(None, alias="V3Score")
    v40_vector: str | None = Field(None, alias="V40Vector")
    v40_score: float | None = Field(None, alias="V40Score")

    def values(self) -> list[CvssInput]:
        """The values that have a base score, newest version first."""
        # The V3 fields hold 3.0 and 3.1 alike, only the vector tells
        # them apart; a score without vector is taken as 3.0.
        v3 = (self.v3_vector or "").startswith(CVSS_31_PREFIX)
        return [
            CvssInput(version=version, base_score=score, vector=vector)
            for version, score, vector in (
                ("4.0", self.v40_score, self.v40_vector),
                ("3.1" if v3 else "3.0", self.v3_score, self.v3_vector),
                ("2.0", self.v2_score, self.v2_vector),
            )
            if score is not None
        ]


class _Vulnerability(BaseModel):
    """Vulnerability detected in a package of a scan target."""

    # Optional in Trivy's schema, but a finding cannot exist without it.
    id: str = Field(alias="VulnerabilityID")
    pkg_name: str | None = Field(None, alias="PkgName")
    installed_version: str | None = Field(None, alias="InstalledVersion")
    pkg_identifier: _PkgIdentifier = Field(
        _PkgIdentifier(), alias="PkgIdentifier"
    )
    cvss: dict[str, _Cvss] = Field({}, alias="CVSS")


class _Result(BaseModel):
    """Scan result of one target: OS packages, a lock file, a binary..."""

    vulnerabilities: list[_Vulnerability] = Field([], alias="Vulnerabilities")


class _Report(BaseModel):
    """The parts of a Trivy report that findings are read from."""

    trivy: _TrivyInfo = Field(_TrivyInfo(), alias="Trivy")
    results: list[_Result] = Field([], alias="Results")


class TrivyAdapter:
    """Reads the vulnerabilities of a Trivy JSON report."""

    name = "trivy"

    def detect(self, document: JsonValue) -> bool:
        """Recognize a JSON object with a top-level ``SchemaVersion`` key."""
        return isinstance(document, dict) and SCHEMA_VERSION_KEY in document

    def parse(self, document: JsonValue) -> list[Finding]:
        """Read one finding per vulnerability of each scan result.

        Vendor advisory IDs (``VendorIDs``) are not kept as aliases: an
        advisory often covers several vulnerabilities.

        Raises:
            ValidationError: the report or one of its findings is invalid.
        """
        report = _Report.model_validate(document)
        return [
            Finding(
                id=vuln.id,
                component=Component(
                    purl=vuln.pkg_identifier.purl,
                    name=vuln.pkg_name,
                    version=vuln.installed_version,
                ),
                # Several sources often give the very same value.
                cvss=list(
                    dict.fromkeys(
                        value
                        for cvss in vuln.cvss.values()
                        for value in cvss.values()
                    )
                ),
                sources=[
                    Provenance(
                        tool=self.name,
                        tool_version=report.trivy.version,
                        original_id=vuln.id,
                    )
                ],
            )
            for result in report.results
            for vuln in result.vulnerabilities
        ]


ADAPTER = TrivyAdapter()
