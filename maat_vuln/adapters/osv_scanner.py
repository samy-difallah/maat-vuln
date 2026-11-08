"""OSV-Scanner JSON input: the vulnerabilities of an OSV-Scanner report."""

from pydantic import BaseModel, JsonValue

from maat_vuln.models import Component, Finding, Provenance

RESULTS_KEY = "results"
GO_PURL_PREFIX = "pkg:golang/"
GO_VERSION_PREFIX = "v"


def _purl(purl: str | None) -> str | None:
    """Put back the ``v`` that OSV strips from Go module versions.

    Go versions start with ``v`` (``v1.6.3``), as other tools write them
    in purls; without it, the same component would not merge across
    tools.
    """
    if not purl or not purl.startswith(GO_PURL_PREFIX) or "@" not in purl:
        return purl or None
    name, _, version = purl.rpartition("@")
    if version.startswith(GO_VERSION_PREFIX):
        return purl
    return f"{name}@{GO_VERSION_PREFIX}{version}"


class _Vulnerability(BaseModel):
    """OSV record of a vulnerability affecting a package."""

    id: str
    aliases: list[str] = []


class _Package(BaseModel):
    """Package found in a scanned source."""

    name: str | None = None
    version: str | None = None
    purl: str | None = None


class _PackageVulns(BaseModel):
    """Package and the vulnerabilities affecting it."""

    package: _Package = _Package()
    vulnerabilities: list[_Vulnerability] = []


class _Result(BaseModel):
    """Scan result of one source: a lock file, an SBOM, an image..."""

    packages: list[_PackageVulns] = []


class _Report(BaseModel):
    """The parts of an OSV-Scanner report that findings are read from."""

    results: list[_Result]


class OsvScannerAdapter:
    """Reads the vulnerabilities of an OSV-Scanner JSON report."""

    name = "osv-scanner"

    def detect(self, document: JsonValue) -> bool:
        """Recognize a JSON object with a top-level ``results`` key."""
        return isinstance(document, dict) and RESULTS_KEY in document

    def parse(self, document: JsonValue) -> list[Finding]:
        """Read one finding per OSV record of each package.

        OSV records give CVSS as bare vectors, without base score, so no
        CVSS is read. The report records no OSV-Scanner release.

        Raises:
            ValidationError: the report or one of its findings is invalid.
        """
        report = _Report.model_validate(document)
        return [
            Finding(
                id=vuln.id,
                aliases=vuln.aliases,
                # A git source reports a commit and an empty version.
                component=Component(
                    purl=_purl(entry.package.purl),
                    name=entry.package.name or None,
                    version=entry.package.version or None,
                ),
                sources=[Provenance(tool=self.name, original_id=vuln.id)],
            )
            for result in report.results
            for entry in result.packages
            for vuln in entry.vulnerabilities
        ]


ADAPTER = OsvScannerAdapter()
