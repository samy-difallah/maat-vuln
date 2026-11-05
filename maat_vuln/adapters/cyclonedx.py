"""CycloneDX JSON input: the vulnerabilities of a BOM, VDR included."""

from pydantic import BaseModel, Field, JsonValue

from maat_vuln.models import (
    Component,
    CvssInput,
    CvssVersion,
    Finding,
    Provenance,
)

BOM_FORMAT = "CycloneDX"
# The CVSS methods of the spec's ``scoreMethod``; OWASP, SSVC and other
# ratings are no CVSS and are ignored.
CVSS_METHODS: dict[str, CvssVersion] = {
    "CVSSv2": "2.0",
    "CVSSv3": "3.0",
    "CVSSv31": "3.1",
    "CVSSv4": "4.0",
}


class _Tool(BaseModel):
    """Tool of the legacy array form, or tool component or service."""

    name: str | None = None
    version: str | None = None


class _Tools(BaseModel):
    """Tools in the object form of CycloneDX 1.5 and later."""

    components: list[_Tool] = []
    services: list[_Tool] = []


_ToolList = list[_Tool] | _Tools | None


class _Component(BaseModel):
    """Component of the BOM, with its nested components."""

    bom_ref: str | None = Field(None, alias="bom-ref")
    purl: str | None = None
    name: str | None = None
    version: str | None = None
    components: list["_Component"] = []


class _Reference(BaseModel):
    """Same vulnerability under another ID."""

    id: str


class _Rating(BaseModel):
    """Score given to a vulnerability by some method."""

    method: str | None = None
    score: float | None = None
    vector: str | None = None


class _Affects(BaseModel):
    """Reference to a component affected by a vulnerability."""

    ref: str


class _Vulnerability(BaseModel):
    """Vulnerability entry of the BOM."""

    # Optional in the spec, but a finding cannot exist without it.
    id: str
    references: list[_Reference] = []
    ratings: list[_Rating] = []
    affects: list[_Affects] = []
    tools: _ToolList = None


class _Metadata(BaseModel):
    """BOM metadata: the tools that made it and its subject component."""

    tools: _ToolList = None
    component: _Component | None = None


class _Bom(BaseModel):
    """The parts of a CycloneDX BOM that findings are read from."""

    metadata: _Metadata = _Metadata()
    components: list[_Component] = []
    vulnerabilities: list[_Vulnerability] = []


def _first_tool(tools: _ToolList) -> _Tool | None:
    """The first tool listed, whatever the form of the list."""
    if isinstance(tools, _Tools):
        tools = [*tools.components, *tools.services]
    return tools[0] if tools else None


def _index(components: list[_Component]) -> dict[str, Component]:
    """Map the bom-ref of every component, nested ones included."""
    index: dict[str, Component] = {}
    for component in components:
        if component.bom_ref is not None:
            # bom-refs only mean something inside the document, so the
            # finding keeps the purl, or the name and version, instead.
            index[component.bom_ref] = Component(
                purl=component.purl,
                name=component.name,
                version=component.version,
            )
        index |= _index(component.components)
    return index


class CycloneDxAdapter:
    """Reads the vulnerabilities of a CycloneDX JSON BOM."""

    name = "cyclonedx"

    def detect(self, document: JsonValue) -> bool:
        """Recognize a JSON object whose ``bomFormat`` is CycloneDX."""
        return (
            isinstance(document, dict)
            and document.get("bomFormat") == BOM_FORMAT
        )

    def parse(self, document: JsonValue) -> list[Finding]:
        """Read one finding per vulnerability and affected component.

        A vulnerability affecting no component gives one finding without
        component; a reference to no component of the BOM keeps the
        bom-ref as the component.

        Raises:
            ValidationError: the BOM or one of its findings is invalid.
        """
        bom = _Bom.model_validate(document)
        subject = [bom.metadata.component] if bom.metadata.component else []
        components = _index([*subject, *bom.components])
        findings = []
        for vuln in bom.vulnerabilities:
            tool = _first_tool(vuln.tools) or _first_tool(bom.metadata.tools)
            source = Provenance(
                tool=tool.name if tool and tool.name else self.name,
                tool_version=tool.version if tool else None,
                original_id=vuln.id,
            )
            cvss = [
                CvssInput(
                    version=CVSS_METHODS[rating.method],
                    base_score=rating.score,
                    vector=rating.vector,
                )
                for rating in vuln.ratings
                if rating.method in CVSS_METHODS and rating.score is not None
            ]
            refs = [affects.ref for affects in vuln.affects] or [None]
            findings += [
                Finding(
                    id=vuln.id,
                    aliases=[reference.id for reference in vuln.references],
                    component=(
                        components.get(ref, Component(bom_ref=ref))
                        if ref is not None
                        else None
                    ),
                    cvss=cvss,
                    sources=[source],
                )
                for ref in refs
            ]
        return findings


ADAPTER = CycloneDxAdapter()
