"""Tests for the CycloneDX JSON input format."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from maat_vuln import load_findings
from maat_vuln.adapters import load_adapters
from maat_vuln.models import Component, CvssInput, Provenance

CYCLONEDX = "cyclonedx"
FIXTURE = Path(__file__).parent / "fixtures" / "cyclonedx.json"
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


@pytest.fixture
def adapter():
    """The CycloneDX adapter, as registered."""
    return next(a for a in load_adapters() if a.name == CYCLONEDX)


@pytest.fixture
def findings():
    """Findings read from the sample BOM through auto-detection."""
    return load_findings(json.loads(FIXTURE.read_text()))


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"bomFormat": "CycloneDX", "specVersion": "1.6"}, True),
        ({"bomFormat": "SPDX"}, False),
        ({"findings": []}, False),
        ([{"bomFormat": "CycloneDX"}], False),
        (None, False),
    ],
)
def test_detect(adapter, document, expected):
    """Only a JSON object with ``bomFormat: CycloneDX`` is recognized."""
    assert adapter.detect(document) is expected


def test_one_finding_per_affected_component(findings):
    """Each affected component, nested or unresolved, has its finding."""
    assert [(f.id, f.component) for f in findings] == [
        (
            "CVE-2021-44228",
            Component(purl=LOG4J, name="log4j-core", version="2.14.1"),
        ),
        ("CVE-2021-44228", Component(name="shaded-lib", version="0.9")),
        (
            "CVE-2021-44228",
            Component(
                bom_ref="urn:cdx:7b8e2f6a-1c3d-4e5f-8a9b-0c1d2e3f4a5b/1#lib"
            ),
        ),
        ("GHSA-XXXX-YYYY-ZZZZ", Component(name="demo-app", version="1.0.0")),
        ("CVE-2024-0001", None),
    ]


def test_references_become_aliases(findings):
    """Reference IDs are kept as aliases."""
    assert findings[0].aliases == ["GHSA-JFH8-C2JP-5V3Q"]


def test_cvss_ratings_only(findings):
    """Only CVSS ratings with a score are kept, severities are ignored."""
    assert findings[0].cvss == [
        CvssInput(
            version="3.1",
            base_score=10,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        ),
        CvssInput(
            version="2.0",
            base_score=9.3,
            vector="AV:N/AC:M/Au:N/C:C/I:C/A:C",
        ),
    ]
    assert findings[-1].cvss == []


def test_provenance(findings):
    """The vulnerability's own tools win over the BOM's metadata tools."""
    assert findings[0].sources == [
        Provenance(
            tool="trivy", tool_version="0.67.2", original_id="CVE-2021-44228"
        )
    ]
    assert findings[3].sources[0].tool == "scanner"
    assert findings[4].sources[0].original_id == "cve-2024-0001"


def test_no_tool_names_the_adapter(adapter):
    """A BOM naming no tool is credited to the adapter."""
    [finding] = adapter.parse(
        {
            "bomFormat": "CycloneDX",
            "vulnerabilities": [{"id": "CVE-2024-0001"}],
        }
    )
    assert finding.sources == [
        Provenance(tool=CYCLONEDX, original_id="CVE-2024-0001")
    ]


def test_bom_without_vulnerabilities(adapter):
    """A plain SBOM gives no finding."""
    assert adapter.parse({"bomFormat": "CycloneDX"}) == []


def test_vulnerability_without_id(adapter):
    """A vulnerability without ID is an invalid document."""
    with pytest.raises(ValidationError, match=r"vulnerabilities\.0\.id"):
        adapter.parse({"bomFormat": "CycloneDX", "vulnerabilities": [{}]})
