"""Tests for the Grype JSON input format."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from maat_vuln import load_findings
from maat_vuln.adapters import load_adapters
from maat_vuln.models import Component, CvssInput, Provenance

GRYPE = "grype"
FIXTURE = Path(__file__).parent / "fixtures" / "grype.json"
LIBSSL = "pkg:deb/debian/libssl3@3.0.13-1~deb12u1?arch=amd64&distro=debian-12"
CURL = Component(name="curl-minimal", version="8.5.0-1.amzn2023.0.2")
AXIOS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"


@pytest.fixture
def adapter():
    """The Grype adapter, as registered."""
    return next(a for a in load_adapters() if a.name == GRYPE)


@pytest.fixture
def findings():
    """Findings read from the sample report through auto-detection."""
    return load_findings(json.loads(FIXTURE.read_text()))


def _match(vuln_id, related=(), cvss=()):
    """A minimal Grype report with one match."""
    return {
        "matches": [
            {
                "vulnerability": {"id": vuln_id, "cvss": list(cvss)},
                "relatedVulnerabilities": [{"id": i} for i in related],
                "artifact": {"name": "pkg", "version": "1.0", "purl": ""},
            }
        ]
    }


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"matches": [], "descriptor": {"name": "grype"}}, True),
        ({"SchemaVersion": 2}, False),
        ({"findings": []}, False),
        ([{"matches": []}], False),
        (None, False),
    ],
)
def test_detect(adapter, document, expected):
    """Only a JSON object with a ``matches`` key is recognized."""
    assert adapter.detect(document) is expected


def test_findings(findings):
    """One finding per match, one per CVE of a multi-CVE advisory."""
    assert [(f.id, f.aliases, f.component) for f in findings] == [
        (
            "CVE-2024-6119",
            [],
            Component(purl=LIBSSL, name="libssl3", version="3.0.13-1~deb12u1"),
        ),
        (
            "CVE-2023-45857",
            ["GHSA-WF5P-G6VW-RHXX"],
            Component(
                purl="pkg:npm/axios@0.21.1", name="axios", version="0.21.1"
            ),
        ),
        ("CVE-2024-2398", [], CURL),
        ("CVE-2024-2004", [], CURL),
    ]


def test_cvss(findings):
    """Values of the match and its related records are kept once each."""
    assert [f.cvss for f in findings] == [
        [
            CvssInput(
                version="3.1",
                base_score=7.5,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            )
        ],
        [CvssInput(version="3.1", base_score=6.5, vector=AXIOS_VECTOR)],
        [
            CvssInput(
                version="3.1",
                base_score=7.5,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            )
        ],
        [
            CvssInput(
                version="3.1",
                base_score=3.5,
                vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
            ),
            CvssInput(
                version="2.0",
                base_score=4.3,
                vector="AV:N/AC:M/Au:N/C:N/I:P/A:N",
            ),
        ],
    ]


def test_provenance(findings):
    """Findings name Grype, its release and the reported ID."""
    assert [f.sources for f in findings[1:3]] == [
        [
            Provenance(
                tool=GRYPE,
                tool_version="0.121.2",
                original_id="GHSA-wf5p-g6vw-rhxx",
            )
        ],
        [
            Provenance(
                tool=GRYPE,
                tool_version="0.121.2",
                original_id="ALAS2023-2024-571",
            )
        ],
    ]


def test_advisory_with_one_cve_is_not_split(adapter):
    """With a single related CVE, related IDs are aliases as usual."""
    [finding] = adapter.parse(
        _match("ALAS-2024-001", ["CVE-2024-0001", "GHSA-AAAA-BBBB-CCCC"])
    )
    assert (finding.id, finding.aliases) == (
        "CVE-2024-0001",
        ["ALAS-2024-001", "GHSA-AAAA-BBBB-CCCC"],
    )


def test_cve_match_is_not_split(adapter):
    """A CVE match keeps its own ID, even with several related CVEs."""
    [finding] = adapter.parse(
        _match("CVE-2024-0001", ["CVE-2024-0002", "CVE-2024-0003"])
    )
    assert finding.id == "CVE-2024-0001"
    assert finding.aliases == ["CVE-2024-0002", "CVE-2024-0003"]


def test_unknown_cvss_version_is_dropped(adapter):
    """A CVSS version Maat does not model is ignored, not an error."""
    cvss = {"version": "5.0", "vector": "", "metrics": {"baseScore": 5.0}}
    [finding] = adapter.parse(_match("CVE-2024-0001", cvss=[cvss]))
    assert finding.cvss == []


def test_clean_report(adapter):
    """A report without match gives no finding."""
    assert adapter.parse({"matches": []}) == []


def test_match_without_id(adapter):
    """A match without vulnerability ID is an invalid document."""
    with pytest.raises(ValidationError, match=r"matches\.0\.vulnerability"):
        adapter.parse({"matches": [{"vulnerability": {}}]})
