"""Tests for the Trivy JSON input format."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from maat_vuln import load_findings
from maat_vuln.adapters import load_adapters
from maat_vuln.models import Component, CvssInput, Provenance

TRIVY = "trivy"
FIXTURE = Path(__file__).with_name("trivy.json")
LIBSSL = (
    "pkg:deb/debian/libssl3@3.0.13-1~deb12u1?arch=amd64&distro=debian-12.7"
)


@pytest.fixture
def adapter():
    """The Trivy adapter, as registered."""
    return next(a for a in load_adapters() if a.name == TRIVY)


@pytest.fixture
def findings():
    """Findings read from the sample report through auto-detection."""
    return load_findings(json.loads(FIXTURE.read_text()))


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"SchemaVersion": 2, "ArtifactName": "alpine"}, True),
        ({"bomFormat": "CycloneDX"}, False),
        ({"findings": []}, False),
        ([{"SchemaVersion": 2}], False),
        (None, False),
    ],
)
def test_detect(adapter, document, expected):
    """Only a JSON object with a ``SchemaVersion`` key is recognized."""
    assert adapter.detect(document) is expected


def test_one_finding_per_vulnerability(findings):
    """Every result's vulnerabilities are read, with their package."""
    assert [(f.id, f.component) for f in findings] == [
        (
            "CVE-2024-6119",
            Component(purl=LIBSSL, name="libssl3", version="3.0.13-1~deb12u1"),
        ),
        ("CVE-2011-3374", Component(name="apt", version="2.6.1")),
        (
            "GHSA-WF5P-G6VW-RHXX",
            Component(
                purl="pkg:npm/axios@0.21.1", name="axios", version="0.21.1"
            ),
        ),
    ]


def test_vendor_ids_are_not_aliases(findings):
    """Vendor advisories cover several vulnerabilities, so are dropped."""
    assert findings[0].aliases == []


def test_cvss(findings):
    """Scored values of every source are kept once, severities ignored."""
    assert findings[0].cvss == [
        CvssInput(
            version="3.1",
            base_score=7.5,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        )
    ]
    assert findings[1].cvss == [
        CvssInput(
            version="4.0",
            base_score=2.3,
            vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N"
            "/SC:N/SI:N/SA:N",
        ),
        CvssInput(
            version="3.0",
            base_score=3.7,
            vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        ),
        CvssInput(
            version="2.0",
            base_score=4.3,
            vector="AV:N/AC:M/Au:N/C:N/I:P/A:N",
        ),
    ]
    assert findings[2].cvss == []


def test_v3_score_without_vector_is_3_0(adapter):
    """Without a vector, a V3 score cannot claim 3.1."""
    [finding] = adapter.parse(
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "CVSS": {"nvd": {"V3Score": 5.3}},
                        }
                    ]
                }
            ],
        }
    )
    assert finding.cvss == [CvssInput(version="3.0", base_score=5.3)]


def test_provenance(findings):
    """Findings name Trivy, its release and the reported ID."""
    assert findings[1].sources == [
        Provenance(
            tool=TRIVY, tool_version="0.67.2", original_id="cve-2011-3374"
        )
    ]


def test_clean_report(adapter):
    """A report without ``Results`` (nothing found) gives no finding."""
    assert adapter.parse({"SchemaVersion": 2}) == []


def test_vulnerability_without_id(adapter):
    """A vulnerability without ID is an invalid document."""
    with pytest.raises(
        ValidationError, match=r"Vulnerabilities\.0\.VulnerabilityID"
    ):
        adapter.parse(
            {"SchemaVersion": 2, "Results": [{"Vulnerabilities": [{}]}]}
        )
