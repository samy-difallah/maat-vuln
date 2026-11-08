"""Tests for the OSV-Scanner JSON input format."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from maat_vuln import load_findings
from maat_vuln.adapters import load_adapters
from maat_vuln.models import Component, Provenance

OSV_SCANNER = "osv-scanner"
FIXTURE = Path(__file__).parent / "fixtures" / "osv-scanner.json"
GOGO = Component(name="github.com/gogo/protobuf", version="1.3.1")
REQUESTS = Component(
    purl="pkg:pypi/requests@2.25.1", name="requests", version="2.25.1"
)


@pytest.fixture
def adapter():
    """The OSV-Scanner adapter, as registered."""
    return next(a for a in load_adapters() if a.name == OSV_SCANNER)


@pytest.fixture
def findings():
    """Findings read from the sample report through auto-detection."""
    return load_findings(json.loads(FIXTURE.read_text()))


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"results": [], "experimental_config": {}}, True),
        ({"Results": [], "SchemaVersion": 2}, False),
        ({"findings": []}, False),
        ([{"results": []}], False),
        (None, False),
    ],
)
def test_detect(adapter, document, expected):
    """Only a JSON object with a ``results`` key is recognized."""
    assert adapter.detect(document) is expected


def test_one_finding_per_record(findings):
    """Every OSV record of every package is read, CVE alias as pivot."""
    assert [(f.id, f.aliases, f.component) for f in findings] == [
        ("CVE-2021-3121", ["GHSA-C3H9-896R-86JM"], GOGO),
        ("CVE-2021-3121", ["GHSA-C3H9-896R-86JM", "GO-2021-0053"], GOGO),
        (
            "CVE-2023-32681",
            ["GHSA-J8R2-6X86-Q33Q", "PYSEC-2023-74"],
            REQUESTS,
        ),
    ]


def test_vectors_are_dropped(findings):
    """OSV severities are bare vectors, without base score."""
    assert all(f.cvss == [] for f in findings)


def test_provenance(findings):
    """Findings name OSV-Scanner and the reported ID, no release."""
    assert [f.sources for f in findings] == [
        [Provenance(tool=OSV_SCANNER, original_id=original_id)]
        for original_id in (
            "GHSA-c3h9-896r-86jm",
            "GO-2021-0053",
            "GHSA-j8r2-6x86-q33q",
        )
    ]


@pytest.mark.parametrize(
    ("record", "aliases"),
    [
        (
            {
                "id": "PYSEC-2023-175",
                "related": ["cve-2023-4863", "GHSA-J7HP-H8JX-5PPR"],
            },
            ["CVE-2023-4863"],
        ),
        (
            {"id": "UBUNTU-CVE-2023-1", "upstream": ["CVE-2023-1000"]},
            ["CVE-2023-1000"],
        ),
        (
            {
                "id": "GHSA-J7HP-H8JX-5PPR",
                "aliases": ["CVE-2023-4863"],
                "related": ["CVE-2023-5129"],
            },
            ["CVE-2023-4863"],
        ),
    ],
)
def test_related_cves(adapter, record, aliases):
    """Related and upstream CVEs are read only when no CVE is known."""
    [finding] = adapter.parse(
        {"results": [{"packages": [{"vulnerabilities": [record]}]}]}
    )
    assert [finding.id] == aliases


def test_git_source(adapter):
    """A git source's empty version is not kept."""
    [finding] = adapter.parse(
        {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "name": "https://github.com/madler/zlib",
                                "version": "",
                                "ecosystem": "",
                                "commit": "51b7f2abdade71cd9bb0e7a373",
                            },
                            "vulnerabilities": [{"id": "OSV-2022-301"}],
                        }
                    ]
                }
            ]
        }
    )
    assert finding.id == "OSV-2022-301"
    assert finding.component == Component(
        name="https://github.com/madler/zlib"
    )


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        (
            "pkg:golang/github.com/gin-gonic/gin@1.6.3",
            "pkg:golang/github.com/gin-gonic/gin@v1.6.3",
        ),
        (
            "pkg:golang/github.com/dgrijalva/jwt-go@3.2.0%2Bincompatible",
            "pkg:golang/github.com/dgrijalva/jwt-go@v3.2.0%2Bincompatible",
        ),
        (
            "pkg:golang/golang.org/x/net@v0.7.0",
            "pkg:golang/golang.org/x/net@v0.7.0",
        ),
        ("pkg:golang/golang.org/x/net", "pkg:golang/golang.org/x/net"),
        ("pkg:pypi/requests@2.25.1", "pkg:pypi/requests@2.25.1"),
    ],
)
def test_go_purl_version(adapter, purl, expected):
    """Go purl versions get the ``v`` other tools write; others do not."""
    [finding] = adapter.parse(
        {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"purl": purl},
                            "vulnerabilities": [{"id": "GO-2021-0053"}],
                        }
                    ]
                }
            ]
        }
    )
    assert finding.component.purl == expected


def test_clean_report(adapter):
    """A report without results (nothing found) gives no finding."""
    assert adapter.parse({"results": [], "experimental_config": {}}) == []


def test_vulnerability_without_id(adapter):
    """An OSV record without ID is an invalid document."""
    with pytest.raises(ValidationError, match=r"vulnerabilities\.0\.id"):
        adapter.parse({"results": [{"packages": [{"vulnerabilities": [{}]}]}]})
