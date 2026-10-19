"""Tests for the finding input models."""

import pytest
from pydantic import ValidationError

from maat_vuln.models import (
    Component,
    CvssInput,
    Finding,
    FindingKey,
    Provenance,
    merge_findings,
)


def test_ids_are_normalized():
    """IDs are stripped, uppercased, deduplicated and sorted."""
    finding = Finding(
        id=" cve-2024-0001 ",
        aliases=[
            "ghsa-xxxx-yyyy-zzzz",
            "GHSA-XXXX-YYYY-ZZZZ",
            "cve-2024-0001",
        ],
    )
    assert finding.id == "CVE-2024-0001"
    assert finding.aliases == ["GHSA-XXXX-YYYY-ZZZZ"]


def test_empty_id_is_rejected():
    """A blank ID is not a finding."""
    with pytest.raises(ValidationError):
        Finding(id="  ")


def test_unknown_fields_are_ignored():
    """Input is tolerant of fields outside the contract."""
    finding = Finding.model_validate({"id": "CVE-2024-0001", "severity": "x"})
    assert not hasattr(finding, "severity")


def test_cve_id_stays_pivot():
    """A CVE ID is kept even when other CVE aliases sort lower."""
    finding = Finding(id="CVE-2024-0002", aliases=["CVE-2020-0001"])
    assert finding.id == "CVE-2024-0002"
    assert finding.aliases == ["CVE-2020-0001"]


def test_lowest_cve_alias_becomes_pivot():
    """CVE aliases compare by year then number, not as strings."""
    finding = Finding(
        id="GHSA-xxxx-yyyy-zzzz",
        aliases=["CVE-2021-10000", "CVE-2021-9999"],
    )
    assert finding.id == "CVE-2021-9999"
    assert finding.aliases == ["CVE-2021-10000", "GHSA-XXXX-YYYY-ZZZZ"]


def test_id_without_cve_stays_pivot():
    """Findings without a CVE keep their own ID."""
    finding = Finding(id="GHSA-xxxx-yyyy-zzzz", aliases=["OSV-2024-1"])
    assert finding.id == "GHSA-XXXX-YYYY-ZZZZ"
    assert finding.aliases == ["OSV-2024-1"]


@pytest.mark.parametrize(
    ("component", "expected"),
    [
        (
            Component(purl="pkg:pypi/a@1", bom_ref="r", name="a"),
            "pkg:pypi/a@1",
        ),
        (Component(bom_ref="r", name="a", version="1"), "r"),
        (Component(name="a", version="1"), "a@1"),
        (Component(name="a"), "a"),
        (Component(version="1"), None),
        (None, None),
    ],
)
def test_key_component_fallbacks(component, expected):
    """The component key falls back from purl to name."""
    finding = Finding(id="CVE-2024-0001", component=component)
    assert finding.key == FindingKey(id="CVE-2024-0001", component=expected)


@pytest.mark.parametrize(
    "cvss",
    [
        {"version": "3.1", "base_score": 10.5},
        {"version": "3.1", "base_score": -1},
        {"version": "3.2", "base_score": 5.0},
        {"version": "3.1"},
    ],
)
def test_invalid_cvss_is_rejected(cvss):
    """Scores stay within 0-10, versions are known, base_score required."""
    with pytest.raises(ValidationError):
        CvssInput.model_validate(cvss)


def test_merge_unions_same_key():
    """Findings sharing a key merge aliases, CVSS values and sources."""
    cvss = CvssInput(version="3.1", base_score=9.8)
    trivy = Provenance(tool="trivy")
    first = Finding(
        id="GHSA-xxxx-yyyy-zzzz",
        aliases=["CVE-2024-0001"],
        cvss=[cvss],
        sources=[trivy],
    )
    second = Finding(
        id="CVE-2024-0001",
        aliases=["OSV-2024-1"],
        cvss=[cvss, CvssInput(version="4.0", base_score=9.3)],
        sources=[trivy, Provenance(tool="grype")],
    )
    [merged] = merge_findings([first, second])
    assert merged.id == "CVE-2024-0001"
    assert merged.aliases == ["GHSA-XXXX-YYYY-ZZZZ", "OSV-2024-1"]
    assert [c.version for c in merged.cvss] == ["3.1", "4.0"]
    assert [s.tool for s in merged.sources] == ["trivy", "grype"]


def test_merge_keeps_distinct_keys_in_order():
    """Different components or IDs stay separate, in first-seen order."""
    findings = [
        Finding(id="CVE-2024-0002"),
        Finding(id="CVE-2024-0001", component=Component(name="a")),
        Finding(id="CVE-2024-0001", component=Component(name="b")),
        Finding(id="cve-2024-0002"),
    ]
    merged = merge_findings(findings)
    assert [f.key for f in merged] == [
        FindingKey(id="CVE-2024-0002", component=None),
        FindingKey(id="CVE-2024-0001", component="a"),
        FindingKey(id="CVE-2024-0001", component="b"),
    ]
