"""Tests for the native JSON input document."""

import pytest
from pydantic import ValidationError

from maat_vuln.models import SCHEMA_VERSION, FindingsInput


@pytest.mark.parametrize("version", [None, SCHEMA_VERSION, "0.9.3"])
def test_compatible_versions_are_accepted(version):
    """A missing version or the same major is accepted."""
    document = FindingsInput(schema_version=version, findings=[])
    assert document.schema_version == version


@pytest.mark.parametrize("version", ["1.0.0", "0.1", "latest"])
def test_incompatible_versions_are_rejected(version):
    """Another major or a malformed version is rejected."""
    with pytest.raises(ValidationError):
        FindingsInput(schema_version=version, findings=[])


def test_json_document_is_parsed():
    """Findings are read and normalized from JSON."""
    document = FindingsInput.model_validate_json(
        '{"schema_version": "0.1.0", "findings": ['
        '{"id": "ghsa-xxxx-yyyy-zzzz", "aliases": ["cve-2024-0001"],'
        ' "component": {"purl": "pkg:pypi/a@1"},'
        ' "cvss": [{"version": "3.1", "base_score": 7.5}],'
        ' "sources": [{"tool": "trivy", "original_id": "GHSA-xxxx"}]}'
        "]}"
    )
    [finding] = document.findings
    assert finding.id == "CVE-2024-0001"
    assert finding.key.component == "pkg:pypi/a@1"
    assert finding.sources[0].original_id == "GHSA-xxxx"
