"""Tests for the native ``maat`` input format."""

import pytest
from pydantic import ValidationError

from maat_vuln.adapters import load_adapters

NATIVE = "maat"


@pytest.fixture
def adapter():
    """The native adapter, as registered."""
    return next(a for a in load_adapters() if a.name == NATIVE)


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"findings": []}, True),
        ({"schema_version": "0.2.0", "findings": []}, True),
        ({"matches": []}, False),
        ([{"findings": []}], False),
        ("findings", False),
        (None, False),
    ],
)
def test_detect(adapter, document, expected):
    """Only a JSON object with a ``findings`` key is recognized."""
    assert adapter.detect(document) is expected


def test_parse(adapter):
    """Findings are validated and normalized as in the input contract."""
    [finding] = adapter.parse(
        {
            "findings": [
                {
                    "id": "ghsa-xxxx-yyyy-zzzz",
                    "aliases": ["cve-2024-0001"],
                    "component": {"purl": "pkg:pypi/a@1"},
                }
            ]
        }
    )
    assert finding.id == "CVE-2024-0001"
    assert finding.aliases == ["GHSA-XXXX-YYYY-ZZZZ"]


def test_parse_rejects_other_major(adapter):
    """A document of another major contract version is refused."""
    with pytest.raises(ValidationError, match="unsupported schema_version"):
        adapter.parse({"schema_version": "1.0.0", "findings": []})
