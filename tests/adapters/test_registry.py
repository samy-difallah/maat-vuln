"""Tests for adapter discovery and format auto-detection."""

import importlib.metadata
from types import SimpleNamespace

import pytest

from maat_vuln import load_findings
from maat_vuln.adapters import ENTRY_POINT_GROUP, FormatError, load_adapters


class FakeAdapter:
    """Adapter recognizing every document, returning no finding."""

    def __init__(self, name):
        """Name the fake format."""
        self.name = name

    def detect(self, document):
        """Recognize anything."""
        return True

    def parse(self, document):
        """Find nothing."""
        return []


@pytest.fixture
def fake_registry(monkeypatch):
    """Replace the installed adapters with two catch-all fakes."""
    fakes = [FakeAdapter("zeta"), FakeAdapter("alpha")]

    def entry_points(group):
        assert group == ENTRY_POINT_GROUP
        return [SimpleNamespace(load=lambda a=a: a) for a in fakes]

    monkeypatch.setattr(importlib.metadata, "entry_points", entry_points)


def test_native_adapter_is_registered():
    """The package registers its native adapter through an entry point."""
    assert "maat" in [adapter.name for adapter in load_adapters()]


def test_adapters_are_sorted_by_name(fake_registry):
    """Adapters load in name order, whatever the entry point order."""
    assert [a.name for a in load_adapters()] == ["alpha", "zeta"]


def test_load_findings_native():
    """A native document is detected and parsed."""
    [finding] = load_findings({"findings": [{"id": "cve-2024-0001"}]})
    assert finding.id == "CVE-2024-0001"


def test_unrecognized_format():
    """A document no adapter recognizes names the supported formats."""
    with pytest.raises(FormatError, match="supported: cyclonedx, maat, trivy"):
        load_findings({"matches": []})


def test_ambiguous_format(fake_registry):
    """A document several adapters recognize names all of them."""
    with pytest.raises(FormatError, match="matches: alpha, zeta"):
        load_findings({})
