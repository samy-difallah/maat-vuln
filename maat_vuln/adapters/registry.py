"""Adapter protocol, discovery through entry points and auto-detection."""

import importlib.metadata
import logging
from typing import Protocol

from pydantic import JsonValue

from maat_vuln.models import Finding

ENTRY_POINT_GROUP = "maat_vuln.adapters"

logger = logging.getLogger(__name__)


class Adapter(Protocol):
    """Turns a parsed JSON document of one input format into findings."""

    name: str

    def detect(self, document: JsonValue) -> bool:
        """Tell whether the document is in this adapter's format."""
        ...

    def parse(self, document: JsonValue) -> list[Finding]:
        """Read the findings of a document in this adapter's format."""
        ...


class FormatError(ValueError):
    """A document matches no input format, or several."""


def load_adapters() -> list[Adapter]:
    """Load every registered adapter, sorted by name."""
    # Called through its module so that tests can register fake adapters.
    entry_points = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
    return sorted(
        (entry_point.load() for entry_point in entry_points),
        key=lambda adapter: adapter.name,
    )


def load_findings(document: JsonValue) -> list[Finding]:
    """Detect the format of a parsed JSON document and read its findings.

    Raises:
        FormatError: no adapter, or several, recognize the document.
        ValidationError: the document is invalid for its format.
    """
    adapters = load_adapters()
    matches = [adapter for adapter in adapters if adapter.detect(document)]
    if not matches:
        supported = ", ".join(adapter.name for adapter in adapters)
        msg = f"unrecognized input format, supported: {supported}"
        raise FormatError(msg)
    if len(matches) > 1:
        names = ", ".join(adapter.name for adapter in matches)
        msg = f"ambiguous input format, matches: {names}"
        raise FormatError(msg)
    logger.info("Detected the %s format", matches[0].name)
    return matches[0].parse(document)
