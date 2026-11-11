"""Pieces shared by the commands: options, error handling and display."""

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.text import Text

from maat_vuln.adapters import FormatError
from maat_vuln.engine import fetch_snapshot
from maat_vuln.feeds import FetchError
from maat_vuln.models import PRIORITIES, Priority
from maat_vuln.snapshot import (
    Snapshot,
    SnapshotError,
    default_root,
    latest_snapshot,
    load_snapshot,
)

EXIT_ERROR = 1
VALUE_ERROR_PREFIX = "Value error, "
DISPLAY_TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"
GREY = "bright_black"
PRIORITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}
UNSCORED = "unscored"
logger = logging.getLogger(__name__)


class OutputFormat(StrEnum):
    """Output format of a command."""

    TABLE = "table"
    JSON = "json"


def _message(error: Exception) -> str:
    """Word an error in one line, validation errors as ``field: reason``."""
    if isinstance(error, json.JSONDecodeError):
        return f"invalid JSON input: {error}"
    if not isinstance(error, ValidationError):
        return str(error)
    # Pydantic's own text spans lines, with its error types and doc URLs.
    return "; ".join(
        ": ".join(
            part
            for part in (
                ".".join(str(loc) for loc in details["loc"]),
                details["msg"].removeprefix(VALUE_ERROR_PREFIX),
            )
            if part
        )
        for details in error.errors(include_url=False)
    )


@contextmanager
def fail_cleanly(quiet: bool = False) -> Iterator[None]:
    """Turn expected errors into a message on stderr and exit code 1.

    Args:
        quiet: Exit with code 1 without any message.
    """
    try:
        yield
    except (
        ValidationError,
        SnapshotError,
        FetchError,
        FormatError,
        json.JSONDecodeError,
    ) as error:
        if not quiet:
            typer.echo(f"Error: {_message(error)}", err=True)
        raise typer.Exit(EXIT_ERROR) from error


def resolve_snapshot(snapshot_id: str | None, refresh: bool) -> Snapshot:
    """Load the requested snapshot, else the latest, else fetch one.

    Raises:
        typer.BadParameter: both a snapshot ID and refresh are given.
        SnapshotError: the snapshot is unknown or inconsistent.
        FetchError: a feed could not be fetched.
    """
    if snapshot_id is not None and refresh:
        raise typer.BadParameter(
            "cannot be combined with --snapshot", param_hint="'--refresh'"
        )
    if snapshot_id is not None:
        logger.info("Loading snapshot %s, given by --snapshot", snapshot_id)
        return load_snapshot(snapshot_id)
    if refresh:
        logger.info("Fetching a new snapshot, as --refresh asks")
        return fetch_snapshot()
    logger.info("Looking for the latest snapshot in %s", default_root())
    if (snapshot := latest_snapshot()) is not None:
        logger.info(
            "Using the latest snapshot %s, created %s",
            snapshot.manifest.snapshot_id,
            timestamp(snapshot.manifest.created_at),
        )
        return snapshot
    logger.info("No snapshot in the cache: fetching a new one")
    return fetch_snapshot()


def priority_label(priority: Priority | None) -> str:
    """Name a priority with its P1-P4 indicator, e.g. ``CRITICAL (P1)``."""
    if priority is None:
        return UNSCORED
    return f"{priority} (P{PRIORITIES.index(priority) + 1})"


def timestamp(moment: datetime) -> str:
    """Format a moment as RFC 3339 UTC to the second, for display."""
    return f"{moment.astimezone(UTC):{DISPLAY_TIMESTAMP}}"


def print_fields(
    console: Console,
    fields: list[tuple[str, Text]],
    indent: str = "",
    width: int | None = None,
) -> None:
    """Print aligned label/value lines, one field per line.

    ``width`` sets the label column, to align several blocks of fields;
    by default it fits the longest label.
    """
    width = width or max(len(label) for label, _ in fields) + 2
    for label, value in fields:
        # Soft wrap: Rich never breaks a long URL, path or hash, so the
        # terminal wraps it on screen and it still copies in one piece.
        console.print(
            Text(indent) + Text(label.ljust(width), "bold") + value,
            soft_wrap=True,
        )
