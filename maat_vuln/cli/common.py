"""Pieces shared by the commands: options, error handling and display."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.text import Text

from maat_vuln.engine import fetch_snapshot
from maat_vuln.feeds import FetchError
from maat_vuln.snapshot import (
    Snapshot,
    SnapshotError,
    latest_snapshot,
    load_snapshot,
)

EXIT_ERROR = 1
VALUE_ERROR_PREFIX = "Value error, "
DISPLAY_TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"
GREY = "bright_black"
PRIORITY_STYLES = {
    "P1": "bold red",
    "P2": "dark_orange",
    "P3": "yellow",
    "P4": "cyan",
}


class OutputFormat(StrEnum):
    """Output format of a command."""

    TABLE = "table"
    JSON = "json"


def _message(error: Exception) -> str:
    """Word an error in one line, validation errors as ``field: reason``."""
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
def fail_cleanly() -> Iterator[None]:
    """Turn expected errors into a message on stderr and exit code 1."""
    try:
        yield
    except (ValidationError, SnapshotError, FetchError) as error:
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
        return load_snapshot(snapshot_id)
    if not refresh and (snapshot := latest_snapshot()) is not None:
        return snapshot
    return fetch_snapshot()


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
