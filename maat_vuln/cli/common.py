"""Pieces shared by the commands: options, error handling and display."""

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

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
FETCH_STATUS = "Fetching the KEV and EPSS feeds…"
# Age past which reusing the latest snapshot warns, unless --max-age;
# stale_after in maat.toml replaces it, through ctx.meta under this key.
STALE_AFTER = timedelta(hours=24)
STALE_AFTER_KEY = "maat_vuln.stale_after"
HOUR = timedelta(hours=1)
# Name of Click's ParameterSource for a value typed on the command line.
COMMAND_LINE = "COMMANDLINE"
logger = logging.getLogger(__name__)


class OutputFormat(StrEnum):
    """Output format of a command."""

    TABLE = "table"
    JSON = "json"


def message(error: Exception) -> str:
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
            typer.echo(f"Error: {message(error)}", err=True)
        raise typer.Exit(EXIT_ERROR) from error


def fetch_with_status(root: Path, status: bool = True) -> Snapshot:
    """Fetch a new snapshot, under a spinner on stderr if ``status``.

    Rich shows the spinner on a terminal only, and erases it once done.

    Raises:
        FetchError: a feed could not be fetched.
    """
    with (
        Console(stderr=True).status(FETCH_STATUS) if status else nullcontext()
    ):
        return fetch_snapshot(root)


def resolve_snapshot(
    ctx: typer.Context,
    snapshot_id: str | None,
    refresh: bool,
    max_age: int | None = None,
    quiet: bool = False,
    verbose: bool = False,
) -> Snapshot:
    """Load the requested snapshot, else the latest, else fetch one.

    Reusing the latest snapshot warns on stderr when it is older than
    ``stale_after`` from the config file, unless ``max_age`` is given.

    Args:
        snapshot_id: Snapshot to load, given by ``--snapshot``.
        refresh: Fetch a new snapshot, as ``--refresh`` asks.
        ctx: Context of the command, holding the snapshot directory.
        max_age: Reuse the latest snapshot only if younger than this
            many hours, as ``--max-age`` or ``MAAT_MAX_AGE`` asks.
        quiet: Leave out the stale snapshot warning and the spinner.
        verbose: Leave out the spinner, as the steps show progress.

    Raises:
        typer.BadParameter: --snapshot, --refresh and a typed
            --max-age are combined.
        SnapshotError: the snapshot is unknown or inconsistent.
        FetchError: a feed could not be fetched.
    """
    if snapshot_id is not None and refresh:
        raise typer.BadParameter(
            "cannot be combined with --snapshot", param_hint="'--refresh'"
        )
    # A max_age not typed gives way to --snapshot and --refresh, as
    # flags beat variables.
    if (
        max_age is not None
        and (snapshot_id is not None or refresh)
        and ctx.get_parameter_source("max_age").name == COMMAND_LINE
    ):
        raise typer.BadParameter(
            "cannot be combined with --snapshot or --refresh",
            param_hint="'--max-age'",
        )
    root = ctx.obj
    status = not (quiet or verbose)
    if snapshot_id is not None:
        logger.info("Loading snapshot %s, given by --snapshot", snapshot_id)
        return load_snapshot(snapshot_id, root)
    if refresh:
        logger.info("Fetching a new snapshot, as --refresh asks")
        return fetch_with_status(root, status)
    logger.info("Looking for the latest snapshot in %s", root)
    if (snapshot := latest_snapshot(root)) is not None:
        age = datetime.now(UTC) - snapshot.manifest.created_at
        if max_age is not None and age >= max_age * HOUR:
            logger.info(
                "The latest snapshot is %d hours old, not younger than"
                " --max-age: fetching a new one",
                age // HOUR,
            )
            return fetch_with_status(root, status)
        logger.info(
            "Using the latest snapshot %s, created %s",
            snapshot.manifest.snapshot_id,
            timestamp(snapshot.manifest.created_at),
        )
        stale = age > ctx.meta[STALE_AFTER_KEY]
        if max_age is None and stale and not quiet:
            typer.echo(
                # A blank line first, as the report starts with one.
                f"\nWarning: the latest snapshot is {age // HOUR} hours old;"
                " use --refresh or --max-age HOURS for fresher feeds.",
                err=True,
            )
        return snapshot
    logger.info("No snapshot in the cache: fetching a new one")
    return fetch_with_status(root, status)


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
