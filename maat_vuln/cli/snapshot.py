"""``maat snapshot``: fetch a new snapshot of the feeds or show one."""

from typing import Annotated

import typer
from rich.console import Console
from rich.text import Text

from maat_vuln.cli.common import (
    EXIT_ERROR,
    GREY,
    OutputFormat,
    fail_cleanly,
    print_fields,
    timestamp,
)
from maat_vuln.engine import fetch_snapshot
from maat_vuln.snapshot import (
    Snapshot,
    latest_snapshot,
    load_snapshot,
    read_cvss,
)

FEED_INDENT = "  "
FETCH_STATUS = "Fetching the KEV and EPSS feeds…"


def snapshot_fetch() -> None:
    """Fetch the KEV and EPSS feeds into a new snapshot; print its ID."""
    # Progress and feed versions go to stderr: stdout holds only the ID,
    # so scripts can capture it.
    console = Console(stderr=True)
    with fail_cleanly(), console.status(FETCH_STATUS):
        snapshot = fetch_snapshot()
    print_fields(
        console,
        [
            (
                feed.name,
                Text(", ".join(f"{k} {v}" for k, v in feed.version.items())),
            )
            for feed in snapshot.manifest.feeds
        ],
    )
    typer.echo(snapshot.manifest.snapshot_id)


def _print_snapshot(snapshot: Snapshot) -> None:
    """Print a snapshot's identity, then one block of fields per feed."""
    manifest = snapshot.manifest
    console = Console()
    console.print()
    print_fields(
        console,
        [
            ("Snapshot", Text(manifest.snapshot_id, "bold")),
            ("Created", Text(timestamp(manifest.created_at))),
            ("Path", Text(str(snapshot.path))),
            ("CVSS lookups", Text(str(len(read_cvss(snapshot))))),
        ],
    )
    for feed in manifest.feeds:
        console.print()
        console.print(Text(feed.name, "bold"))
        print_fields(
            console,
            [
                *((key, Text(value)) for key, value in feed.version.items()),
                ("retrieved", Text(timestamp(feed.retrieved_at))),
                ("url", Text(feed.url)),
                ("sha256", Text(feed.sha256, GREY)),
            ],
            indent=FEED_INDENT,
        )
    console.print()


def snapshot_show(
    snapshot_id: Annotated[
        str | None,
        typer.Argument(metavar="[ID]", help="Snapshot ID, latest if none."),
    ] = None,
    output: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """Show a snapshot's manifest: its feeds, versions and hashes."""
    with fail_cleanly():
        snapshot = (
            latest_snapshot()
            if snapshot_id is None
            else load_snapshot(snapshot_id)
        )
    if snapshot is None:
        typer.echo(
            "Error: no snapshot in cache, run maat snapshot fetch", err=True
        )
        raise typer.Exit(EXIT_ERROR)
    if output is OutputFormat.JSON:
        typer.echo(snapshot.manifest.model_dump_json(indent=2))
    else:
        _print_snapshot(snapshot)
