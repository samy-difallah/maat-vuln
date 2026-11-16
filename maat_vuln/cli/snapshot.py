"""``maat snapshot``: fetch a snapshot of the feeds, list, show or delete."""

from typing import Annotated

import typer
from pydantic import TypeAdapter
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
    Manifest,
    Snapshot,
    latest_snapshot,
    list_snapshots,
    load_snapshot,
    prune_snapshots,
    read_cvss,
    remove_snapshots,
)

FEED_INDENT = "  "
FETCH_STATUS = "Fetching the KEV and EPSS feeds…"
EMPTY_CACHE = "no snapshot in cache, run maat snapshot fetch"


def _versions(version: dict[str, str]) -> Text:
    """Word a feed's version info on one line: ``key value, ...``."""
    return Text(", ".join(f"{k} {v}" for k, v in version.items()))


def snapshot_fetch(ctx: typer.Context) -> None:
    """Fetch the KEV and EPSS feeds into a new snapshot; print its ID."""
    # Progress and feed versions go to stderr: stdout holds only the ID,
    # so scripts can capture it.
    console = Console(stderr=True)
    with fail_cleanly(), console.status(FETCH_STATUS):
        snapshot = fetch_snapshot(ctx.obj)
    print_fields(
        console,
        [
            (feed.name, _versions(feed.version))
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
    ctx: typer.Context,
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
            latest_snapshot(ctx.obj)
            if snapshot_id is None
            else load_snapshot(snapshot_id, ctx.obj)
        )
    if snapshot is None:
        typer.echo(f"Error: {EMPTY_CACHE}", err=True)
        raise typer.Exit(EXIT_ERROR)
    if output is OutputFormat.JSON:
        typer.echo(snapshot.manifest.model_dump_json(indent=2))
    else:
        _print_snapshot(snapshot)


def _print_list(snapshots: list[Snapshot]) -> None:
    """Print one block of fields per snapshot, headed by its ID."""
    console = Console()
    for snapshot in snapshots:
        manifest = snapshot.manifest
        console.print()
        console.print(Text(manifest.snapshot_id, "bold"), soft_wrap=True)
        print_fields(
            console,
            [
                ("created", Text(timestamp(manifest.created_at))),
                ("CVSS lookups", Text(str(len(read_cvss(snapshot))))),
                *(
                    (feed.name, _versions(feed.version))
                    for feed in manifest.feeds
                ),
            ],
            indent=FEED_INDENT,
        )
    console.print()


def snapshot_list(
    ctx: typer.Context,
    output: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """List the snapshots of the cache, newest first."""
    snapshots = list_snapshots(ctx.obj)
    if output is OutputFormat.JSON:
        manifests = [snapshot.manifest for snapshot in snapshots]
        typer.echo(TypeAdapter(list[Manifest]).dump_json(manifests, indent=2))
    elif snapshots:
        _print_list(snapshots)
    else:
        # Not an error: an empty list is a valid answer.
        typer.echo(EMPTY_CACHE.capitalize(), err=True)


def snapshot_prune(
    ctx: typer.Context,
    keep: Annotated[
        int,
        typer.Option(
            min=0, metavar="N", help="Number of newest snapshots to keep."
        ),
    ],
) -> None:
    """Delete every snapshot but the N newest; print the deleted IDs."""
    with fail_cleanly():
        pruned = prune_snapshots(keep, ctx.obj)
    for snapshot_id in pruned:
        typer.echo(snapshot_id)


def snapshot_rm(
    ctx: typer.Context,
    snapshot_ids: Annotated[
        list[str],
        typer.Argument(metavar="ID...", help="Snapshot IDs to delete."),
    ],
) -> None:
    """Delete the given snapshots and print their IDs."""
    with fail_cleanly():
        removed = remove_snapshots(snapshot_ids, ctx.obj)
    for snapshot_id in removed:
        typer.echo(snapshot_id)
