"""Command line: ``maat rank``, ``maat explain`` and ``maat snapshot``.

The CLI stays synchronous and calls the library's sync facades; it is
the only part of Maât that writes to the terminal.
"""

import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from enum import StrEnum
from typing import Annotated

import typer
from pydantic import MISSING, ValidationError
from rich.console import Console
from rich.table import Table
from rich.text import Text

from maat_vuln.engine import fetch_snapshot, prioritize
from maat_vuln.feeds import (
    DEFAULT_CONCURRENCY,
    EPSS_FEED_NAME,
    KEV_FEED_NAME,
    FetchError,
)
from maat_vuln.models import (
    Component,
    CvssSignal,
    Decision,
    EpssSignal,
    Finding,
    FindingsInput,
    KevSignal,
    Report,
)
from maat_vuln.snapshot import (
    Snapshot,
    SnapshotError,
    latest_snapshot,
    load_snapshot,
    read_cvss,
)

EXIT_ERROR = 1
ABSENT = "-"
NOT_COMPUTED = "not computed"
NO_DATA = "no data"
UNSCORED = "unscored"
COLUMNS = (
    "Priority",
    "ID",
    "Component",
    "KEV",
    "EPSS",
    "Pctl",
    "CVSS",
    "Rule",
    "Flags",
)
FEED_COLUMNS = ("Feed", "Version", "Retrieved", "URL", "SHA-256")

app = typer.Typer(no_args_is_help=True, add_completion=False)
snapshot_app = typer.Typer(no_args_is_help=True)
app.add_typer(
    snapshot_app, name="snapshot", help="Fetch or inspect feed snapshots."
)


class OutputFormat(StrEnum):
    """Output format of a command."""

    TABLE = "table"
    JSON = "json"


@app.callback()
def main() -> None:
    """Maât: exploitation-driven vulnerability prioritization."""


@contextmanager
def _fail_cleanly() -> Iterator[None]:
    """Turn expected errors into a message on stderr and exit code 1."""
    try:
        yield
    except (ValidationError, SnapshotError, FetchError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(EXIT_ERROR) from error


def _read_findings(
    ids: list[str], document: typer.FileText | None
) -> list[Finding]:
    """Collect the findings given as arguments, JSON or stdin lines.

    Raises:
        typer.BadParameter: nothing given and stdin is a terminal.
        ValidationError: an ID or the JSON document is invalid.
    """
    findings = [Finding(id=vuln_id) for vuln_id in ids]
    if document is not None:
        findings += FindingsInput.model_validate_json(document.read()).findings
    elif not ids:
        if sys.stdin.isatty():
            raise typer.BadParameter(
                "give IDs, --input FILE or IDs on stdin", param_hint="IDS"
            )
        findings = [
            Finding(id=line)
            for line in sys.stdin.read().splitlines()
            if line.strip()
        ]
    return findings


def _snapshot(snapshot_id: str | None, refresh: bool) -> Snapshot:
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


def _row(decision: Decision) -> list[str]:
    """Render one decision as a table row; absent signals show a dash."""
    signals = decision.explanation.signals
    kev = signals.kev
    epss = signals.epss
    cvss = signals.cvss
    return [
        decision.priority or ABSENT,
        decision.finding_key.id,
        decision.finding_key.component or "",
        ("yes" if kev.in_kev else "no")
        if isinstance(kev, KevSignal)
        else ABSENT,
        f"{epss.probability:.5f}" if isinstance(epss, EpssSignal) else ABSENT,
        f"{epss.percentile:.3f}" if isinstance(epss, EpssSignal) else ABSENT,
        f"{cvss.selected.base_score:.1f} v{cvss.selected.version}"
        if isinstance(cvss, CvssSignal)
        else ABSENT,
        decision.rule_id,
        ", ".join(decision.flags),
    ]


def _print_table(report: Report) -> None:
    """Print the decisions as a table, then the summary and snapshot."""
    table = Table(*COLUMNS)
    for decision in report.decisions:
        table.add_row(*_row(decision))
    console = Console()
    console.print(table)
    console.print(
        " · ".join(f"{key} {count}" for key, count in report.summary)
    )
    console.print(f"snapshot {report.snapshot_id}")


@app.command()
def rank(
    ids: Annotated[
        list[str] | None,
        typer.Argument(
            metavar="IDS...", help="Vulnerability IDs (CVE, GHSA…)."
        ),
    ] = None,
    document: Annotated[
        typer.FileText | None,
        typer.Option("--input", help="JSON input document, '-' for stdin."),
    ] = None,
    output: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.TABLE,
    snapshot_id: Annotated[
        str | None,
        typer.Option("--snapshot", help="Snapshot ID to rank against."),
    ] = None,
    refresh: Annotated[
        bool,
        typer.Option("--refresh", help="Fetch a new snapshot first."),
    ] = False,
    concurrency: Annotated[
        int,
        typer.Option(min=1, help="Maximum simultaneous CVSS lookups."),
    ] = DEFAULT_CONCURRENCY,
) -> None:
    """Rank vulnerabilities by priority, P1 first.

    With no IDs and no --input, IDs are read from stdin, one per line.
    The latest snapshot is used unless --snapshot or --refresh is given;
    one is fetched when the cache has none.
    """
    with _fail_cleanly():
        findings = _read_findings(ids or [], document)
        report = prioritize(
            findings, _snapshot(snapshot_id, refresh), concurrency
        )
    if output is OutputFormat.JSON:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _print_table(report)


def _describe[S](
    signal: S | MISSING | None, describe: Callable[[S], str]
) -> str:
    """Describe a signal, telling not computed from looked up in vain."""
    if signal is MISSING:
        return NOT_COMPUTED
    if signal is None:
        return NO_DATA
    return describe(signal)


def _kev(kev: KevSignal) -> str:
    """Describe a KEV status with its dates."""
    if not kev.in_kev:
        return "not in KEV"
    ransomware = kev.known_ransomware_campaign_use
    return (
        f"in KEV, added {kev.date_added}, due {kev.due_date}, known"
        f" ransomware use {'yes' if ransomware is True else 'no'}"
    )


def _epss(epss: EpssSignal) -> str:
    """Describe an EPSS score with its model and date."""
    return (
        f"probability {epss.probability:.5f}, percentile"
        f" {epss.percentile:.5f}, model {epss.model_version}, scored"
        f" {epss.score_date}"
    )


def _cvss(cvss: CvssSignal) -> str:
    """List every CVSS value with its source, the selected one marked."""
    return "\n".join(
        f"{value.base_score:.1f} v{value.version} {value.vector or ''}"
        f" ({value.source}){' selected' if value == cvss.selected else ''}"
        for value in cvss.values
    )


def _feed_source(snapshot: Snapshot, name: str) -> str:
    """Name the snapshot feed file a signal was read from."""
    feed = next(f for f in snapshot.manifest.feeds if f.name == name)
    return f"{feed.url}, retrieved {feed.retrieved_at.isoformat()}"


def _print_decision(decision: Decision, snapshot: Snapshot) -> None:
    """Print a decision: its rule, then each signal and its source."""
    explanation = decision.explanation
    signals = explanation.signals
    lines = [
        ("ID", decision.finding_key.id),
        ("Component", decision.finding_key.component or ABSENT),
        ("Priority", decision.priority or UNSCORED),
        ("Rule", decision.rule_id),
        ("Condition", explanation.rule),
        (
            "Thresholds",
            ", ".join(f"{k} {v}" for k, v in explanation.thresholds.items())
            or ABSENT,
        ),
    ]
    for label, signal, describe, feed in (
        ("KEV", signals.kev, _kev, KEV_FEED_NAME),
        ("EPSS", signals.epss, _epss, EPSS_FEED_NAME),
        ("CVSS", signals.cvss, _cvss, None),
    ):
        lines.append((label, _describe(signal, describe)))
        # A feed was searched, in vain or not, whenever its signal is set.
        if feed is not None and signal is not MISSING:
            lines.append((f"{label} source", _feed_source(snapshot, feed)))
    lines += [
        ("Flags", ", ".join(decision.flags) or ABSENT),
        ("Snapshot", decision.snapshot_id),
        ("Created", snapshot.manifest.created_at.isoformat()),
    ]
    table = Table.grid(padding=(0, 2))
    for label, value in lines:
        table.add_row(label, Text(value))
    Console().print(table)


@app.command()
def explain(
    vuln_id: Annotated[
        str, typer.Argument(metavar="ID", help="Vulnerability ID.")
    ],
    purl: Annotated[
        str | None,
        typer.Option("--component", help="Package URL of the component."),
    ] = None,
    output: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.TABLE,
    snapshot_id: Annotated[
        str | None,
        typer.Option("--snapshot", help="Snapshot ID to explain against."),
    ] = None,
    refresh: Annotated[
        bool,
        typer.Option("--refresh", help="Fetch a new snapshot first."),
    ] = False,
) -> None:
    """Explain the priority of one vulnerability: rule and signals.

    The latest snapshot is used unless --snapshot or --refresh is given;
    one is fetched when the cache has none.
    """
    component = Component(purl=purl) if purl else None
    with _fail_cleanly():
        finding = Finding(id=vuln_id, component=component)
        snapshot = _snapshot(snapshot_id, refresh)
        decision = prioritize([finding], snapshot).decisions[0]
    if output is OutputFormat.JSON:
        typer.echo(decision.model_dump_json(indent=2))
    else:
        _print_decision(decision, snapshot)


@snapshot_app.command("fetch")
def snapshot_fetch() -> None:
    """Fetch the KEV and EPSS feeds into a new snapshot; print its ID."""
    with _fail_cleanly():
        snapshot = fetch_snapshot()
    typer.echo(snapshot.manifest.snapshot_id)


def _print_snapshot(snapshot: Snapshot) -> None:
    """Print a snapshot's identity, then one table row per feed."""
    manifest = snapshot.manifest
    # Plain echo: Rich would wrap the path, which must stay copyable.
    typer.echo(f"snapshot {manifest.snapshot_id}")
    typer.echo(f"created {manifest.created_at.isoformat()}")
    typer.echo(f"path {snapshot.path}")
    typer.echo(f"cached CVSS lookups {len(read_cvss(snapshot))}")
    table = Table(*FEED_COLUMNS)
    # Fold rather than truncate: the URL and hash matter in full.
    for column in table.columns:
        column.overflow = "fold"
    for feed in manifest.feeds:
        table.add_row(
            feed.name,
            "\n".join(f"{key}={value}" for key, value in feed.version.items()),
            feed.retrieved_at.isoformat(),
            feed.url,
            feed.sha256,
        )
    Console().print(table)


@snapshot_app.command("show")
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
    with _fail_cleanly():
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
