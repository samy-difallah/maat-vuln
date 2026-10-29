"""Command line: ``maat rank`` prints the prioritized findings.

The CLI stays synchronous and calls the library's sync facades; it is
the only part of Maât that writes to the terminal.
"""

import sys
from enum import StrEnum
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from maat_vuln.engine import fetch_snapshot, prioritize
from maat_vuln.feeds import DEFAULT_CONCURRENCY, FetchError
from maat_vuln.models import (
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
)

EXIT_ERROR = 1
ABSENT = "-"
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

app = typer.Typer(no_args_is_help=True, add_completion=False)


class OutputFormat(StrEnum):
    """Output format of ``maat rank``."""

    TABLE = "table"
    JSON = "json"


@app.callback()
def main() -> None:
    """Maât: exploitation-driven vulnerability prioritization."""


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
        SnapshotError: the snapshot is unknown or inconsistent.
        FetchError: a feed could not be fetched.
    """
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
    if snapshot_id is not None and refresh:
        raise typer.BadParameter(
            "cannot be combined with --snapshot", param_hint="'--refresh'"
        )
    try:
        findings = _read_findings(ids or [], document)
        report = prioritize(
            findings, _snapshot(snapshot_id, refresh), concurrency
        )
    except (ValidationError, SnapshotError, FetchError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(EXIT_ERROR) from error
    if output is OutputFormat.JSON:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _print_table(report)
