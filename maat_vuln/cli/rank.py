"""``maat rank``: rank vulnerabilities by priority, as a table or JSON."""

import json
import sys
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from maat_vuln.adapters import load_findings
from maat_vuln.cli.common import (
    GREY,
    PRIORITY_STYLES,
    OutputFormat,
    fail_cleanly,
    priority_label,
    resolve_snapshot,
)
from maat_vuln.engine import prioritize
from maat_vuln.feeds import DEFAULT_CONCURRENCY
from maat_vuln.models import (
    CvssSignal,
    Decision,
    EpssSignal,
    Finding,
    KevSignal,
    Report,
)

ABSENT = "-"
# Name Click gives the stream it opens for the '-' file argument.
STDIN_NAME = "<stdin>"
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
NUMERIC_COLUMNS = frozenset({"EPSS", "Pctl", "CVSS"})
COMPONENT_COLUMN = "Component"
WRAPPING_COLUMNS = frozenset({COMPONENT_COLUMN, "Rule", "Flags"})


def _read_findings(
    ids: list[str], documents: list[typer.FileText]
) -> list[Finding]:
    """Collect the findings given as arguments, JSON or stdin lines.

    The findings of every document are kept in order; the engine merges
    those of the same vulnerability and component.

    Raises:
        typer.BadParameter: stdin given twice as --input, or nothing
            given and stdin is a terminal.
        JSONDecodeError: an input document is not JSON.
        FormatError: an input document is in no supported format.
        ValidationError: an ID or an input document is invalid.
    """
    if [document.name for document in documents].count(STDIN_NAME) > 1:
        raise typer.BadParameter(
            "'-' (stdin) can be given only once", param_hint="--input"
        )
    findings = [Finding(id=vuln_id) for vuln_id in ids]
    for document in documents:
        findings += load_findings(json.loads(document.read()))
    if not ids and not documents:
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


def _table(*columns: str) -> Table:
    """Start a table with a bold header over a heavy rule, no borders."""
    # The box's blank vertical and the right padding keep columns 2 apart.
    return Table(
        *columns,
        box=box.SIMPLE_HEAVY,
        show_edge=False,
        pad_edge=False,
        padding=(0, 1, 0, 0),
        header_style="bold",
    )


def _cell(value: str | None, style: str = "") -> Text:
    """Style a table cell; a missing value shows an unstyled dash."""
    return Text(value, style) if value else Text(ABSENT)


def _row(decision: Decision, with_component: bool) -> list[Text]:
    """Render one decision as a table row, coloured by its priority."""
    signals = decision.explanation.signals
    kev = signals.kev
    epss = signals.epss
    cvss = signals.cvss
    style = PRIORITY_STYLES.get(decision.priority or "", "")
    in_kev = isinstance(kev, KevSignal) and kev.in_kev
    return [
        _cell(priority_label(decision.priority), style),
        _cell(decision.finding_key.id, style),
        *([_cell(decision.finding_key.component)] if with_component else []),
        _cell(
            ("yes" if in_kev else "no")
            if isinstance(kev, KevSignal)
            else None,
            style if in_kev else "",
        ),
        _cell(
            f"{epss.probability:.5f}" if isinstance(epss, EpssSignal) else None
        ),
        _cell(
            f"{epss.percentile:.3f}" if isinstance(epss, EpssSignal) else None
        ),
        _cell(
            f"{cvss.selected.base_score:.1f}"
            if isinstance(cvss, CvssSignal)
            else None
        ),
        _cell(decision.rule_id),
        _cell("\n".join(decision.flags), GREY),
    ]


def _print_table(report: Report) -> None:
    """Print the decisions as a table, then the summary and snapshot."""
    with_component = any(d.finding_key.component for d in report.decisions)
    table = _table(
        *(c for c in COLUMNS if with_component or c != COMPONENT_COLUMN)
    )
    for column in table.columns:
        if column.header in NUMERIC_COLUMNS:
            column.justify = "right"
        # On a narrow terminal, only these columns give up width, so an
        # ID or a score is never cut short.
        if column.header in WRAPPING_COLUMNS:
            column.overflow = "fold"
        else:
            column.no_wrap = True
    for decision in report.decisions:
        table.add_row(*_row(decision, with_component))
    summary = Text(" · ").join(
        Text(f"{key} {count}", PRIORITY_STYLES.get(key, ""))
        for key, count in report.summary
    )
    snapshot = Text(f"snapshot {report.snapshot_id}")
    console = Console()
    for block in ("", table, "", summary, "", snapshot, ""):
        console.print(block)


def rank(
    ids: Annotated[
        list[str] | None,
        typer.Argument(
            metavar="IDS...", help="Vulnerability IDs (CVE, GHSA…)."
        ),
    ] = None,
    documents: Annotated[
        list[typer.FileText] | None,
        typer.Option(
            "--input",
            help="JSON input document in a supported format, '-' for stdin;"
            " repeat to combine several.",
        ),
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
    """Rank vulnerabilities by priority, CRITICAL first.

    IDs and --input documents, in any supported formats, are ranked
    together; findings of the same vulnerability and component merge.
    With no IDs and no --input, IDs are read from stdin, one per line.
    The latest snapshot is used unless --snapshot or --refresh is given;
    one is fetched when the cache has none.
    """
    with fail_cleanly():
        findings = _read_findings(ids or [], documents or [])
        report = prioritize(
            findings, resolve_snapshot(snapshot_id, refresh), concurrency
        )
    if output is OutputFormat.JSON:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _print_table(report)
