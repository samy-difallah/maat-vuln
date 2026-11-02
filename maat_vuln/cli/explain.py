"""``maat explain``: the rule, signals and sources behind one verdict."""

from collections.abc import Callable
from typing import Annotated

import typer
from pydantic import MISSING
from rich.console import Console
from rich.text import Text

from maat_vuln.cli.common import (
    GREY,
    PRIORITY_STYLES,
    OutputFormat,
    fail_cleanly,
    print_fields,
    resolve_snapshot,
    timestamp,
)
from maat_vuln.engine import prioritize
from maat_vuln.feeds import EPSS_FEED_NAME, KEV_FEED_NAME
from maat_vuln.models import (
    Component,
    CvssSignal,
    Decision,
    EpssSignal,
    Finding,
    Flag,
    KevSignal,
)
from maat_vuln.snapshot import Snapshot

NOT_COMPUTED = "not computed, no CVE ID"
LOOKUP_FAILED = "lookup failed, retried on the next run"
SELECTED = "selected"
NO_DATA = "no data"
UNSCORED = "unscored"


def _describe[S](
    signal: S | MISSING | None,
    describe: Callable[[S], str],
    not_computed: str,
) -> str:
    """Describe a signal, telling not computed from looked up in vain."""
    if signal is MISSING:
        return not_computed
    if signal is None:
        return NO_DATA
    return describe(signal)


def _kev(kev: KevSignal) -> str:
    """Describe a KEV status with its dates."""
    if not kev.in_kev:
        return "not in KEV"
    # CISA only tells known from unknown: it never states "no ransomware".
    ransomware = (
        "known" if kev.known_ransomware_campaign_use is True else "unknown"
    )
    return (
        f"in KEV, added {kev.date_added}, due {kev.due_date},"
        f" ransomware use {ransomware}"
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
        " ".join(
            part
            for part in (
                f"{value.base_score:.1f}",
                f"v{value.version}",
                value.vector,
                f"({value.source})",
                SELECTED if value == cvss.selected else None,
            )
            if part
        )
        for value in cvss.values
    )


def _feed_source(snapshot: Snapshot, name: str) -> str:
    """Name the snapshot feed file a signal was read from."""
    feed = next(f for f in snapshot.manifest.feeds if f.name == name)
    return f"{feed.url}, retrieved {timestamp(feed.retrieved_at)}"


def _print_decision(decision: Decision, snapshot: Snapshot) -> None:
    """Print a decision in blocks: verdict, rule, signals, provenance."""
    explanation = decision.explanation
    signals = explanation.signals
    style = PRIORITY_STYLES.get(decision.priority or "", "")
    verdict = [("ID", Text(decision.finding_key.id, style))]
    if decision.finding_key.component:
        verdict.append(("Component", Text(decision.finding_key.component)))
    verdict.append(("Priority", Text(decision.priority or UNSCORED, style)))
    if decision.flags:
        verdict.append(("Flags", Text(", ".join(decision.flags), GREY)))
    rule = [
        ("Rule", Text(decision.rule_id)),
        ("Condition", Text(explanation.rule)),
    ]
    if explanation.thresholds:
        rule.append(
            (
                "Thresholds",
                Text(
                    ", ".join(
                        f"{k} {v}" for k, v in explanation.thresholds.items()
                    )
                ),
            )
        )
    cvss_not_computed = (
        LOOKUP_FAILED
        if Flag.CVSS_LOOKUP_FAILED in decision.flags
        else NOT_COMPUTED
    )
    evidence: list[tuple[str, Text]] = []
    provenance = [
        ("Snapshot", Text(decision.snapshot_id)),
        ("Created", Text(timestamp(snapshot.manifest.created_at))),
    ]
    for label, signal, describe, not_computed, feed in (
        ("KEV", signals.kev, _kev, NOT_COMPUTED, KEV_FEED_NAME),
        ("EPSS", signals.epss, _epss, NOT_COMPUTED, EPSS_FEED_NAME),
        ("CVSS", signals.cvss, _cvss, cvss_not_computed, None),
    ):
        first, *rest = _describe(signal, describe, not_computed).splitlines()
        # Further CVSS values go under the first, with no label.
        evidence += [(label, Text(first)), *(("", Text(r)) for r in rest)]
        # A feed was searched, in vain or not, whenever its signal is set.
        if feed is not None and signal is not MISSING:
            provenance.append(
                (f"{label} source", Text(_feed_source(snapshot, feed)))
            )
    blocks = (verdict, rule, evidence, provenance)
    width = max(len(label) for block in blocks for label, _ in block) + 2
    console = Console()
    for block in blocks:
        console.print()
        print_fields(console, block, width=width)
    console.print()


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
    with fail_cleanly():
        finding = Finding(id=vuln_id, component=component)
        snapshot = resolve_snapshot(snapshot_id, refresh)
        decision = prioritize([finding], snapshot).decisions[0]
    if output is OutputFormat.JSON:
        typer.echo(decision.model_dump_json(indent=2))
    else:
        _print_decision(decision, snapshot)
