"""Prioritization engine: findings and a snapshot in, a report out.

Signals are resolved once per vulnerability from the snapshot; CVSS
values missing from both the input and the snapshot cache are looked
up, then appended to the cache. Every async entry point has a sync
facade for callers without an event loop.
"""

import asyncio
import hashlib
from collections import Counter
from collections.abc import Callable, Coroutine, Iterable
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from pydantic import MISSING

from maat_vuln.feeds import (
    DEFAULT_CONCURRENCY,
    EPSS_FEED_NAME,
    KEV_FEED_NAME,
    HttpClient,
    fetch_epss,
    fetch_kev,
    lookup_cvss,
    parse_epss,
    parse_kev,
)
from maat_vuln.models import (
    CVE_PATTERN,
    CvssInput,
    CvssSignal,
    CvssValue,
    EpssSignal,
    Finding,
    KevSignal,
    PolicyRef,
    Report,
    Signals,
    Summary,
    merge_findings,
)
from maat_vuln.policy import (
    POLICY_ID,
    POLICY_VERSION,
    decide,
    select_cvss,
    sort_decisions,
)
from maat_vuln.snapshot import (
    CvssEntry,
    Snapshot,
    SnapshotError,
    append_cvss,
    create_snapshot,
    read_cvss,
)

MAAT_VERSION = version("maat-vuln")
INPUT_SOURCE = "input"
UNSCORED = "unscored"


def _feed_content(snapshot: Snapshot, name: str) -> bytes:
    """Read a feed file of the snapshot, checked against its hash.

    Raises:
        SnapshotError: the feed is missing or its file was altered.
    """
    snapshot_id = snapshot.manifest.snapshot_id
    record = next(
        (feed for feed in snapshot.manifest.feeds if feed.name == name), None
    )
    if record is None:
        raise SnapshotError(f"snapshot {snapshot_id} has no {name} feed")
    try:
        content = (snapshot.path / record.filename).read_bytes()
    except OSError as error:
        raise SnapshotError(
            f"cannot read {record.filename} of snapshot {snapshot_id}"
        ) from error
    # The manifest hash only covers the manifest, not the files it lists.
    if hashlib.sha256(content).hexdigest() != record.sha256:
        raise SnapshotError(
            f"{record.filename} of snapshot {snapshot_id} does not match"
            " its hash"
        )
    return content


def _signals(
    vuln_id: str,
    inputs: list[CvssValue],
    kev: dict[str, KevSignal],
    epss: dict[str, EpssSignal],
    cvss: dict[str, CvssEntry],
) -> Signals:
    """Resolve the signals of one vulnerability.

    CVSS comes from the input first, then from the snapshot cache; it
    stays absent when neither has it, i.e. the lookup failed or, for a
    non-CVE pivot, never ran.
    """
    cvss_signal: CvssSignal | MISSING | None = MISSING
    if inputs:
        cvss_signal = select_cvss(inputs)
    elif (entry := cvss.get(vuln_id)) is not None:
        cvss_signal = select_cvss(entry.values) if entry.values else None
    if not CVE_PATTERN.fullmatch(vuln_id):
        return Signals(cvss=cvss_signal)
    return Signals(
        kev=kev.get(vuln_id, KevSignal(in_kev=False)),
        epss=epss.get(vuln_id),
        cvss=cvss_signal,
    )


async def aprioritize(
    findings: Iterable[Finding],
    snapshot: Snapshot,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> Report:
    """Prioritize findings against a snapshot of the feeds.

    ``concurrency`` caps simultaneous CVSS lookup requests.

    Raises:
        SnapshotError: a feed file of the snapshot is missing or altered.
    """
    merged = merge_findings(findings)
    # Signals are per vulnerability, so the input CVSS of every finding
    # of a vulnerability applies to all of them.
    inputs: dict[str, dict[CvssInput, None]] = {}
    for finding in merged:
        inputs.setdefault(finding.id, {}).update(dict.fromkeys(finding.cvss))
    input_values = {
        vuln_id: [
            CvssValue(**value.model_dump(), source=INPUT_SOURCE)
            for value in values
        ]
        for vuln_id, values in inputs.items()
    }
    cves = sorted(i for i in input_values if CVE_PATTERN.fullmatch(i))
    kev = parse_kev(_feed_content(snapshot, KEV_FEED_NAME))
    epss = parse_epss(_feed_content(snapshot, EPSS_FEED_NAME), cves)
    cvss = read_cvss(snapshot)
    to_look_up = [c for c in cves if not input_values[c] and c not in cvss]
    if to_look_up:
        async with HttpClient(concurrency) as client:
            entries = await lookup_cvss(client, to_look_up)
        append_cvss(snapshot, entries)
        cvss |= {entry.id: entry for entry in entries}
    signals = {
        vuln_id: _signals(vuln_id, values, kev, epss, cvss)
        for vuln_id, values in input_values.items()
    }
    snapshot_id = snapshot.manifest.snapshot_id
    decisions = sort_decisions(
        decide(finding.key, signals[finding.id], snapshot_id)
        for finding in merged
    )
    counts = Counter(d.priority or UNSCORED for d in decisions)
    return Report(
        generated_at=datetime.now(UTC),
        maat_version=MAAT_VERSION,
        policy=PolicyRef(id=POLICY_ID, version=POLICY_VERSION),
        snapshot_id=snapshot_id,
        decisions=decisions,
        summary=Summary(**{key: counts[key] for key in Summary.model_fields}),
    )


async def afetch_snapshot(root: Path | None = None) -> Snapshot:
    """Fetch the KEV and EPSS feeds and store them as a new snapshot.

    ``root`` defaults to the snapshot directory of the user cache.

    Raises:
        FetchError: a feed could not be fetched or is malformed.
    """
    async with HttpClient() as client:
        feeds = await asyncio.gather(fetch_kev(client), fetch_epss(client))
    return create_snapshot(list(feeds), root)


def _run[T](start: Callable[[], Coroutine[object, object, T]], name: str) -> T:
    """Run an async entry point from sync code.

    The loop is checked before the coroutine is created, so a refused
    call leaves no coroutine never awaited behind.

    Raises:
        RuntimeError: an event loop is already running.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(start())
    raise RuntimeError(
        f"an event loop is already running: await {name}() instead"
    )


def prioritize(
    findings: Iterable[Finding],
    snapshot: Snapshot,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> Report:
    """Sync facade of :func:`aprioritize`.

    Raises:
        RuntimeError: called from a running event loop.
        SnapshotError: a feed file of the snapshot is missing or altered.
    """
    return _run(
        lambda: aprioritize(findings, snapshot, concurrency), "aprioritize"
    )


def fetch_snapshot(root: Path | None = None) -> Snapshot:
    """Sync facade of :func:`afetch_snapshot`.

    Raises:
        RuntimeError: called from a running event loop.
        FetchError: a feed could not be fetched or is malformed.
    """
    return _run(lambda: afetch_snapshot(root), "afetch_snapshot")
