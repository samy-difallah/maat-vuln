"""Tests for the prioritization engine."""

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import MISSING

from maat_vuln import aprioritize, fetch_snapshot, prioritize
from maat_vuln.feeds import (
    CVSS_LOOKUP_URL,
    EPSS_FILENAME,
    EPSS_URL,
    KEV_FILENAME,
    KEV_URL,
)
from maat_vuln.models import Finding, Flag
from maat_vuln.snapshot import (
    CVSS_CACHE_NAME,
    RawFeed,
    SnapshotError,
    create_snapshot,
    load_snapshot,
    read_cvss,
)

# Trimmed real feed samples, shared with the feed client tests.
FEEDS_DIR = Path(__file__).parent.parent / "feeds"
KEV = (FEEDS_DIR / "kev.json").read_bytes()
EPSS = gzip.compress((FEEDS_DIR / "epss.csv").read_bytes())
CVSS_ANSWER = json.loads((FEEDS_DIR / "cvss_bulk.json").read_text())

IN_KEV = "CVE-2026-106931"
LOG4SHELL = "CVE-2021-44228"
XZ = "CVE-2024-3094"
DROWN = "CVE-2016-0800"
NO_CVSS = "CVE-2099-0001"
GHSA = "GHSA-JFH8-C2JP-5V3Q"
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def raw_feed(name, filename, content):
    """Build a raw feed file as fetched."""
    return RawFeed(
        name=name,
        url=f"https://example.org/{filename}",
        filename=filename,
        retrieved_at=datetime(2026, 10, 22, 12, tzinfo=UTC),
        version={},
        content=content,
    )


@pytest.fixture
def snapshot(tmp_path):
    """Snapshot of the KEV and EPSS samples."""
    return create_snapshot(
        [
            raw_feed("kev", KEV_FILENAME, KEV),
            raw_feed("epss", EPSS_FILENAME, EPSS),
        ],
        root=tmp_path,
    )


def finding(vuln_id, purl=None, cvss=()):
    """Build a finding, with input CVSS 3.1 base scores if given."""
    return Finding.model_validate(
        {
            "id": vuln_id,
            "component": {"purl": purl} if purl else None,
            "cvss": [{"version": "3.1", "base_score": s} for s in cvss],
        }
    )


def asked_cves(route):
    """CVE IDs sent to the bulk endpoint, NVD record IDs left out."""
    return sorted(
        id_
        for call in route.calls
        for id_ in json.loads(call.request.content)["ids"]
        if id_.startswith("CVE-")
    )


async def test_end_to_end(snapshot, respx_mock):
    """Findings get sorted decisions, CVSS looked up only when missing."""
    route = respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=CVSS_ANSWER)
    findings = [
        finding(GHSA),
        finding(NO_CVSS),
        finding(DROWN),
        finding(XZ),
        finding(LOG4SHELL, LOG4J, cvss=[10.0]),
        finding(IN_KEV, cvss=[9.8]),
    ]
    report = await aprioritize(findings, snapshot)
    assert asked_cves(route) == [DROWN, XZ, NO_CVSS]
    assert [
        (d.finding_key.id, d.priority, d.rule_id, d.flags)
        for d in report.decisions
    ] == [
        (IN_KEV, "P1", "p1.kev", [Flag.EPSS_MISSING]),
        (LOG4SHELL, "P2", "p2.epss_likely", []),
        (XZ, "P2", "p2.epss_likely", []),
        (DROWN, "P4", "p4.low", [Flag.EPSS_MISSING]),
        (
            NO_CVSS,
            None,
            "none.unscored",
            [Flag.CVSS_MISSING, Flag.EPSS_MISSING, Flag.UNSCORED],
        ),
        (
            GHSA,
            None,
            "none.unscored",
            [
                Flag.CVSS_MISSING,
                Flag.EPSS_MISSING,
                Flag.UNRESOLVED_ID,
                Flag.UNSCORED,
            ],
        ),
    ]
    signals = {
        d.finding_key.id: d.explanation.signals for d in report.decisions
    }
    assert signals[LOG4SHELL].cvss.selected.source == "input"
    assert signals[XZ].cvss.selected.source == "vulnerability-lookup"
    assert signals[NO_CVSS].cvss is None
    assert signals[NO_CVSS].kev.in_kev is False
    assert signals[GHSA].kev is MISSING
    assert report.summary.model_dump() == {
        "P1": 1,
        "P2": 2,
        "P3": 0,
        "P4": 1,
        "unscored": 2,
    }
    snapshot_id = snapshot.manifest.snapshot_id
    assert report.snapshot_id == snapshot_id
    assert {d.snapshot_id for d in report.decisions} == {snapshot_id}
    assert (report.policy.id, report.policy.version) == ("maat-default", 1)
    assert report.maat_version


async def test_lookups_are_cached(snapshot, respx_mock):
    """Lookups land in the snapshot and are never requested again."""
    route = respx_mock.post(CVSS_LOOKUP_URL).respond(200, json=CVSS_ANSWER)
    first = await aprioritize([finding(XZ), finding(NO_CVSS)], snapshot)
    assert set(read_cvss(snapshot)) == {XZ, NO_CVSS}
    second = await aprioritize([finding(XZ), finding(NO_CVSS)], snapshot)
    assert route.call_count == 1
    assert second.decisions == first.decisions


async def test_failed_lookup_is_flagged_not_cached(snapshot, respx_mock):
    """A failed lookup leaves CVSS absent and caches nothing."""
    respx_mock.post(CVSS_LOOKUP_URL).respond(400)
    report = await aprioritize([finding(XZ)], snapshot)
    decision = report.decisions[0]
    assert decision.explanation.signals.cvss is MISSING
    assert decision.flags == [Flag.CVSS_LOOKUP_FAILED]
    assert decision.priority == "P2"
    assert read_cvss(snapshot) == {}


async def test_input_cvss_is_per_vulnerability(snapshot, respx_mock):
    """Input CVSS of one finding applies to every finding of its CVE."""
    report = await aprioritize(
        [
            finding(XZ, "pkg:rpm/xz@5.6.0"),
            finding(XZ, "pkg:deb/xz@5.6.0", [3.9]),
        ],
        snapshot,
    )
    assert not respx_mock.calls
    assert [d.rule_id for d in report.decisions] == [
        "p3.epss_capped_low_cvss",
        "p3.epss_capped_low_cvss",
    ]


@pytest.mark.parametrize("filename", [KEV_FILENAME, EPSS_FILENAME])
async def test_altered_feed_file(snapshot, filename):
    """A feed file that no longer matches its hash is refused."""
    (snapshot.path / filename).write_bytes(b"tampered")
    with pytest.raises(SnapshotError, match="does not match"):
        await aprioritize([finding(XZ)], snapshot)


async def test_missing_feed_file(snapshot):
    """A feed file deleted from the snapshot is refused."""
    (snapshot.path / KEV_FILENAME).unlink()
    with pytest.raises(SnapshotError, match="cannot read"):
        await aprioritize([finding(XZ)], snapshot)


async def test_missing_feed(tmp_path):
    """A snapshot without one of the feeds is refused."""
    snapshot = create_snapshot(
        [raw_feed("kev", KEV_FILENAME, KEV)], root=tmp_path
    )
    with pytest.raises(SnapshotError, match="no epss feed"):
        await aprioritize([finding(XZ)], snapshot)


def test_prioritize_sync(snapshot):
    """The sync facade runs the engine without an event loop."""
    report = prioritize([finding(IN_KEV, cvss=[9.8])], snapshot)
    assert report.summary.P1 == 1


async def test_prioritize_in_running_loop(snapshot):
    """The sync facade points to the async entry point inside a loop."""
    with pytest.raises(RuntimeError, match="await aprioritize"):
        prioritize([finding(IN_KEV)], snapshot)


def test_fetch_snapshot(tmp_path, respx_mock):
    """Both feeds are fetched into a snapshot that loads back."""
    respx_mock.get(KEV_URL).respond(200, content=KEV)
    respx_mock.get(EPSS_URL).respond(200, content=EPSS)
    snapshot = fetch_snapshot(tmp_path)
    assert [feed.name for feed in snapshot.manifest.feeds] == ["epss", "kev"]
    assert load_snapshot(snapshot.manifest.snapshot_id, tmp_path) == snapshot
    assert not (snapshot.path / CVSS_CACHE_NAME).exists()
