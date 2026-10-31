"""Tests for the snapshot store."""

import hashlib
import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from maat_vuln.models import CvssValue
from maat_vuln.snapshot import (
    CVSS_CACHE_NAME,
    MANIFEST_NAME,
    CvssEntry,
    RawFeed,
    SnapshotError,
    append_cvss,
    compute_snapshot_id,
    create_snapshot,
    default_root,
    latest_snapshot,
    load_snapshot,
    read_cvss,
)

RETRIEVED_AT = datetime(2026, 10, 20, 12, tzinfo=UTC)


def raw_feed(name="kev", filename="kev.json", content=b"{}"):
    """Build a raw feed file."""
    return RawFeed(
        name=name,
        url=f"https://example.org/{filename}",
        filename=filename,
        retrieved_at=RETRIEVED_AT,
        version={"catalogVersion": "2026.10.20"},
        content=content,
    )


FEEDS = [
    raw_feed("kev", "kev.json", b'{"vulnerabilities": []}'),
    raw_feed("epss", "epss.csv.gz", b"\x1f\x8b"),
]


def test_create_writes_files_and_manifest(tmp_path):
    """Feed files and manifest land in a directory named after the ID."""
    snapshot = create_snapshot(FEEDS, root=tmp_path)
    manifest = snapshot.manifest
    assert snapshot.path == tmp_path / manifest.snapshot_id
    assert manifest.snapshot_id == compute_snapshot_id(manifest)
    assert [record.name for record in manifest.feeds] == ["epss", "kev"]
    for feed in FEEDS:
        content = (snapshot.path / feed.filename).read_bytes()
        assert content == feed.content
    assert {record.sha256 for record in manifest.feeds} == {
        hashlib.sha256(feed.content).hexdigest() for feed in FEEDS
    }
    leftovers = [path.name for path in tmp_path.iterdir()]
    assert leftovers == [manifest.snapshot_id]


def test_snapshot_id_hashes_canonical_manifest(tmp_path):
    """The ID is the SHA-256 of the sorted, compact manifest sans ID."""
    snapshot = create_snapshot(FEEDS, root=tmp_path)
    stored = json.loads((snapshot.path / MANIFEST_NAME).read_text())
    del stored["snapshot_id"]
    canonical = json.dumps(stored, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode()).hexdigest()
    assert snapshot.manifest.snapshot_id == expected


def test_load_round_trip(tmp_path):
    """A created snapshot loads back with the same manifest."""
    snapshot = create_snapshot(FEEDS, root=tmp_path)
    assert load_snapshot(snapshot.manifest.snapshot_id, tmp_path) == snapshot


@pytest.mark.parametrize(
    "feeds",
    [
        [raw_feed("kev", "a.json"), raw_feed("kev", "b.json")],
        [raw_feed("kev", "a.json"), raw_feed("epss", "a.json")],
        [raw_feed("kev", MANIFEST_NAME)],
        [raw_feed("kev", CVSS_CACHE_NAME)],
    ],
)
def test_create_rejects_clashing_feeds(tmp_path, feeds):
    """Feed names and file names are unique and spare reserved names."""
    with pytest.raises(SnapshotError):
        create_snapshot(feeds, root=tmp_path)
    assert not tmp_path.exists() or not any(tmp_path.iterdir())


@pytest.mark.parametrize("filename", ["../kev.json", "a/b", ".hidden", ""])
def test_create_rejects_unsafe_filenames(tmp_path, filename):
    """A feed file name cannot leave or hide in the snapshot directory."""
    with pytest.raises(ValidationError):
        create_snapshot([raw_feed(filename=filename)], root=tmp_path)


@pytest.mark.parametrize("snapshot_id", ["a" * 64, "../" + "a" * 61])
def test_load_unknown_snapshot(tmp_path, snapshot_id):
    """An unknown or malformed ID is an error."""
    with pytest.raises(SnapshotError, match="unknown snapshot"):
        load_snapshot(snapshot_id, tmp_path)


def test_load_detects_tampered_manifest(tmp_path):
    """A manifest edited after creation no longer matches its ID."""
    snapshot = create_snapshot(FEEDS, root=tmp_path)
    manifest_path = snapshot.path / MANIFEST_NAME
    stored = json.loads(manifest_path.read_text())
    stored["created_at"] = "2000-01-01T00:00:00Z"
    manifest_path.write_text(json.dumps(stored))
    with pytest.raises(SnapshotError, match="does not match"):
        load_snapshot(snapshot.manifest.snapshot_id, tmp_path)


def test_load_detects_invalid_manifest(tmp_path):
    """A manifest that does not parse is reported as a snapshot error."""
    snapshot = create_snapshot(FEEDS, root=tmp_path)
    (snapshot.path / MANIFEST_NAME).write_text("{")
    with pytest.raises(SnapshotError, match="invalid manifest"):
        load_snapshot(snapshot.manifest.snapshot_id, tmp_path)


def test_latest_snapshot_is_newest(tmp_path):
    """The latest snapshot has the newest creation time."""
    create_snapshot(FEEDS, root=tmp_path)
    newest = create_snapshot([raw_feed(content=b"[]")], root=tmp_path)
    (tmp_path / ".tmp-leftover").mkdir()
    (tmp_path / "notes").mkdir()
    assert latest_snapshot(tmp_path) == newest


def test_latest_snapshot_none(tmp_path):
    """No snapshot yet, whether the root exists or not."""
    assert latest_snapshot(tmp_path / "missing") is None
    assert latest_snapshot(tmp_path) is None


def test_default_root_in_user_cache():
    """Snapshots live under the application's cache directory."""
    root = default_root()
    assert root.name == "snapshots"
    assert "maat-vuln" in root.parts


def cvss_entry(cve, score=None):
    """Build a CVSS lookup entry; no score means no result."""
    values = None
    if score is not None:
        values = [
            CvssValue(
                version="3.1",
                base_score=score,
                vector=None,
                source="vulnerability-lookup",
            )
        ]
    return CvssEntry(id=cve, retrieved_at=RETRIEVED_AT, values=values)


def test_cvss_cache_round_trip(tmp_path):
    """Appended lookups, with or without result, are read back."""
    snapshot = create_snapshot(FEEDS, root=tmp_path)
    assert read_cvss(snapshot) == {}
    first = [cvss_entry("CVE-2024-0001", 9.8)]
    second = [cvss_entry("CVE-2024-0002")]
    append_cvss(snapshot, first)
    append_cvss(snapshot, second)
    assert read_cvss(snapshot) == {
        "CVE-2024-0001": first[0],
        "CVE-2024-0002": second[0],
    }
    assert load_snapshot(snapshot.manifest.snapshot_id, root=tmp_path)


def test_cvss_cache_first_entry_wins(tmp_path):
    """A later lookup of a cached CVE never replaces the first one."""
    snapshot = create_snapshot(FEEDS, root=tmp_path)
    append_cvss(snapshot, [cvss_entry("CVE-2024-0001", 9.8)])
    append_cvss(snapshot, [cvss_entry("CVE-2024-0001", 5.0)])
    cached = read_cvss(snapshot)["CVE-2024-0001"]
    assert cached == cvss_entry("CVE-2024-0001", 9.8)


def test_cvss_cache_skips_torn_lines(tmp_path):
    """A line cut short by an interrupted write is ignored."""
    snapshot = create_snapshot(FEEDS, root=tmp_path)
    append_cvss(snapshot, [cvss_entry("CVE-2024-0001", 9.8)])
    with (snapshot.path / CVSS_CACHE_NAME).open("a") as cache:
        cache.write('{"id": "CVE-2024-0002", "retr\n')
    assert list(read_cvss(snapshot)) == ["CVE-2024-0001"]


def test_cvss_entry_needs_values_or_none():
    """An empty list is not a result: no result is ``None``."""
    with pytest.raises(ValidationError):
        CvssEntry(id="CVE-2024-0001", retrieved_at=RETRIEVED_AT, values=[])
