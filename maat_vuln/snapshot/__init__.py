"""Snapshots: dated, hashed copies of the feeds verdicts are tied to."""

from maat_vuln.snapshot.store import (
    CVSS_CACHE_NAME,
    MANIFEST_NAME,
    CvssEntry,
    FeedRecord,
    Manifest,
    ManifestContent,
    RawFeed,
    Snapshot,
    SnapshotError,
    append_cvss,
    compute_snapshot_id,
    create_snapshot,
    default_root,
    latest_snapshot,
    load_snapshot,
    read_cvss,
)

__all__ = [
    "CVSS_CACHE_NAME",
    "MANIFEST_NAME",
    "CvssEntry",
    "FeedRecord",
    "Manifest",
    "ManifestContent",
    "RawFeed",
    "Snapshot",
    "SnapshotError",
    "append_cvss",
    "compute_snapshot_id",
    "create_snapshot",
    "default_root",
    "latest_snapshot",
    "load_snapshot",
    "read_cvss",
]
