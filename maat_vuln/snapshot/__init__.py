"""Snapshots: dated, hashed copies of the feeds verdicts are tied to."""

from maat_vuln.snapshot.store import (
    MANIFEST_NAME,
    FeedRecord,
    Manifest,
    ManifestContent,
    RawFeed,
    Snapshot,
    SnapshotError,
    compute_snapshot_id,
    create_snapshot,
    default_root,
    latest_snapshot,
    load_snapshot,
)

__all__ = [
    "MANIFEST_NAME",
    "FeedRecord",
    "Manifest",
    "ManifestContent",
    "RawFeed",
    "Snapshot",
    "SnapshotError",
    "compute_snapshot_id",
    "create_snapshot",
    "default_root",
    "latest_snapshot",
    "load_snapshot",
]
