"""Local store of feed snapshots, each identified by its manifest hash.

A snapshot is a directory named after its ID, holding the raw feed files
and ``manifest.json``. The manifest only lists full feed files, so the
ID never changes once the snapshot is written.
"""

import hashlib
import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from platformdirs import user_cache_path
from pydantic import Field, ValidationError

from maat_vuln.models import (
    SHA256_PATTERN,
    OutputModel,
    SnapshotId,
    UtcDatetime,
)

APP_NAME = "maat-vuln"
SNAPSHOTS_DIR = "snapshots"
MANIFEST_NAME = "manifest.json"
TMP_PREFIX = ".tmp-"

# No separator and no leading dot: a feed file stays inside its snapshot.
FILENAME_PATTERN = r"^[A-Za-z0-9_-][A-Za-z0-9._-]*$"


class SnapshotError(Exception):
    """Snapshot missing, inconsistent or impossible to write."""


@dataclass(frozen=True)
class RawFeed:
    """Feed file as retrieved, before it is stored in a snapshot."""

    name: str
    url: str
    filename: str
    retrieved_at: datetime
    version: dict[str, str]
    content: bytes


class FeedRecord(OutputModel):
    """Manifest entry of one feed file."""

    name: str
    url: str
    filename: Annotated[str, Field(pattern=FILENAME_PATTERN)]
    retrieved_at: UtcDatetime
    sha256: Annotated[str, Field(pattern=SHA256_PATTERN)]
    version: dict[str, str]


class ManifestContent(OutputModel):
    """Hashed part of the manifest."""

    created_at: UtcDatetime
    feeds: list[FeedRecord]


class Manifest(ManifestContent):
    """Content of ``manifest.json``."""

    snapshot_id: SnapshotId


@dataclass(frozen=True)
class Snapshot:
    """Snapshot directory and its manifest."""

    path: Path
    manifest: Manifest


def default_root() -> Path:
    """Return the directory holding snapshots in the user cache."""
    return user_cache_path(APP_NAME, appauthor=False) / SNAPSHOTS_DIR


def compute_snapshot_id(content: ManifestContent) -> str:
    """Return the SHA-256 of the canonical manifest, without its ID."""
    canonical = json.dumps(
        content.model_dump(
            mode="json", include=set(ManifestContent.model_fields)
        ),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def create_snapshot(
    feeds: list[RawFeed], root: Path | None = None
) -> Snapshot:
    """Store the feed files and their manifest as a new snapshot.

    Files are written to a temporary directory renamed once complete, so
    an interrupted write never leaves a snapshot under a valid ID.
    """
    root = default_root() if root is None else root
    records = sorted(
        (
            FeedRecord(
                name=feed.name,
                url=feed.url,
                filename=feed.filename,
                retrieved_at=feed.retrieved_at,
                sha256=hashlib.sha256(feed.content).hexdigest(),
                version=feed.version,
            )
            for feed in feeds
        ),
        key=lambda record: record.name,
    )
    names = {record.name for record in records}
    filenames = {record.filename for record in records}
    if len(names) != len(records) or len(filenames) != len(records):
        raise SnapshotError("feed names and file names must be unique")
    if MANIFEST_NAME in filenames:
        raise SnapshotError(f"a feed file cannot be named {MANIFEST_NAME}")
    content = ManifestContent(created_at=datetime.now(UTC), feeds=records)
    manifest = Manifest(
        **dict(content), snapshot_id=compute_snapshot_id(content)
    )
    target = root / manifest.snapshot_id
    root.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=TMP_PREFIX, dir=root))
    try:
        for feed in feeds:
            (tmp / feed.filename).write_bytes(feed.content)
        (tmp / MANIFEST_NAME).write_text(
            manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        # Same ID means same content: the existing snapshot is kept.
        if not target.exists():
            tmp.rename(target)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return Snapshot(path=target, manifest=manifest)


def load_snapshot(snapshot_id: str, root: Path | None = None) -> Snapshot:
    """Load a snapshot and check its manifest still matches its ID."""
    root = default_root() if root is None else root
    path = root / snapshot_id
    manifest_path = path / MANIFEST_NAME
    if not re.fullmatch(SHA256_PATTERN, snapshot_id) or not (
        manifest_path.is_file()
    ):
        raise SnapshotError(f"unknown snapshot {snapshot_id}")
    try:
        manifest = Manifest.model_validate_json(manifest_path.read_bytes())
    except ValidationError as error:
        raise SnapshotError(f"invalid manifest in {path}") from error
    if snapshot_id != manifest.snapshot_id or snapshot_id != (
        compute_snapshot_id(manifest)
    ):
        raise SnapshotError(f"manifest of {path} does not match its ID")
    return Snapshot(path=path, manifest=manifest)


def latest_snapshot(root: Path | None = None) -> Snapshot | None:
    """Return the most recently created snapshot, if there is one."""
    root = default_root() if root is None else root
    if not root.is_dir():
        return None
    snapshots = [
        load_snapshot(path.name, root)
        for path in root.iterdir()
        if re.fullmatch(SHA256_PATTERN, path.name)
    ]
    return max(
        snapshots,
        key=lambda snapshot: snapshot.manifest.created_at,
        default=None,
    )
