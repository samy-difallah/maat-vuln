"""FIRST Exploit Prediction Scoring System (EPSS) scores.

The daily file of every score is fetched as one gzipped CSV and stored
as is in the snapshot; signals are then read back from that file.
"""

import csv
import gzip
import io
from collections.abc import Iterable
from datetime import UTC, datetime

from pydantic import BaseModel, TypeAdapter

from maat_vuln.feeds.http import FetchError, HttpClient
from maat_vuln.models import EpssSignal, Probability, UtcDatetime, VulnId
from maat_vuln.snapshot import RawFeed

# Documented at https://www.first.org/epss/data
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_FEED_NAME = "epss"
EPSS_FILENAME = "epss.csv.gz"
COMMENT_PREFIX = "#"
COLUMNS = ["cve", "epss", "percentile"]


class _EpssHeader(BaseModel):
    """Version info of the leading comment line; other keys are ignored."""

    model_version: str
    score_date: UtcDatetime


# Tuples, not models: validating ~400k rows as models takes seconds.
_ROWS = TypeAdapter(list[tuple[VulnId, Probability, Probability]])


def _read(
    content: bytes,
) -> tuple[dict[str, str], list[tuple[str, float, float]]]:
    """Return the raw version info and the rows of the gzipped CSV.

    Raises:
        ValueError: the file is not a well-formed EPSS score file.
    """
    try:
        text = gzip.decompress(content).decode()
    except (OSError, EOFError, UnicodeDecodeError) as error:
        raise ValueError("not a gzipped UTF-8 file") from error
    comment, _, body = text.partition("\n")
    if not comment.startswith(COMMENT_PREFIX):
        raise ValueError("missing the model version comment line")
    # e.g. "#model_version:v2026.06.15,score_date:2026-10-22T12:00:12Z"
    version = dict(
        item.partition(":")[::2]
        for item in comment.removeprefix(COMMENT_PREFIX).strip().split(",")
    )
    _EpssHeader.model_validate(version)
    reader = csv.reader(io.StringIO(body))
    if next(reader, None) != COLUMNS:
        raise ValueError(f"columns are not {COLUMNS}")
    return version, _ROWS.validate_python(list(reader))


async def fetch_epss(client: HttpClient) -> RawFeed:
    """Download the current EPSS scores, checked to parse before storing.

    Raises:
        FetchError: the request failed or the file is malformed.
    """
    response = await client.get(EPSS_URL)
    if not response.is_success:
        raise FetchError(f"HTTP {response.status_code} from {EPSS_URL}")
    try:
        version, _ = _read(response.content)
    except ValueError as error:
        raise FetchError(f"malformed EPSS scores from {EPSS_URL}") from error
    return RawFeed(
        name=EPSS_FEED_NAME,
        url=EPSS_URL,
        filename=EPSS_FILENAME,
        retrieved_at=datetime.now(UTC),
        version={key: version[key] for key in _EpssHeader.model_fields},
        content=response.content,
    )


def parse_epss(content: bytes, cves: Iterable[str]) -> dict[str, EpssSignal]:
    """Map each of the given CVEs that is scored to its EPSS signal.

    Only the asked CVEs get a signal, as building one per row of the
    feed takes seconds. A CVE missing from the mapping has no EPSS score.
    """
    version, rows = _read(content)
    header = _EpssHeader.model_validate(version)
    wanted = set(cves)
    return {
        cve: EpssSignal(
            probability=probability,
            percentile=percentile,
            model_version=header.model_version,
            score_date=header.score_date.date(),
        )
        for cve, probability, percentile in rows
        if cve in wanted
    }
