"""CISA Known Exploited Vulnerabilities (KEV) catalog.

The full catalog is fetched as one JSON file and stored as is in the
snapshot; signals are then read back from that file.
"""

from datetime import UTC, date, datetime

from pydantic import BaseModel, ValidationError

from maat_vuln.feeds.http import FetchError, HttpClient
from maat_vuln.models import KevSignal, VulnId
from maat_vuln.snapshot import RawFeed

# Documented at https://www.cisa.gov/known-exploited-vulnerabilities-catalog
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_FEED_NAME = "kev"
KEV_FILENAME = "kev.json"
RANSOMWARE_KNOWN = "Known"


class _KevEntry(BaseModel):
    """Catalog entry; fields Maat does not use are ignored."""

    cveID: VulnId  # noqa: N815 (field name of the CISA schema)
    dateAdded: date  # noqa: N815
    dueDate: date  # noqa: N815
    # Optional in the CISA schema; "Unknown" is its value for no evidence.
    knownRansomwareCampaignUse: str = "Unknown"  # noqa: N815


class _KevCatalog(BaseModel):
    """KEV catalog file."""

    catalogVersion: str  # noqa: N815
    dateReleased: str  # noqa: N815
    vulnerabilities: list[_KevEntry]


async def fetch_kev(client: HttpClient) -> RawFeed:
    """Download the KEV catalog, checked to parse before it is stored.

    Raises:
        FetchError: the request failed or the catalog is malformed.
    """
    response = await client.get(KEV_URL)
    if not response.is_success:
        raise FetchError(f"HTTP {response.status_code} from {KEV_URL}")
    try:
        catalog = _KevCatalog.model_validate_json(response.content)
    except ValidationError as error:
        raise FetchError(f"malformed KEV catalog from {KEV_URL}") from error
    return RawFeed(
        name=KEV_FEED_NAME,
        url=KEV_URL,
        filename=KEV_FILENAME,
        retrieved_at=datetime.now(UTC),
        version={
            "catalogVersion": catalog.catalogVersion,
            "dateReleased": catalog.dateReleased,
        },
        content=response.content,
    )


def parse_kev(content: bytes) -> dict[str, KevSignal]:
    """Map each CVE in the catalog to its KEV signal.

    A CVE missing from the mapping is not in KEV.
    """
    catalog = _KevCatalog.model_validate_json(content)
    return {
        entry.cveID: KevSignal(
            in_kev=True,
            date_added=entry.dateAdded,
            due_date=entry.dueDate,
            known_ransomware_campaign_use=(
                entry.knownRansomwareCampaignUse == RANSOMWARE_KNOWN
            ),
        )
        for entry in catalog.vulnerabilities
    }
