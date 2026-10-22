"""CVSS lookups in CIRCL Vulnerability-Lookup.

CVEs are looked up in batches through the bulk endpoint, reading both
the CVE record (CNA and ADP metrics) and the NVD record of each CVE.
A CVE whose lookup failed is left out of the result, so it is not
cached and a later run retries it.
"""

import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime

import httpx
from pydantic import BaseModel, JsonValue, ValidationError

from maat_vuln.feeds.http import FetchError, HttpClient
from maat_vuln.models import CvssScore, CvssValue, CvssVersion
from maat_vuln.snapshot import CvssEntry

# Documented at https://vulnerability.circl.lu/api/
CVSS_LOOKUP_URL = "https://vulnerability.circl.lu/api/vulnerability/bulk"
# Two records per CVE, and the endpoint takes at most 100 IDs.
CVSS_BATCH_SIZE = 50
NVD_PREFIX = "fkie_"
SOURCE = "vulnerability-lookup"
CVE_RECORD_FIELDS: dict[str, CvssVersion] = {
    "cvssV4_0": "4.0",
    "cvssV3_1": "3.1",
    "cvssV3_0": "3.0",
    "cvssV2_0": "2.0",
}
NVD_RECORD_FIELDS: dict[str, CvssVersion] = {
    "cvssMetricV40": "4.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV30": "3.0",
    "cvssMetricV2": "2.0",
}


class _Cvss(BaseModel):
    """CVSS object of either record; fields Maât does not use are ignored."""

    baseScore: CvssScore  # noqa: N815 (field name of the record schemas)
    vectorString: str | None = None  # noqa: N815


class _CveMetric(BaseModel):
    """Metric of a CVE record, holding at most one CVSS version."""

    cvssV4_0: _Cvss | None = None  # noqa: N815
    cvssV3_1: _Cvss | None = None  # noqa: N815
    cvssV3_0: _Cvss | None = None  # noqa: N815
    cvssV2_0: _Cvss | None = None  # noqa: N815


class _CveContainer(BaseModel):
    """CNA or ADP container of a CVE record."""

    metrics: list[_CveMetric] = []


class _CveContainers(BaseModel):
    """Containers of a CVE record; a rejected CVE has no metrics."""

    cna: _CveContainer = _CveContainer()
    adp: list[_CveContainer] = []


class _CveRecord(BaseModel):
    """CVE JSON 5 record."""

    containers: _CveContainers


class _NvdMetric(BaseModel):
    """NVD metric, primary or secondary."""

    cvssData: _Cvss  # noqa: N815


class _NvdMetrics(BaseModel):
    """NVD metrics, one list per CVSS version."""

    cvssMetricV40: list[_NvdMetric] = []  # noqa: N815
    cvssMetricV31: list[_NvdMetric] = []  # noqa: N815
    cvssMetricV30: list[_NvdMetric] = []  # noqa: N815
    cvssMetricV2: list[_NvdMetric] = []  # noqa: N815


class _NvdRecord(BaseModel):
    """NVD record, as mirrored by FKIE."""

    metrics: _NvdMetrics = _NvdMetrics()


class _BulkEntry(BaseModel):
    """Answer for one ID; ``None`` when Vulnerability-Lookup lacks it."""

    id: str
    vulnerability: dict[str, JsonValue] | None


class _BulkAnswer(BaseModel):
    """Answer of the bulk endpoint."""

    data: list[_BulkEntry]


def _values(
    cve_record: dict[str, JsonValue] | None,
    nvd_record: dict[str, JsonValue] | None,
) -> list[CvssValue] | None:
    """Return the CVSS values of both records, without duplicates.

    Raises:
        ValidationError: a record is malformed.
    """
    found: list[tuple[CvssVersion, _Cvss]] = []
    if cve_record is not None:
        containers = _CveRecord.model_validate(cve_record).containers
        found += [
            (version, cvss)
            for container in [containers.cna, *containers.adp]
            for metric in container.metrics
            for field, version in CVE_RECORD_FIELDS.items()
            if (cvss := getattr(metric, field)) is not None
        ]
    if nvd_record is not None:
        metrics = _NvdRecord.model_validate(nvd_record).metrics
        found += [
            (version, metric.cvssData)
            for field, version in NVD_RECORD_FIELDS.items()
            for metric in getattr(metrics, field)
        ]
    # Values from both records share one source, so equal ones are one.
    unique = dict.fromkeys(
        (version, cvss.baseScore, cvss.vectorString) for version, cvss in found
    )
    return [
        CvssValue(
            version=version, base_score=score, vector=vector, source=SOURCE
        )
        for version, score, vector in unique
    ] or None


async def _lookup_batch(
    client: HttpClient, cves: list[str]
) -> list[CvssEntry]:
    """Look up one batch; CVEs whose answer is unusable are left out."""
    nvd_ids = {cve: NVD_PREFIX + cve.lower() for cve in cves}
    ids = [id_ for cve in cves for id_ in (cve, nvd_ids[cve])]
    try:
        response = await client.post(CVSS_LOOKUP_URL, json={"ids": ids})
        response.raise_for_status()
        answer = _BulkAnswer.model_validate_json(response.content)
    except (FetchError, httpx.HTTPStatusError, ValidationError):
        return []
    retrieved_at = datetime.now(UTC)
    records = {entry.id: entry.vulnerability for entry in answer.data}
    entries = []
    for cve in cves:
        if cve not in records or nvd_ids[cve] not in records:
            continue
        try:
            values = _values(records[cve], records[nvd_ids[cve]])
        except ValidationError:
            continue
        entries.append(
            CvssEntry(id=cve, retrieved_at=retrieved_at, values=values)
        )
    return entries


async def lookup_cvss(
    client: HttpClient, cves: Iterable[str]
) -> list[CvssEntry]:
    """Look up the CVSS values of the given CVEs, in sorted order.

    A CVE missing from the result could not be looked up; a CVE whose
    ``values`` is ``None`` has no CVSS in Vulnerability-Lookup.
    """
    unique = sorted(set(cves))
    batches = [
        unique[start : start + CVSS_BATCH_SIZE]
        for start in range(0, len(unique), CVSS_BATCH_SIZE)
    ]
    results = await asyncio.gather(
        *(_lookup_batch(client, batch) for batch in batches)
    )
    return [entry for result in results for entry in result]
