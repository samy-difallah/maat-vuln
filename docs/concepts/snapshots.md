# Snapshots

KEV and EPSS change every day. To make a verdict reproducible, Maat never ranks against the live feeds: it downloads them into a snapshot, a frozen copy identified by its hash, and every report names the snapshot it was computed against.

## What a snapshot holds

A snapshot is a directory named after its ID, under `snapshots/` in the cache directory:

```text
snapshots/
└── 806c87fc259d5cad70b977820d298c26847346dcc6a0819a6de56794a19f9979/
    ├── manifest.json
    ├── kev.json
    ├── epss.csv.gz
    └── cvss.jsonl
```

- **The feeds**: the full KEV catalog and the full EPSS score file, as downloaded. A snapshot needs nothing else to rank against KEV and EPSS.
- **`manifest.json`**: when the snapshot was created and, for each feed, the URL it came from, when it was retrieved, the SHA-256 of the file and its version (KEV catalog version and release date; EPSS model version and score date).
- **`cvss.jsonl`**: the CVSS values looked up in Vulnerability-Lookup, one line per CVE (see [below](#the-cvss-cache)).

The cache directory is the user cache of the platform (`~/.cache/maat-vuln` on Linux), unless `--cache-dir` or `cache_dir` in the [configuration](../guides/configuration.md) names another one.

## Snapshot ID

The ID is the SHA-256 of the manifest, without the ID itself, serialized as compact JSON with sorted keys. Since the manifest holds the hash of each feed file, the ID covers the feeds: two snapshots with the same ID hold the same data.

When Maat loads a snapshot, it checks that the manifest still hashes to the ID, and that each feed file still matches its hash. An altered snapshot is an error, never a silent change of verdicts.

A snapshot is written to a temporary directory and renamed once complete, so an interrupted fetch leaves no half-written snapshot behind.

## The CVSS cache

CVSS lookups are per CVE, so they cannot be downloaded in advance. Maat appends them to `cvss.jsonl` as they happen, one JSON line per CVE: its ID, when it was retrieved, and its CVSS values, or `null` when Vulnerability-Lookup has none.

This file is outside the hash: the snapshot ID never changes as the cache grows. Lines are only ever added, never rewritten, and the first line of a CVE wins, so a report keeps reproducing against its snapshot. A line that does not parse, after an interrupted write, is ignored, and its CVE is looked up again.

A failed lookup is not cached: the next run tries again.

## Which snapshot a command uses

`maat rank` and `maat explain` pick a snapshot as follows:

| Option | Snapshot used |
|---|---|
| none | the latest one, by creation date; a new one is fetched when the cache holds none |
| `--snapshot ID` | that snapshot, which must be in the cache |
| `--refresh` | a new one, fetched first |
| `--max-age HOURS` | the latest one if it is younger than `HOURS`, otherwise a new one |

When the latest snapshot is reused without `--max-age` and is older than 24 hours, a warning on stderr gives its age and suggests `--refresh` or `--max-age`. The age is set by `stale_after` in the [configuration](../guides/configuration.md). A snapshot chosen with `--snapshot` never warns.

To reproduce a report, rank again with the `snapshot_id` it records:

```sh
maat rank --input trivy.json --snapshot 806c87fc259d5cad70b977820d298c26847346dcc6a0819a6de56794a19f9979
```

## Housekeeping

Snapshots are never deleted automatically. The `maat snapshot` commands manage them:

```sh
maat snapshot fetch            # fetch a new snapshot, print its ID
maat snapshot list             # every snapshot, newest first
maat snapshot show [ID]        # one snapshot's manifest, the latest by default
maat snapshot prune --keep 5   # delete all but the 5 newest
maat snapshot rm ID...         # delete the given snapshots
```

`rm` deletes nothing when one of the IDs is unknown. See the [command line reference](../reference/cli.md#maat-snapshot) for their options.

## Network access

Maat makes three kinds of requests:

- **KEV and EPSS**: one download each, when a snapshot is fetched.
- **CVSS**: lookups in Vulnerability-Lookup, only for vulnerabilities that have no CVSS in the input and are not in the snapshot's cache yet. They go through its bulk endpoint, 50 CVEs per request, with at most 8 requests at a time by default (`--concurrency`).

Every request identifies itself with the `User-Agent` header `maat-vuln/<version>`. Requests that fail on a network error, a rate limit (HTTP 429) or a server error (HTTP 5xx) are retried a bounded number of times with exponential backoff, honoring `Retry-After`. A CVSS lookup that still fails does not fail the run: the decisions of its CVEs get the `cvss_lookup_failed` flag.

Once a snapshot is in the cache and its CVSS lookups are cached, ranking the same vulnerabilities again makes no request at all.
