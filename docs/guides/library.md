# Python library

The command line is a thin layer over the `maat_vuln` package: everything it does is available from Python, with typed Pydantic models in and out. The [Python API](../reference/api.md) reference lists every class and function.

## Rank findings

```python
from maat_vuln import fetch_snapshot, prioritize
from maat_vuln.models import Component, Finding

snapshot = fetch_snapshot()
findings = [
    Finding(id="CVE-2021-44228"),
    Finding(
        id="GHSA-jfh8-c2jp-5v3q",
        aliases=["CVE-2021-44228"],
        component=Component(
            purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        ),
    ),
]
report = prioritize(findings, snapshot)

for decision in report.decisions:
    print(
        decision.priority,
        decision.finding_key.id,
        decision.rule_id,
        decision.flags,
    )
print(report.summary)
```

`prioritize(findings, snapshot)` merges the findings, resolves their signals against the snapshot, looks up missing CVSS values and returns a `Report`: the same object the command line prints as JSON. `concurrency` caps simultaneous CVSS lookups (8 by default).

`report.model_dump_json(indent=2)` gives the JSON report, as described in [JSON output](../reference/json.md).

## Async

The core is asynchronous. `aprioritize` and `afetch_snapshot` are the coroutines behind `prioritize` and `fetch_snapshot`:

```python
from maat_vuln import afetch_snapshot, aprioritize


async def rank(findings):
    snapshot = await afetch_snapshot()
    return await aprioritize(findings, snapshot)
```

`prioritize` and `fetch_snapshot` run their coroutine with `asyncio.run()`. Called from a running event loop, in a Jupyter notebook or an async web framework for instance, they raise a `RuntimeError` pointing to the async version: use `await aprioritize(...)` there.

## Snapshots

`fetch_snapshot()` downloads KEV and EPSS into a new snapshot. To reuse one, as the command line does, use the functions of `maat_vuln.snapshot`:

```python
from maat_vuln import fetch_snapshot, prioritize
from maat_vuln.snapshot import latest_snapshot, load_snapshot

snapshot = latest_snapshot() or fetch_snapshot()
same = load_snapshot(report.snapshot_id)
```

Every snapshot function takes an optional `root`: the directory holding the snapshots, `default_root()` (the user cache) when not given. The command line's `--cache-dir DIR` is `root=DIR / "snapshots"`.

`load_snapshot` checks that the manifest still hashes to the ID, and raises `SnapshotError` otherwise, or when the snapshot is missing. `prioritize` raises it when a feed file no longer matches its hash.

## Scanner outputs

`load_findings(document)` detects the format of a parsed JSON document, as `--input` does, and returns its findings:

```python
import json
from pathlib import Path

from maat_vuln import load_findings

findings = [
    *load_findings(json.loads(Path("trivy.json").read_text())),
    *load_findings(json.loads(Path("grype.json").read_text())),
]
```

A document that matches no format, or several, raises `FormatError`, a `ValueError`; an invalid document of a known format raises Pydantic's `ValidationError`. Findings from several documents can simply be concatenated: `prioritize` merges them.

## Logging

The library never prints. It logs through the standard `logging` module, under the `maat_vuln` logger, and configures no handler: configure one to see what it does.

```python
import logging

logging.basicConfig(level=logging.INFO)
```

At `DEBUG` level it logs every step that `maat rank -v` shows.

## Adding an input format

Input formats are adapters registered under the `maat_vuln.adapters` [entry point group](https://packaging.python.org/en/latest/specifications/entry-points/). Maat's own formats are registered that way, so another package can add a format without any change to Maat.

An adapter is any object with:

- `name`: the format name, shown by `maat formats` and used as the tool name when a document names none.
- `detect(document) -> bool`: whether a parsed JSON document is in this format, from its top-level structure. A document must match exactly one installed adapter.
- `parse(document) -> list[Finding]`: the findings of the document. Adapters make no network request.

```python
# my_package/acme.py
from maat_vuln.models import Finding, Provenance


class AcmeAdapter:
    """Findings of the ACME scanner's JSON report."""

    name = "acme"

    def detect(self, document):
        return isinstance(document, dict) and "acme_report" in document

    def parse(self, document):
        return [
            Finding(
                id=issue["cve"],
                sources=[Provenance(tool=self.name, original_id=issue["cve"])],
            )
            for issue in document["acme_report"]["issues"]
        ]


ADAPTER = AcmeAdapter()
```

```toml
# pyproject.toml of my_package
[project.entry-points."maat_vuln.adapters"]
acme = "my_package.acme:ADAPTER"
```

Once `my_package` is installed, `maat formats` lists `acme`, and `maat rank --input` and `load_findings` read its documents.
