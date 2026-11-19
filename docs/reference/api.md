# Python API

The public API of the `maat_vuln` package, generated from its docstrings. The [Python library](../guides/library.md) guide shows how the pieces fit together. Each subpackage exports its public names from its own `__init__`: import from `maat_vuln.models`, never from its submodules.

## Entry points

::: maat_vuln.prioritize

::: maat_vuln.aprioritize

::: maat_vuln.fetch_snapshot

::: maat_vuln.afetch_snapshot

::: maat_vuln.load_findings

## Input models

::: maat_vuln.models.FindingsInput

::: maat_vuln.models.Finding
    options:
      members: [id, aliases, component, cvss, sources, key]

::: maat_vuln.models.Component

::: maat_vuln.models.CvssInput

::: maat_vuln.models.Provenance

## Output models

::: maat_vuln.models.Report

::: maat_vuln.models.Decision

::: maat_vuln.models.FindingKey

::: maat_vuln.models.Explanation

::: maat_vuln.models.Flag

::: maat_vuln.models.Signals

::: maat_vuln.models.KevSignal

::: maat_vuln.models.EpssSignal

::: maat_vuln.models.CvssSignal

::: maat_vuln.models.CvssValue

::: maat_vuln.models.PolicyRef

::: maat_vuln.models.Summary

::: maat_vuln.models.Selection

## Snapshots

::: maat_vuln.snapshot.Snapshot

::: maat_vuln.snapshot.latest_snapshot

::: maat_vuln.snapshot.load_snapshot

::: maat_vuln.snapshot.list_snapshots

::: maat_vuln.snapshot.default_root

::: maat_vuln.snapshot.SnapshotError

## Adapters

::: maat_vuln.adapters.Adapter

::: maat_vuln.adapters.load_adapters

::: maat_vuln.adapters.FormatError
