# Command line

```text
maat [GLOBAL OPTIONS] COMMAND [ARGS]...
```

Every command accepts `--help`. Options that can also be set by an environment variable or in `maat.toml` are marked with the variable; see [Configuration](../guides/configuration.md) for the precedence.

## Global options

Global options go before the command: `maat --cache-dir DIR rank …`.

| Option | Variable | Effect |
|---|---|---|
| `-V`, `--version` | | print `maat-vuln <version>` and exit |
| `--cache-dir DIR` | `MAAT_CACHE_DIR` | keep snapshots in `DIR/snapshots` instead of the user cache |
| `--config FILE` | | read this config file instead of `./maat.toml` |

## maat rank

```text
maat rank [OPTIONS] [IDS...]
```

Rank vulnerabilities by priority, `CRITICAL` first. IDs and `--input` documents are ranked together, and findings of the same vulnerability and component merge. With no IDs and no `--input`, IDs are read from stdin, one per line. See [Inputs](../guides/inputs.md).

| Option | Variable | Effect |
|---|---|---|
| `IDS...` | | vulnerability IDs: CVE, GHSA… |
| `--input FILE` | | JSON document in a [supported format](../guides/sca-tools.md), `-` for stdin (at most once); repeat to combine several |
| `--format table\|json` | `MAAT_FORMAT` | output format, `table` by default |
| `--snapshot ID` | | rank against this snapshot |
| `--refresh` | | fetch a new snapshot first |
| `--max-age HOURS` | `MAAT_MAX_AGE` | reuse the latest snapshot only if it is younger than `HOURS`, otherwise fetch a new one; not with `--snapshot` or `--refresh` |
| `--concurrency N` | `MAAT_CONCURRENCY` | maximum simultaneous CVSS lookups, 8 by default |
| `--min-priority CRITICAL\|HIGH\|MEDIUM\|LOW` | `MAAT_MIN_PRIORITY` | keep the decisions of this priority or above; unscored ones are left out |
| `--top N` | | keep the first N decisions, after `--min-priority` |
| `-q`, `--quiet` | | print nothing, not even errors |
| `-v`, `--verbose` | | print every processing step on stderr; not with `--quiet` |

`--top` counts decisions, not vulnerabilities, and the cut is exact: it may keep some decisions of a vulnerability and leave out others. The table states how many decisions it shows out of how many; the JSON report records the selection in `selection`. In both, the summary counts every decision, selected or not.

## maat explain

```text
maat explain [OPTIONS] ID
```

Explain the priority of one vulnerability: the rule that matched, its condition, every signal value with its source, and the snapshot used. With `--format json`, it prints the [Decision](json.md#decision).

| Option | Variable | Effect |
|---|---|---|
| `ID` | | vulnerability ID, required |
| `--component PURL` | | package URL of the component |
| `--format table\|json` | `MAAT_FORMAT` | output format, `table` by default |
| `--snapshot ID` | | explain against this snapshot |
| `--refresh` | | fetch a new snapshot first |
| `--max-age HOURS` | `MAAT_MAX_AGE` | as for `rank` |

## maat snapshot

Manage the [snapshots](../concepts/snapshots.md) of the cache.

| Command | Effect |
|---|---|
| `maat snapshot fetch` | fetch the KEV and EPSS feeds into a new snapshot and print its ID |
| `maat snapshot list [--format table\|json]` | list every snapshot, newest first, with its ID, creation date, number of cached CVSS lookups and feed versions; `json` prints the list of manifests |
| `maat snapshot show [ID] [--format table\|json]` | show a snapshot, the latest by default: its ID, creation date, cached CVSS lookups, and each feed's version, URL and hash; `json` prints the manifest |
| `maat snapshot prune --keep N` | delete every snapshot but the N newest and print the deleted IDs, one per line |
| `maat snapshot rm ID...` | delete the given snapshots and print their IDs; if one ID is unknown, it is an error and nothing is deleted |

`--format` of `list` and `show` also reads `MAAT_FORMAT`.

## maat formats

```text
maat formats
```

List the input formats of the installed adapters, one name per line, sorted. Formats added by other packages appear here once installed.

## Output and exit codes

stdout holds only the result: the table, the JSON document or the snapshot IDs. Progress, warnings and errors go to stderr.

| Exit code | Meaning |
|---|---|
| 0 | success, including when some CVSS lookups failed (their decisions are flagged `cvss_lookup_failed`) |
| 1 | error: a feed could not be fetched, an input could not be read or parsed, a snapshot is unknown or altered, the config file is invalid |
| 2 | invalid command line: unknown option, invalid value, incompatible options |
