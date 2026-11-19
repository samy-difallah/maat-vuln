# Configuration

Every setting has a sensible default, so Maat needs no configuration. Settings can be changed for one run with a flag, for a shell session or a CI job with an environment variable, or for a project with a `maat.toml` file. None of them changes a verdict: they only change where data is kept, how it is fetched and what is shown.

## Precedence

For each setting, the first of these that is set wins:

1. The command-line flag.
2. The `MAAT_*` environment variable.
3. The config file.
4. The default.

## Config file

Maat reads `maat.toml` from the current directory when it exists, or the file given with `--config FILE`:

```toml
cache_dir = ".maat-cache"
concurrency = 4
max_age = 12
stale_after = 48
format = "json"
min_priority = "HIGH"
```

| Key | Type | Default | Effect |
|---|---|---|---|
| `cache_dir` | string | the user cache | directory holding the `snapshots/` directory; relative to the config file's directory |
| `concurrency` | integer ≥ 1 | 8 | maximum simultaneous CVSS lookup requests (`rank`) |
| `max_age` | integer ≥ 1 | none | reuse the latest snapshot only if it is younger than this many hours (`rank`, `explain`) |
| `stale_after` | integer ≥ 1 | 24 | age in hours past which reusing the latest snapshot warns |
| `format` | `table` or `json` | `table` | output format of every command that has `--format` |
| `min_priority` | `CRITICAL`, `HIGH`, `MEDIUM` or `LOW` | none | keep the decisions of this priority or above (`rank`) |

The file is strict: an unknown key, a wrong type or invalid TOML is an error, reported even under `maat rank -q`, since the file is read before the command runs.

`--config FILE` replaces the lookup of `./maat.toml`: only its file is read, and keys it does not set fall back to their defaults, never to `./maat.toml`. A missing `--config` file is an error. There is no command to read or write the file.

## Environment variables

Every key that has a flag can also be set as an environment variable:

| Variable | Flag |
|---|---|
| `MAAT_CACHE_DIR` | `--cache-dir` |
| `MAAT_CONCURRENCY` | `--concurrency` |
| `MAAT_MAX_AGE` | `--max-age` |
| `MAAT_FORMAT` | `--format` |
| `MAAT_MIN_PRIORITY` | `--min-priority` |

`stale_after` has no flag, so it has no variable either.

## Cache directory

Snapshots live in the user cache of the platform: `~/.cache/maat-vuln/snapshots` on Linux, `~/Library/Caches/maat-vuln/snapshots` on macOS and `%LOCALAPPDATA%\maat-vuln\Cache\snapshots` on Windows. `--cache-dir DIR`, a global option given before the command, moves them to `DIR/snapshots`:

```sh
maat --cache-dir .maat-cache rank --input trivy.json
```

A cache directory inside a project, or one restored by CI between jobs, keeps snapshots next to the reports that name them.

## Snapshot freshness

By default, `rank` and `explain` reuse the latest snapshot whatever its age, and warn on stderr when it is older than `stale_after` hours. `--max-age HOURS` fetches a new snapshot when the latest is older than that, and never warns. `--snapshot ID` and `--refresh` override a `max_age` set by a variable or the config file; on the command line, `--max-age` cannot be combined with them. See [Snapshots](../concepts/snapshots.md#which-snapshot-a-command-uses).

## Output streams

stdout only holds the result: the table, the JSON report, snapshot IDs. Progress, warnings and errors go to stderr, so `maat rank --format json > report.json` writes a clean JSON file.

`maat rank` has two more modes, as flags only, with no variable or config key:

- **`-q/--quiet`** prints nothing, in any format, errors included: only the exit code tells how the run went. Mistakes in the command line itself are still reported.
- **`-v/--verbose`** prints every processing step on stderr: the snapshot chosen and why, every request to a feed and its answer, the findings read and merged, the signals found, the CVSS lookups and the decisions made.

They cannot be combined.
