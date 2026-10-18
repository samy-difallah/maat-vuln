# maat-vuln

Maât: exploitation-driven vulnerability prioritization, as a Python library first with a thin CLI on top. It ranks vulnerabilities with CISA KEV and FIRST EPSS (CVSS as a secondary signal); every verdict is explained and tied to a dated, hashed snapshot of the feeds.

The design (data contract, default policy, roadmap) is the reference for every decision:

@docs/design.md

## Scope

- Work only on the current milestone: the first roadmap milestone in `docs/design.md` that has no release yet (compare with `version` in `pyproject.toml` and `CHANGELOG.md`). Do not start features of later milestones.
- When the design doc is silent or ambiguous, ask instead of guessing. Items marked **Provisional** may be implemented as written but must stay easy to change.
- Feed endpoints and formats change: check them against the official documentation before writing a client, and keep the URL used in the code.

## Environment

- Package manager: pip + venv.
- No `requirements*.txt` — `pyproject.toml` is the single source of truth for dependencies. Never add a parallel requirements file.
- Setup: `python3 -m venv .venv && . .venv/bin/activate`
- Install: `pip install -e ".[dev]"` (aggregates `test` + `lint` + `release` groups; use `.[test]`, `.[lint]` or `.[release]` alone for a narrower install).
- Runtime stack: Pydantic v2 (single source of truth for the data contract), Typer (CLI), Rich (tables), httpx (HTTP), platformdirs (cache location). Test stack: pytest, pytest-cov, pytest-asyncio, respx.

## Layout

- Flat layout, no `src/`: the package lives directly at the repo root as `maat_vuln/`.
- Expected subpackages: `models/` (contract), `feeds/` (KEV, EPSS, CVSS clients), `snapshot/`, `policy/`, `cli/`, plus `engine.py`. Create them progressively, as each feature is implemented — do not pre-create empty subpackages or empty test directories/files.
- `tests/` mirrors the package structure. No `__init__.py` in `tests/` or its subdirectories. Each test directory has its own `conftest.py` when it needs fixtures.
- Each subpackage's `__init__.py` re-exports its public symbols via `__all__` (e.g. `models/__init__.py` re-exports `Finding`, `Decision`). Code outside that subpackage imports from the subpackage itself (`from maat_vuln.models import Finding`), never by reaching into the submodule directly (`from maat_vuln.models.finding import Finding`). Cross-imports within the same subpackage may use the direct submodule path.
- This convention is enforced by `import-linter` (`[tool.importlinter]` in pyproject.toml, run via `lint-imports`): one `forbidden` contract per subpackage bars every *other* subpackage (and `tests/`) from importing its submodules directly. Whenever a new submodule with public exports is created, add it to the relevant contract's `forbidden_modules` list in the same commit — otherwise the rule silently does not cover it.
- JSON Schemas generated from the Pydantic models live in `schemas/` and are committed; CI fails if they drift from the models.

## Code style

Config lives in `pyproject.toml`. Rules are never disabled to make code pass; the code changes instead.

- Line length: 79 (PEP 8, not Black's 88).
- Docstrings: Google convention, required on every module (including test files and `conftest.py`) and every function/class/method.
- Blank line after a module docstring, before the first import/statement.
- No blank line after a function/method docstring (`D202`, enforced, not disabled).
- `# pragma: no cover` is for genuinely non-testable infrastructure lines only (e.g. reading package version via `importlib.metadata`) — not a shortcut to dodge the coverage threshold.
- The library never prints; only `cli/` writes to the terminal.
- Thresholds, rule IDs and flag names are named constants, never inline literals.
- Determinism: stable sort orders, RFC 3339 UTC timestamps, uppercase vulnerability IDs.

## Type hints

Enforced by ruff `ANN` rules — never disabled to make code pass.

- Every function, method, and `__init__` must have full annotations: every parameter and the return type, including `-> None` where nothing is returned.
- Use built-in generics (`list[str]`, `dict[str, int]`), not `List`/`Dict` from `typing` (PEP 585).
- Use `X | None`, not `Optional[X]` (PEP 604).
- Pydantic model fields are typed directly on the class body; do not re-annotate them in a custom `__init__`.
- `Any` is a last resort, not a convenience — prefer a precise type, a `TypeVar`, or a `Protocol`.
- Exception: `tests/**` is exempt from `ANN` (`per-file-ignores` in `pyproject.toml`). Docstrings are still required there.

## Comments

- Comments explain why a choice was made, not what the code does.
- No commented-out code committed, ever — delete it, Git keeps the history.
- Skip comments that restate the obvious.

## Tests

- `pytest`, with `--import-mode=importlib`.
- Coverage via `pytest-cov`, threshold `fail_under = 80` in `pyproject.toml`.
- Run: `pytest` (all config comes from `pyproject.toml`, no flags needed).
- Tests never hit the network: mock HTTP with respx and use small committed fixtures (trimmed real feed samples) next to the tests that use them.

## Commits and branches

- Conventional Commits for commit messages and pull request titles: `^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9._/-]+\))?!?: .{1,100}`. Commit messages are checked locally by the pre-commit `commit-msg` hook; PR titles are not checked automatically, so get them right by hand.
- Branch names: `^(feature|fix|hotfix|release|docs|chore|refactor|test|ci|build|perf|style)/[a-z0-9]+(?:[-.][a-z0-9]+)*$`
- Group commits by unit of meaning, not by file — never one giant commit, never one commit per file.
- `develop` is the default branch; `main` holds the latest stable release only. Both are protected by repository rulesets: PR required, no direct or force push, no deletion, `lint` and `test` checks required.
- All other branches are ephemeral: force pushes are blocked everywhere (no `push --force` after a rebase or an amend), and head branches are deleted automatically once their PR is merged.
- Merge methods (rebase merging is disabled):
  - ephemeral branch → `develop`: **squash**. The PR title becomes the commit subject and the PR description its body, so both are what git-cliff and the history keep.
  - `release/X.Y.Z` or `hotfix/<name>` → `main`: **merge commit** (the only method the `main` ruleset allows).
  - `main` → `develop` (merge back): **merge commit**. The `develop` ruleset allows both squash and merge, so choosing the right one here is a convention.
- Pull requests: the description follows `.github/PULL_REQUEST_TEMPLATE.md` (`## Changes`, one bullet per logical change as `**type(scope)**` — what and why; `## Tests`, files/cases, `pytest` result, coverage).
- `CONTRIBUTING.md` is the contributor-facing version of these rules: when a convention here changes, update it in the same commit.

## Pre-commit

- `.pre-commit-config.yaml` mirrors the CI `lint` job: `ruff check`, `ruff format --check`, `lint-imports`, schema drift check, plus a `commit-msg` hook validating Conventional Commits. `pytest` stays out of it (CI runs it).
- `pre-commit` belongs to the `lint` dependency group. Install the hooks with `pre-commit install --hook-type pre-commit --hook-type commit-msg`.
- When a check is added to the CI `lint` job, add it to pre-commit in the same commit.

## Documentation

- Markdown files: no hard-wrapped lines (one paragraph or list item per line), exactly one blank line between blocks, headings in sentence case, and text after a `**Label**:` continues in lowercase unless it starts with a proper noun.
- Links in `README.md` are absolute URLs to the `main` branch (`blob/main/` for files, `tree/main/` for directories): it is also the PyPI project page.
- Never document an unreleased feature as available. The roadmap section of the README may announce planned versions as planned.
- Do not mention other projects as consumers of Maât in public documentation.

## CI

`.github/workflows/ci.yml` runs on `push`/`pull_request` to `main`/`develop` only: a `lint` job (`ruff check` + `ruff format --check` + `lint-imports` + schema drift check) on Python 3.12 and a `test-matrix` job (`pytest`) on Python 3.12, 3.13 and 3.14, summed up by a `test` job. Each installs only its own dependency group (`.[lint]` or `.[test]`), not `.[dev]`.

The rulesets require the `lint` and `test` checks by name: never rename these jobs.

`.github/workflows/publish.yml` publishes through PyPI trusted publishing (OIDC, no token): a push to `release/**` publishes a `X.Y.Z.devN` rehearsal to TestPyPI (environment `testpypi`); a `vX.Y.Z` tag checks it matches `pyproject.toml`, publishes to PyPI (environment `pypi`) and creates the GitHub release with the version's `CHANGELOG.md` section as notes.

## Releases

Versions follow SemVer `X.Y.Z`, configured in `[tool.git-cliff.bump]` with `features_always_bump_minor = true` and `breaking_always_bump_major = false`: until 1.0, `fix` bumps the patch version, while `feat` and breaking changes bump the minor one. A roadmap milestone `v0.N` is the `0.N.x` release series, so the features of one milestone ship together in one release. The version is hardcoded in `pyproject.toml`; `CHANGELOG.md` is generated by git-cliff (`[tool.git-cliff]` in `pyproject.toml`), except the hand-written 0.1.0 entry.

1. Create `release/X.Y.Z` from `develop` (hotfix: `hotfix/<name>` from `main`).
2. Set `version` in `pyproject.toml` to `git cliff --bumped-version` (without the `v`), then run `git cliff --unreleased --tag vX.Y.Z --prepend CHANGELOG.md` and review the new section. Commit both together as `chore(release): prepare X.Y.Z`.
3. Push the branch: the TestPyPI rehearsal runs. Install it in a clean venv (`pip install --pre --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ maat-vuln`) and run `maat` on a few CVE IDs.
4. Open the PR from `release/X.Y.Z` into `main` and merge it with a merge commit. Make sure the changelog date is the release day.
5. Tag the merge commit on `main` (`git tag -a vX.Y.Z -m vX.Y.Z`) and push the tag: PyPI publishing and the GitHub release follow. Release tags `v*` cannot be moved or deleted.
6. Open a PR from `main` into `develop` and merge it with a merge commit, never a squash: git-cliff only sees tags that are ancestors of the current branch. If it conflicts, resolve on a temporary branch created from `main` (`git merge develop`, fix, PR into `develop` with a merge commit), never by committing to `main`.

## Working with Claude Code

- Plan first (plan mode), then implement in small steps; run `ruff check`, `ruff format --check`, `lint-imports` and `pytest` after each step.
- Use available skills when their description matches the task; do not ask before using one.
