# Contributing to Maat

Thanks for your interest in Maat. This guide covers the conventions every change follows. The design document, [docs/design.md](docs/design.md), is the reference for every decision: read it before proposing a feature.

Everyone taking part in the project follows the [code of conduct](CODE_OF_CONDUCT.md).

## Issues

Report bugs and propose features through the [issue forms](https://github.com/samy-difallah/maat-vuln/issues/new/choose). Security vulnerabilities are reported privately, as described in [SECURITY.md](SECURITY.md), never in a public issue.

## Scope

Work happens one roadmap milestone at a time: the current milestone is the first one in the design document that has no release yet. Features of later milestones are not accepted ahead of time. When the design document is silent or ambiguous, open an issue to discuss it before writing code.

## Setup

Maat uses pip and a virtual environment. `pyproject.toml` is the single source of truth for dependencies: there is no `requirements*.txt`, and none should be added.

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pre-commit install --hook-type pre-commit --hook-type commit-msg
```

The `dev` extra aggregates `test`, `lint`, `release` and `docs`; install one of them alone (`.[test]`, `.[lint]`, `.[release]` or `.[docs]`) for a narrower environment. The pre-commit hooks run the tools from the virtual environment, so activate it before committing.

## Checks

Run these before pushing; CI runs the same ones:

```sh
ruff check
ruff format --check
lint-imports
python scripts/generate_schemas.py --check
pytest
```

The pre-commit hooks mirror the CI `lint` job (`ruff check`, `ruff format --check`, `lint-imports`, schema drift check) and validate commit messages. `pytest` is left to CI. When a check is added to the CI `lint` job, it is added to pre-commit in the same commit.

The JSON Schemas in `schemas/` are generated from the Pydantic models and committed: after changing a model, regenerate them with `python scripts/generate_schemas.py` and commit them with the change.

## Branches

`develop` is the default branch; `main` holds the latest stable release only. Both are protected: changes go through a pull request with the `lint` and `test` checks passing. Pull requests also wait for the CodeQL code scanning analysis, which GitHub runs on every push to them, and cannot merge if it finds new errors or new security alerts of high severity or above.

Branch names follow `^(feature|fix|hotfix|release|docs|chore|refactor|test|ci|build|perf|style)/[a-z0-9]+(?:[-.][a-z0-9]+)*$`, for example `feature/kev-client` or `fix/epss-date-parsing`. Branches are deleted automatically once merged.

Force pushes are blocked everywhere: do not rebase or amend commits that are already pushed, push new commits instead.

## Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/): `^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9._/-]+\))?!?: .{1,100}`. The `commit-msg` hook checks them locally.

Group commits by unit of meaning, not by file: neither one giant commit nor one commit per file.

## Pull requests

- **Title**: a Conventional Commits subject as well. It is not checked automatically, so get it right by hand: on merge into `develop` it becomes the commit subject that the changelog keeps.
- **Description**: follow the template exactly, without emojis. Under `## Changes`, one bullet per commit, in commit order, as `**type(scope)**` — what and why; release and hotfix pull requests list every commit they bring into `main`, each ending with its pull request reference (`— what and why (#51).`). Under `## Tests`, `**Files**:` with one sub-bullet per modified test file and what its cases cover (`- **Files**: none.` when no test changed), then the `pytest` result and the coverage (`97%`), each on its own line. Every list item ends with a period, except `**Files**:` when it introduces its sub-list; headings never do.
- **Merge method**: pull requests into `develop` are squashed: the title becomes the commit subject, which git-cliff turns into the changelog line, and GitHub fills the body with the list of the branch's commits. Release and hotfix branches are merged into `main` with a merge commit, and `main` is merged back into `develop` with a merge commit, never a squash.
- **Dependabot**: it opens a monthly `ci(deps)` pull request for GitHub Actions, left out of the changelog, and a `fix(deps)` pull request when a security advisory affects a dependency, which raises its minimum version in `pyproject.toml`. It leaves the example project of `docs/examples/project` alone: that project is vulnerable on purpose, and its scans are committed. Its branch names and descriptions are its own: they are exempt from the conventions above, but its titles follow Conventional Commits.

## Code layout

- The package lives at the repository root as `maat_vuln/` (no `src/`). Subpackages are created when a feature needs them, never in advance.
- Each subpackage re-exports its public symbols from its `__init__.py` via `__all__`. Code outside a subpackage imports from the subpackage (`from maat_vuln.models import Finding`), never from its submodules. `import-linter` enforces this: when you add a submodule with public exports, add it to the `forbidden_modules` of its subpackage's contract in `pyproject.toml`, in the same commit.
- The library never prints; only the CLI writes to the terminal.
- Thresholds, rule IDs and flag names are named constants, never inline literals.
- Output is deterministic: stable sort orders, RFC 3339 UTC timestamps, uppercase vulnerability IDs.

## Code style

The ruff configuration in `pyproject.toml` is authoritative. Rules are never disabled to make code pass: the code changes instead.

- Line length is 79.
- Every module (test files and `conftest.py` included), class, function and method has a Google-style docstring.
- Every function and method is fully annotated, including `-> None`. Use built-in generics (`list[str]`) and `X | None`. `Any` is a last resort. Tests are exempt from annotations, not from docstrings.
- Comments explain why, not what. Commented-out code is never committed.
- `# pragma: no cover` is reserved for genuinely untestable infrastructure lines, not for reaching the coverage threshold.

## Tests

- `tests/` mirrors the package structure, without `__init__.py` files. A test directory gets its own `conftest.py` when it needs fixtures.
- `tests/examples/` is the exception: it runs `maat rank` end to end, offline, on the files of `docs/examples/`. A known gap is a strict `xfail` test asserting the expected behavior, so its fix makes the test pass and the marker must then be removed.
- Coverage must stay at or above 80%.
- Tests never hit the network: mock HTTP with respx and use small committed fixtures (trimmed real feed samples) in a `fixtures/` directory beside the tests that use them.

## Documentation

Markdown files use one line per paragraph or list item (no hard wrapping), exactly one blank line between blocks and sentence-case headings. Text after a `**Label**:` continues in lowercase unless it starts with a proper noun.

Links in `README.md` are absolute URLs to the `main` branch, because the README is also the PyPI project page. Unreleased features are never documented as available; the README roadmap may announce them as planned.

The [documentation site](https://maat-vuln.readthedocs.io/) is built with Zensical and mkdocstrings from `docs/`. Read the Docs serves the latest release by default and builds a preview of every pull request. A change that users can see updates the matching pages in the same pull request. Check the site before pushing, and preview it while writing:

```sh
zensical build --strict
zensical serve
```

## Releases

Versions follow SemVer. Until 1.0, `fix` bumps the patch version, while `feat` and breaking changes bump the minor one. A roadmap milestone `v0.N` is the `0.N.x` release series. `CHANGELOG.md` is generated by git-cliff from the commit history.

Maintainers release as follows:

1. Create `release/X.Y.Z` from `develop` (for a hotfix: `hotfix/<name>` from `main`).
2. Set `version` in `pyproject.toml` to `git cliff --bumped-version` (without the `v`), run `git cliff --unreleased --tag vX.Y.Z --prepend CHANGELOG.md` and review the new section. Commit both as `chore(release): prepare X.Y.Z`.
3. Push the branch: a `X.Y.Z.devN` rehearsal is published to TestPyPI. Install it in a clean virtual environment (`pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ maat-vuln==X.Y.Z.devN`, with the version the workflow published; `--pre` would also pull pre-releases of the dependencies) and run `maat` on a few CVE IDs.
4. Open the pull request from `release/X.Y.Z` into `main` and merge it with a merge commit. Make sure the changelog date is the release day.
5. Tag the merge commit on `main` (`git tag -a vX.Y.Z -m vX.Y.Z`) and push the tag: PyPI publishing and the GitHub release follow. Release tags cannot be moved or deleted.
6. Open a pull request from `main` into `develop` and merge it with a merge commit. If it conflicts, resolve it on a temporary branch created from `main` (`git merge develop`, fix, pull request into `develop` with a merge commit), never by committing to `main`.
