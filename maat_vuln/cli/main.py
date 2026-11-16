"""Command line: ``maat rank``, ``maat explain`` and ``maat snapshot``.

The CLI stays synchronous and calls the library's sync facades; it is
the only part of Maat that writes to the terminal. Each command lives in
its own module; this one assembles them into the ``maat`` app.
"""

from importlib.metadata import version
from pathlib import Path
from typing import Annotated

import typer

from maat_vuln.cli.explain import explain
from maat_vuln.cli.rank import rank
from maat_vuln.cli.snapshot import (
    snapshot_fetch,
    snapshot_list,
    snapshot_show,
)
from maat_vuln.snapshot import SNAPSHOTS_DIR, default_root

app = typer.Typer(no_args_is_help=True, add_completion=False)
snapshot_app = typer.Typer(no_args_is_help=True)
app.add_typer(
    snapshot_app, name="snapshot", help="Fetch, list or show feed snapshots."
)
app.command()(rank)
app.command()(explain)
snapshot_app.command("fetch")(snapshot_fetch)
snapshot_app.command("list")(snapshot_list)
snapshot_app.command("show")(snapshot_show)


def print_version(value: bool) -> None:
    """Print ``maat-vuln <version>`` and exit, when ``--version`` is given.

    Args:
        value: Whether ``--version`` was given.

    Raises:
        typer.Exit: Always when ``value`` is true, to skip the command.
    """
    if value:
        typer.echo(f"maat-vuln {version('maat-vuln')}")
        raise typer.Exit


@app.callback()
def main(
    ctx: typer.Context,
    _version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=print_version,
            is_eager=True,
            help="Print the version and exit.",
        ),
    ] = False,
    cache_dir: Annotated[
        Path | None,
        typer.Option(
            metavar="DIR",
            envvar="MAAT_CACHE_DIR",
            file_okay=False,
            help="Cache directory, the user cache if none.",
        ),
    ] = None,
) -> None:
    """Maat: exploitation-driven vulnerability prioritization."""
    # The commands read the snapshot directory from the context object.
    ctx.obj = (
        default_root() if cache_dir is None else cache_dir / SNAPSHOTS_DIR
    )
