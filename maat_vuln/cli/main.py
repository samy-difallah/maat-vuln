"""Command line: ``maat rank``, ``maat explain`` and ``maat snapshot``.

The CLI stays synchronous and calls the library's sync facades; it is
the only part of Maat that writes to the terminal. Each command lives in
its own module; this one assembles them into the ``maat`` app.
"""

import typer

from maat_vuln.cli.explain import explain
from maat_vuln.cli.rank import rank
from maat_vuln.cli.snapshot import snapshot_fetch, snapshot_show

app = typer.Typer(no_args_is_help=True, add_completion=False)
snapshot_app = typer.Typer(no_args_is_help=True)
app.add_typer(
    snapshot_app, name="snapshot", help="Fetch or inspect feed snapshots."
)
app.command()(rank)
app.command()(explain)
snapshot_app.command("fetch")(snapshot_fetch)
snapshot_app.command("show")(snapshot_show)


@app.callback()
def main() -> None:
    """Maat: exploitation-driven vulnerability prioritization."""
