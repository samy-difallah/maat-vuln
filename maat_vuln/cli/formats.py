"""``maat formats``: the input formats of the installed adapters."""

import typer

from maat_vuln.adapters import load_adapters


def formats() -> None:
    """List the input formats of the installed adapters, one per line."""
    for adapter in load_adapters():
        typer.echo(adapter.name)
