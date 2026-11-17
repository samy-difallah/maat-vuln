"""``maat.toml``: the config file, defaults for the command line options.

Its values reach the commands through Click's ``default_map``, which
Click consults after the flags and their ``MAAT_*`` variables, so the
precedence of the design comes for free.
"""

import tomllib
from datetime import timedelta
from pathlib import Path
from typing import Literal

import typer
from pydantic import BaseModel, ConfigDict, PositiveInt

from maat_vuln.cli.common import (
    EXIT_ERROR,
    STALE_AFTER,
    STALE_AFTER_KEY,
    message,
)
from maat_vuln.models import Priority

CONFIG_FILE = "maat.toml"


class Config(BaseModel):
    """Keys of ``maat.toml``; an unknown key or a wrong type is an error."""

    model_config = ConfigDict(extra="forbid", strict=True)

    cache_dir: str | None = None
    concurrency: PositiveInt | None = None
    max_age: PositiveInt | None = None
    stale_after: PositiveInt = STALE_AFTER // timedelta(hours=1)
    format: Literal["table", "json"] | None = None
    min_priority: Priority | None = None


def _read(path: Path) -> Config:
    """Read and check a config file, exiting with a message if invalid.

    Raises:
        typer.Exit: The file cannot be read, parsed or validated.
    """
    try:
        return Config.model_validate(
            tomllib.loads(path.read_text(encoding="utf-8"))
        )
    # ValueError covers TOMLDecodeError, UnicodeDecodeError and
    # ValidationError, which message() words field by field.
    except (OSError, ValueError) as error:
        typer.echo(f"Error: {path}: {message(error)}", err=True)
        raise typer.Exit(EXIT_ERROR) from error


def load_config(ctx: typer.Context, path: Path | None) -> None:
    """Read ``--config FILE``, else ``./maat.toml``, into the context.

    Its option values become Click's ``default_map``, keyed by command
    and parameter name; ``stale_after`` goes to ``ctx.meta``, since no
    flag sets it.
    """
    if path is None and (local := Path(CONFIG_FILE)).is_file():
        path = local
    config = Config() if path is None else _read(path)
    ctx.meta[STALE_AFTER_KEY] = timedelta(hours=config.stale_after)
    values = config.model_dump(exclude_none=True)

    def pick(**params: str) -> dict[str, object]:
        """Map parameter names to the values of their config keys."""
        return {
            param: values[key]
            for param, key in params.items()
            if key in values
        }

    ranking = pick(
        output="format",
        concurrency="concurrency",
        max_age="max_age",
        min_priority="min_priority",
    )
    explaining = pick(output="format", max_age="max_age")
    showing = pick(output="format")
    ctx.default_map = {
        "rank": ranking,
        "explain": explaining,
        "snapshot": {"show": showing, "list": showing},
    }
    if config.cache_dir is not None:
        # Relative to the config file, as it is written for that place.
        ctx.default_map["cache_dir"] = (
            path.parent / Path(config.cache_dir).expanduser()
        )
