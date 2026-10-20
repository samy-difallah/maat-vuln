"""Generate the JSON Schemas of the data contract into ``schemas/``.

With ``--check``, write nothing and fail when the committed schemas drift
from the models.
"""

import argparse
import json
import sys
from pathlib import Path

from maat_vuln.models import FindingsInput, Report

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"


def render() -> dict[str, str]:
    """Render each schema file name to its JSON text."""
    schemas = {
        # Input is read, so it is validated; the report is only ever dumped.
        "input.schema.json": FindingsInput.model_json_schema(
            mode="validation"
        ),
        "report.schema.json": Report.model_json_schema(mode="serialization"),
    }
    return {
        name: json.dumps({"$schema": JSON_SCHEMA_DIALECT, **schema}, indent=2)
        + "\n"
        for name, schema in schemas.items()
    }


def main() -> None:
    """Write the schemas, or check them with ``--check``."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the committed schemas differ from the models",
    )
    args = parser.parse_args()
    rendered = render()
    if args.check:
        drifted = [
            name
            for name, text in rendered.items()
            if not (SCHEMAS_DIR / name).is_file()
            or (SCHEMAS_DIR / name).read_text() != text
        ]
        if drifted:
            sys.exit(
                f"schemas out of date: {', '.join(drifted)}; "
                "run python scripts/generate_schemas.py"
            )
        return
    SCHEMAS_DIR.mkdir(exist_ok=True)
    for name, text in rendered.items():
        (SCHEMAS_DIR / name).write_text(text)


if __name__ == "__main__":
    main()
