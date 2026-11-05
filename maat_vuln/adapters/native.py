"""Native ``maat`` input format: the input document of the data contract."""

from pydantic import JsonValue

from maat_vuln.models import Finding, FindingsInput

FINDINGS_KEY = "findings"


class NativeAdapter:
    """Reads Maat's own input document (``schema_version``, ``findings``)."""

    name = "maat"

    def detect(self, document: JsonValue) -> bool:
        """Recognize a JSON object with a top-level ``findings`` key."""
        return isinstance(document, dict) and FINDINGS_KEY in document

    def parse(self, document: JsonValue) -> list[Finding]:
        """Validate the document against the input contract.

        Raises:
            ValidationError: the document breaks the input contract.
        """
        return FindingsInput.model_validate(document).findings


ADAPTER = NativeAdapter()
