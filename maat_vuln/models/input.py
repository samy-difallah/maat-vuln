"""Native JSON input document."""

from pydantic import BaseModel, Field, field_validator

from maat_vuln.models.finding import Finding

SCHEMA_VERSION = "0.1.0"

SEMVER_PATTERN = r"^\d+\.\d+\.\d+$"


class FindingsInput(BaseModel):
    """Top-level input document: a list of findings."""

    schema_version: str | None = Field(default=None, pattern=SEMVER_PATTERN)
    findings: list[Finding]

    @field_validator("schema_version")
    @classmethod
    def _same_major(cls, value: str | None) -> str | None:
        """Reject documents written for another major contract version."""
        major = SCHEMA_VERSION.split(".")[0]
        if value and value.split(".")[0] != major:
            msg = f"unsupported schema_version {value}, expected {major}.x"
            raise ValueError(msg)
        return value
