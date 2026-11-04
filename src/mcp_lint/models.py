"""Plain data types shared by the client, rules, and reports.

Rules work on ``ToolDef`` rather than SDK objects so they can be tested
without a live server and stay stable if the SDK's types change.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

    @property
    def rank(self) -> int:
        return {"info": 0, "warning": 1, "error": 2}[self.value]


@dataclass
class ToolDef:
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)  # camelCase MCP hints

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolDef":
        """Build from a tools/list entry (accepts camelCase or snake_case)."""
        schema = data.get("inputSchema", data.get("input_schema")) or {}
        return cls(
            name=data["name"],
            description=data.get("description"),
            input_schema=schema,
            annotations=data.get("annotations") or {},
        )

    @property
    def read_only(self) -> bool:
        """True only if the server explicitly marks the tool read-only.

        This is the probe safety gate. ``destructiveHint: false`` is NOT enough:
        it means "only adds, never deletes" (e.g. git_commit), which still
        changes state. A tool with no annotations counts as not read-only.
        """
        return self.annotations.get("readOnlyHint") is True

    @property
    def params(self) -> dict[str, dict[str, Any]]:
        props = self.input_schema.get("properties") or {}
        return {k: v if isinstance(v, dict) else {} for k, v in props.items()}


@dataclass
class Finding:
    """One problem. ``tool`` is None for server-wide findings."""

    rule: str
    severity: Severity
    tool: str | None
    message: str
    param: str | None = None
    hint: str | None = None
    related: list[str] | None = None  # other tools involved, e.g. an S4 duplicate
    kind: str | None = None  # sub-type for scoring, e.g. P4 "opaque" vs "no_guidance"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
