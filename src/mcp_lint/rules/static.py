"""Static rules: checks on tool definitions alone, no tool calls.

Each rule takes a ``ToolDef`` and returns a list of ``Finding``.
Based on Anthropic's "Writing effective tools for agents":
https://www.anthropic.com/engineering/writing-tools-for-agents
"""

from __future__ import annotations

from mcp_lint.models import Finding, Severity, ToolDef

MIN_DESCRIPTION_WORDS = 15

# Names that tell an agent almost nothing on their own.
VAGUE_PARAM_NAMES = frozenset(
    {
        "id", "user", "data", "q", "obj", "item", "value", "val", "input",
        "params", "args", "arg", "info", "payload", "body", "thing", "x",
    }
)

# Any of these keys gives a parameter usable type information.
TYPE_KEYS = ("type", "enum", "const", "anyOf", "oneOf", "allOf", "$ref")


def _has_description(spec: dict) -> bool:
    desc = spec.get("description")
    return isinstance(desc, str) and desc.strip() != ""


def s1_description_length(tool: ToolDef) -> list[Finding]:
    """S1: description missing or shorter than ~15 words."""
    desc = (tool.description or "").strip()
    if not desc:
        return [
            Finding(
                rule="S1",
                severity=Severity.ERROR,
                tool=tool.name,
                message="Tool has no description.",
                hint="Describe what it does, when to use it, and what it returns, "
                "as if onboarding a new teammate.",
            )
        ]
    words = len(desc.split())
    if words < MIN_DESCRIPTION_WORDS:
        return [
            Finding(
                rule="S1",
                severity=Severity.WARNING,
                tool=tool.name,
                message=f"Description is only {words} words "
                f"(aim for {MIN_DESCRIPTION_WORDS}+).",
                hint="Add when to use this tool, what it returns, and any limits.",
            )
        ]
    return []


def s2_vague_param_names(tool: ToolDef) -> list[Finding]:
    """S2: vague parameter names (user, id, data, q, ...) with no description."""
    findings = []
    for name, spec in tool.params.items():
        if name.lower() in VAGUE_PARAM_NAMES and not _has_description(spec):
            findings.append(
                Finding(
                    rule="S2",
                    severity=Severity.WARNING,
                    tool=tool.name,
                    param=name,
                    message=f"Parameter '{name}' has a vague name and no description.",
                    hint="Use a specific name (e.g. 'user_id' not 'user') "
                    "or describe what value is expected.",
                )
            )
    return findings


def s3_param_documentation(tool: ToolDef) -> list[Finding]:
    """S3: parameters with no type information or no description."""
    findings = []
    for name, spec in tool.params.items():
        if not any(k in spec for k in TYPE_KEYS):
            findings.append(
                Finding(
                    rule="S3",
                    severity=Severity.WARNING,
                    tool=tool.name,
                    param=name,
                    message=f"Parameter '{name}' has no type or enum.",
                    hint="Add a JSON Schema type, or an enum if only a few values are valid.",
                )
            )
        if not _has_description(spec):
            findings.append(
                Finding(
                    rule="S3",
                    severity=Severity.INFO,
                    tool=tool.name,
                    param=name,
                    message=f"Parameter '{name}' has no description.",
                    hint="Say what the value means and give an example format.",
                )
            )
    return findings


STATIC_RULES = [s1_description_length, s2_vague_param_names, s3_param_documentation]
