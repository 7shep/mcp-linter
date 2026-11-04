"""Terminal and JSON reports."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from mcp_lint import __version__
from mcp_lint.models import Finding, Severity, ToolDef
from mcp_lint.text import CHARS_PER_TOKEN, definition_json, estimate_tokens

_MARK = {Severity.ERROR: "x", Severity.WARNING: "!", Severity.INFO: "i"}


def summary(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {s.value: counts.get(s.value, 0) for s in Severity}


def definition_tokens(tools: list[ToolDef]) -> int:
    return sum(estimate_tokens(definition_json(t)) for t in tools)


def to_json(server: dict[str, Any], tools: list[ToolDef], findings: list[Finding]) -> dict[str, Any]:
    return {
        "mcp_lint_version": __version__,
        "server": server,
        "tool_count": len(tools),
        "definition_tokens": {
            "total": definition_tokens(tools),
            "method": f"estimate: {CHARS_PER_TOKEN} chars per token of compact JSON",
        },
        "summary": summary(findings),
        "server_findings": [f.to_dict() for f in findings if f.tool is None],
        "tools": [
            {
                "name": t.name,
                "definition_tokens": estimate_tokens(definition_json(t)),
                "findings": [f.to_dict() for f in findings if f.tool == t.name],
            }
            for t in tools
        ],
    }


def _section(title: str, items: list[Finding]) -> list[str]:
    lines = [title]
    for f in sorted(items, key=lambda f: (-f.severity.rank, f.rule)):
        where = f" [{f.param}]" if f.param else ""
        lines.append(f"  {_MARK[f.severity]} {f.rule}{where} {f.message}")
        if f.hint:
            lines.append(f"      -> {f.hint}")
    lines.append("")
    return lines


def render_text(server: dict[str, Any], tools: list[ToolDef], findings: list[Finding],
                min_severity: Severity = Severity.INFO) -> str:
    shown = [f for f in findings if f.severity.rank >= min_severity.rank]
    lines = [f"mcp-lint {__version__}  server: {server.get('name')} {server.get('version') or ''}".rstrip(),
             f"{len(tools)} tools checked, definitions ~{definition_tokens(tools):,} tokens (estimated)",
             ""]
    server_wide = [f for f in shown if f.tool is None]
    if server_wide:
        lines += _section("(server)", server_wide)
    for tool in tools:
        tf = [f for f in shown if f.tool == tool.name]
        if tf:
            lines += _section(tool.name, tf)
    clean = sum(1 for t in tools if not any(f.tool == t.name for f in findings))
    s = summary(findings)
    lines.append(f"{s['error']} errors, {s['warning']} warnings, {s['info']} info; "
                 f"{clean}/{len(tools)} tools clean")
    return "\n".join(lines)


def write_json(path: str, data: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
