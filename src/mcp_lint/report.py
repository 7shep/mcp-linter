"""Terminal and JSON reports."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from mcp_lint import __version__
from mcp_lint.models import Finding, Severity, ToolDef

_MARK = {Severity.ERROR: "x", Severity.WARNING: "!", Severity.INFO: "i"}


def summary(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {s.value: counts.get(s.value, 0) for s in Severity}


def to_json(server: dict[str, Any], tools: list[ToolDef], findings: list[Finding]) -> dict[str, Any]:
    return {
        "mcp_lint_version": __version__,
        "server": server,
        "tool_count": len(tools),
        "summary": summary(findings),
        "tools": [
            {
                "name": t.name,
                "findings": [f.to_dict() for f in findings if f.tool == t.name],
            }
            for t in tools
        ],
    }


def render_text(server: dict[str, Any], tools: list[ToolDef], findings: list[Finding],
                min_severity: Severity = Severity.INFO) -> str:
    shown = [f for f in findings if f.severity.rank >= min_severity.rank]
    lines = [f"mcp-lint {__version__}  server: {server.get('name')} {server.get('version') or ''}".rstrip(),
             f"{len(tools)} tools checked", ""]
    for tool in tools:
        tf = [f for f in shown if f.tool == tool.name]
        if not tf:
            continue
        lines.append(tool.name)
        for f in sorted(tf, key=lambda f: (-f.severity.rank, f.rule)):
            where = f" [{f.param}]" if f.param else ""
            lines.append(f"  {_MARK[f.severity]} {f.rule}{where} {f.message}")
            if f.hint:
                lines.append(f"      -> {f.hint}")
        lines.append("")
    clean = sum(1 for t in tools if not any(f.tool == t.name for f in findings))
    s = summary(findings)
    lines.append(f"{s['error']} errors, {s['warning']} warnings, {s['info']} info; "
                 f"{clean}/{len(tools)} tools clean")
    return "\n".join(lines)


def write_json(path: str, data: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
