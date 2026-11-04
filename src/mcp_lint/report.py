"""Terminal and JSON reports."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from mcp_lint import __version__
from mcp_lint.models import Finding, Severity, ToolDef
from mcp_lint.probe import ProbeResult
from mcp_lint.text import CHARS_PER_TOKEN, definition_json, estimate_tokens

_MARK = {Severity.ERROR: "x", Severity.WARNING: "!", Severity.INFO: "i"}


def summary(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {s.value: counts.get(s.value, 0) for s in Severity}


def definition_tokens(tools: list[ToolDef]) -> int:
    return sum(estimate_tokens(definition_json(t)) for t in tools)


def render_probes(results: list[ProbeResult]) -> str:
    """Table of probe calls: what ran, what came back, how big, how slow."""
    lines = ["Probes"]
    width = max((len(r.tool) + (len(r.label) + 3 if r.label else 0) for r in results), default=10)
    for r in results:
        name = f"{r.tool} ({r.label})" if r.label else r.tool
        if r.ran:
            status = r.status + (" (expected)" if r.expect_error and r.status != "ok" else "")
            size = f"~{r.tokens:,} tok" if r.status != "protocol_error" else ""
            lines.append(f"  {name:<{width}}  {status:<24} {size:>11}  {r.latency_ms} ms")
            if r.status == "protocol_error":
                lines.append(f"      {r.reason}")
        else:
            lines.append(f"  {name:<{width}}  {r.status:<24}")
            if r.status == "blocked":
                lines.append(f"      {r.reason}")
    ran = sum(r.ran for r in results)
    blocked = sum(r.status == "blocked" for r in results)
    skipped = sum(r.status == "skipped" for r in results)
    lines.append(f"  {ran} ran, {blocked} blocked, {skipped} skipped")
    return "\n".join(lines)


def to_json(server: dict[str, Any], tools: list[ToolDef], findings: list[Finding],
            probes: list[ProbeResult] | None = None, include_responses: bool = False) -> dict[str, Any]:
    data = _to_json(server, tools, findings)
    if probes is not None:
        data["probes"] = [r.to_dict(include_text=include_responses) for r in probes]
    return data


def _to_json(server: dict[str, Any], tools: list[ToolDef], findings: list[Finding]) -> dict[str, Any]:
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
