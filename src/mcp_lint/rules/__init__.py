"""Lint rules. Static rules inspect definitions; probe rules (planned) call tools."""

from __future__ import annotations

from mcp_lint.models import Finding, ToolDef
from mcp_lint.rules.static import STATIC_RULES


def run_static(tools: list[ToolDef]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        for rule in STATIC_RULES:
            findings.extend(rule(tool))
    return findings
