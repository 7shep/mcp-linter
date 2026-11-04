"""Probe rules: checks on what tools actually returned (needs ``--probe``).

Each rule takes the server's tools (by name) and the probe results, and
returns findings. Rules only look at probes that ran.
Based on Anthropic's "Writing effective tools for agents":
https://www.anthropic.com/engineering/writing-tools-for-agents
"""

from __future__ import annotations

from mcp_lint.models import Finding, Severity, ToolDef
from mcp_lint.probe import ProbeResult
from mcp_lint.text import split_name

# P1, in estimated tokens per response. 25k matches Claude Code's default cap
# on tool output; past that the agent sees a truncated result.
RESPONSE_TOKENS_WARN = 5_000
RESPONSE_TOKENS_ERROR = 25_000

# P5: a tool whose probes returned more than this should let agents ask for less.
CONCISE_MODE_INFO = 1_000

# Parameter-name words that let an agent choose how much comes back.
VERBOSITY_WORDS = frozenset(
    "format verbosity verbose detail details detailed concise brief summary "
    "fields select projection".split()
)
# Enum values that signal a concise/detailed switch, whatever the param is called.
VERBOSITY_VALUES = frozenset("concise detailed brief full summary compact minimal verbose".split())


def _probe_name(r: ProbeResult) -> str:
    return f"{r.tool} ({r.label})" if r.label else r.tool


def p1_response_size(tools: dict[str, ToolDef], results: list[ProbeResult]) -> list[Finding]:
    """P1: responses over ~5k tokens (warning) or ~25k tokens (error)."""
    findings = []
    for r in results:
        if r.status not in ("ok", "tool_error") or r.tokens <= RESPONSE_TOKENS_WARN:
            continue
        error = r.tokens > RESPONSE_TOKENS_ERROR
        findings.append(
            Finding(
                rule="P1",
                severity=Severity.ERROR if error else Severity.WARNING,
                tool=r.tool,
                message=f"Probe '{_probe_name(r)}' returned ~{r.tokens:,} tokens (estimated)"
                + (f", over the {RESPONSE_TOKENS_ERROR:,}-token cap agents like Claude Code "
                   "apply, so the agent sees a truncated result." if error else
                   f"; over {RESPONSE_TOKENS_WARN:,} uses up the agent's context fast."),
                hint="Paginate or truncate by default (with a note saying how to get more), "
                "and offer a concise response format.",
            )
        )
    return findings


def has_verbosity_control(tool: ToolDef) -> bool:
    """True if some parameter lets the agent choose how much detail comes back."""
    for name, spec in tool.params.items():
        if set(split_name(name)) & VERBOSITY_WORDS:
            return True
        values = spec.get("enum") or []
        if any(isinstance(v, str) and v.lower() in VERBOSITY_VALUES for v in values):
            return True
    return False


def p5_concise_mode(tools: dict[str, ToolDef], results: list[ProbeResult]) -> list[Finding]:
    """P5: tools with large responses but no response_format / verbosity option."""
    biggest: dict[str, ProbeResult] = {}
    for r in results:
        if r.status == "ok" and (r.tool not in biggest or r.tokens > biggest[r.tool].tokens):
            biggest[r.tool] = r
    findings = []
    for name, r in biggest.items():
        tool = tools.get(name)
        if tool is None or r.tokens <= CONCISE_MODE_INFO or has_verbosity_control(tool):
            continue
        findings.append(
            Finding(
                rule="P5",
                severity=Severity.WARNING if r.tokens > RESPONSE_TOKENS_WARN else Severity.INFO,
                tool=name,
                message=f"Returned up to ~{r.tokens:,} tokens but has no option for a "
                "shorter response.",
                hint="Add a 'response_format' parameter (e.g. enum ['concise', 'detailed']) "
                "so agents can skip fields they don't need.",
            )
        )
    return findings


PROBE_RULES = [p1_response_size, p5_concise_mode]


def run_probe_rules(tools: list[ToolDef], results: list[ProbeResult]) -> list[Finding]:
    by_name = {t.name: t for t in tools}
    findings: list[Finding] = []
    for rule in PROBE_RULES:
        findings.extend(rule(by_name, results))
    return findings
