"""Probe rules: checks on what tools actually returned (needs ``--probe``).

Each rule takes the server's tools (by name) and the probe results, and
returns findings. Rules only look at probes that ran.
Based on Anthropic's "Writing effective tools for agents":
https://www.anthropic.com/engineering/writing-tools-for-agents
"""

from __future__ import annotations

import re

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


# --- P4: error quality --------------------------------------------------------

_STACK_TRACE = re.compile(
    r"Traceback \(most recent call last\)"  # Python
    r"|File \"[^\"]+\", line \d+"  # Python frame
    r"|^\s*at \S+ \(?[^\s()]+:\d+:\d+\)?"  # JS / Java-ish frame
    r"|Exception in thread \"",
    re.MULTILINE,
)
# Messages that say a call failed and nothing else.
_OPAQUE = re.compile(
    r"^\s*(error( executing tool \S+)?|internal (server )?error|an? (unknown|unexpected) error"
    r"( occurred)?|something went wrong|failed|bad request|invalid (input|request|params)|"
    r"(error|err)?[\s:#-]*-?\d{1,6})[\s.!]*$",
    re.IGNORECASE,
)
# A "successful" result whose text is really an error message.
_ERROR_PREFIX = re.compile(
    r"^\s*(\[(error|err)\]|(error|err|exception|failed|failure)\b)[\s:!-]", re.IGNORECASE
)
# Words that tell the agent what valid input looks like or what to do next.
_GUIDANCE = re.compile(
    r"\b(expected|must|should|required|requires|valid|allowed|one of|did you mean|"
    r"try|instead|example|e\.g\.|format|missing|not found|no such|does not exist|"
    r"received|got|invalid|unknown|no(?: \w+){1,3} found|not allowed|denied|outside)\b",
    re.IGNORECASE,
)


def error_issues(r: ProbeResult) -> list[str]:
    """Problem kinds in one expected-error probe's response."""
    if r.status == "ok":
        if _ERROR_PREFIX.match(r.error_text):
            return ["error_as_success"]
        return [] if r.may_succeed else ["accepted"]
    text = r.error_text.strip()
    if not text:
        return ["empty"]
    issues = []
    if _STACK_TRACE.search(text):
        issues.append("stack_trace")
    if _OPAQUE.match(text):
        issues.append("opaque")
        return issues  # "no guidance" is implied; don't double-report
    names_input = bool(r.target and r.target.lower() in text.lower()) or any(
        isinstance(v, str) and len(v) >= 3 and v in text for v in r.args.values()
    )
    if not names_input and not _GUIDANCE.search(text):
        issues.append("no_guidance")
    return issues


_P4_KINDS = {
    "stack_trace": (Severity.WARNING, "leaked a stack trace",
                    "Catch the exception and return a short message saying what was wrong "
                    "with the input; tracebacks cost tokens and don't tell the agent what to change."),
    "opaque": (Severity.WARNING, "said only that the call failed",
               "Say which argument was wrong and what a valid value looks like. "
               "(With the MCP Python SDK, raise ToolError; other exceptions are hidden "
               "behind 'Error executing tool <name>'.)"),
    "empty": (Severity.WARNING, "returned an empty error",
              "Return a message saying what was wrong and how to fix it."),
    "no_guidance": (Severity.INFO, "didn't name the bad input or say how to fix it",
                    "Mention the argument and what's expected, e.g. \"'limit' must be 1-50\"."),
    "error_as_success": (Severity.INFO, "returned an error message as a successful result",
                         "Set isError: true on error results (raise ToolError in the Python SDK) "
                         "so clients and agents can tell a failed call from a real answer."),
    "accepted": (Severity.INFO, "accepted invalid arguments without an error",
                 "Validate input against the schema so agents learn about mistakes "
                 "instead of getting results for a request they didn't mean."),
}


def p4_error_quality(tools: dict[str, ToolDef], results: list[ProbeResult]) -> list[Finding]:
    """P4: responses to bad input that won't help an agent fix its call.

    Looks at probes marked expect_error (from fixtures or --error-probes).
    One finding per tool per problem kind, with a count and an example.
    """
    grouped: dict[tuple[str, str], list[ProbeResult]] = {}
    totals: dict[str, int] = {}
    for r in results:
        if not r.expect_error or not r.ran:
            continue
        totals[r.tool] = totals.get(r.tool, 0) + 1
        for kind in error_issues(r):
            grouped.setdefault((r.tool, kind), []).append(r)
    findings = []
    for (tool, kind), rs in grouped.items():
        severity, what, hint = _P4_KINDS[kind]
        example = rs[0]
        msg = f"{len(rs)} of {totals[tool]} error probes {what}"
        excerpt = " ".join(example.error_text.split())[:90]
        msg += f" (e.g. '{_probe_name(example)}'" + (f": \"{excerpt}\")." if excerpt and kind != "accepted" else ").")
        findings.append(Finding(rule="P4", severity=severity, tool=tool, message=msg, hint=hint))
    return findings


PROBE_RULES = [p1_response_size, p4_error_quality, p5_concise_mode]


def run_probe_rules(tools: list[ToolDef], results: list[ProbeResult]) -> list[Finding]:
    by_name = {t.name: t for t in tools}
    findings: list[Finding] = []
    for rule in PROBE_RULES:
        findings.extend(rule(by_name, results))
    return findings
