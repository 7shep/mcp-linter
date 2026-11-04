"""Per-tool scores, weighted by how many tokens each problem costs an agent.

Every finding becomes an estimate of tokens an agent wastes in a typical
session using the tool. Measured costs come from probes (response tokens past
a budget, opaque-ID characters) and definitions (tokens past a budget, resent
each turn). Problems that can't be measured (a vague description, a useless
error) get a fixed estimate of what they cause: retries, wrong tool picks,
re-reading. The score halves for every HALF_LIFE wasted tokens.

The constants are rough guesses, kept in one place so they can be argued
with. What matters is the ordering: an 80k-token response or an error that
makes the agent guess costs far more than a short description.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_lint.models import Finding, ToolDef
from mcp_lint.probe import ProbeResult
from mcp_lint.rules.probe import CONCISE_MODE_INFO, PAGING_PARAM_WORDS, has_paging_hint, opaque_share
from mcp_lint.text import definition_json, estimate_tokens, split_name

HALF_LIFE = 5_000  # wasted tokens per session that halve a tool's score
SERVER_HALF_LIFE = 10_000  # same for a whole server's per-session total

# Responses: tokens past this are context the agent pays for but rarely needs.
RESPONSE_BUDGET = 2_000

# Definitions: tokens past this per tool are overhead. They're resent every
# turn but usually prompt-cached: ~20 turns at ~10% cost = 2 full copies.
DEFINITION_BUDGET = 300
DEFINITION_COPIES = 2

# Fixed estimates, in wasted tokens per session, keyed by (rule, kind) or
# (rule, severity). Roughly: a failed call plus the agent's recovery turn is
# ~1,000-2,000 tokens; a bad argument that gets a clear error is ~300.
FIXED_COSTS: dict[tuple[str, str], int] = {
    ("S1", "error"): 2_000,    # no description: misuse, or the tool never gets used
    ("S1", "warning"): 500,    # short description: occasional wrong pick or bad args
    ("S2", "warning"): 300,    # vague param name: a wrong-argument retry
    ("S3", "warning"): 300,    # untyped param: a wrong-type retry
    ("S3", "info"): 100,       # undescribed param
    ("S4", "warning"): 500,    # overlapping tool: sometimes the wrong one
    ("S5", "warning"): 100,    # missing service prefix
    ("S7", "warning"): 2_000,  # unbounded list: expected oversized response (if not measured)
    ("P3", "warning"): 1_000,  # big response, no hint, no paging: agent can't tell it's partial
    ("P3", "info"): 0,         # the tool can page; the agent asked for that much
    ("P4", "stack_trace"): 1_500,
    ("P4", "opaque"): 1_500,   # agent retries blind
    ("P4", "empty"): 1_500,
    ("P4", "no_guidance"): 700,
    ("P4", "error_as_success"): 500,
    ("P4", "accepted"): 500,
    ("P5", "warning"): 300,    # the big response itself is counted by P1's measurement
    ("P5", "info"): 100,
}
# Rules whose cost is measured from data instead of a fixed estimate.
MEASURED = {"P1", "P2", "S6"}


@dataclass
class Cost:
    source: str  # rule ID, or "definition"
    tokens: int
    note: str


@dataclass
class ToolScore:
    tool: str
    score: int
    grade: str
    waste: int
    costs: list[Cost] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "score": self.score, "grade": self.grade, "waste_tokens": self.waste,
            "costs": [{"source": c.source, "tokens": c.tokens, "note": c.note} for c in self.costs],
        }


def grade(score: int) -> str:
    for cutoff, letter in ((90, "A"), (75, "B"), (50, "C"), (25, "D")):
        if score >= cutoff:
            return letter
    return "F"


def to_score(waste: int, half_life: int = HALF_LIFE) -> int:
    return round(100 * 0.5 ** (waste / half_life))


_LABELS = {
    ("S1", "error"): "no description", ("S1", "warning"): "short description",
    ("S2", "warning"): "vague param", ("S3", "warning"): "untyped param",
    ("S3", "info"): "undescribed param", ("S4", "warning"): "overlaps another tool",
    ("S5", "warning"): "missing prefix", ("S7", "warning"): "unbounded list",
    ("P3", "warning"): "no paging hint", ("P3", "info"): "no paging hint",
    ("P5", "warning"): "no concise mode", ("P5", "info"): "no concise mode",
}


def _label(f: Finding) -> str:
    base = _LABELS.get((f.rule, f.severity.value)) or (f.kind or "").replace("_", " ") or f.severity.value
    if f.rule == "P4":
        base = f"error: {base}"
    return f"{f.rule} {base}" + (f" [{f.param}]" if f.param else "")


def _requests_size(p: ProbeResult) -> bool:
    """True if the probe set a limit/paging argument, i.e. asked for this size."""
    return any(set(split_name(a)) & PAGING_PARAM_WORDS for a in p.args)


def _fixed_cost(f: Finding) -> int:
    return FIXED_COSTS.get((f.rule, f.kind or ""), FIXED_COSTS.get((f.rule, f.severity.value), 0))


def score_tool(tool: ToolDef, findings: list[Finding], probes: list[ProbeResult]) -> ToolScore:
    costs: list[Cost] = []

    size = estimate_tokens(definition_json(tool))
    if size > DEFINITION_BUDGET:
        costs.append(Cost("definition", (size - DEFINITION_BUDGET) * DEFINITION_COPIES,
                          f"{size:,}-token definition"))

    ok = [p for p in probes if p.status == "ok"]
    measured_response = bool(ok)
    # A response the agent asked to be big (max_length=999999, max_count=400)
    # isn't waste the tool caused, and a paged response that says what's left
    # ("19000 remaining") lets the agent decide. Score what ordinary calls return.
    ordinary = [p for p in ok if not _requests_size(p)]
    charged = [p for p in ordinary if not has_paging_hint(p.agent_text)]
    if charged:
        big = max(charged, key=lambda p: p.tokens)
        if big.tokens > RESPONSE_BUDGET:
            costs.append(Cost("P1", big.tokens - RESPONSE_BUDGET,
                              f"{big.tokens:,}-token response"))
        if any(f.rule == "P2" for f in findings):
            id_waste = max(round(opaque_share(p.agent_text)[1] * p.tokens) for p in ok)
            if id_waste:
                costs.append(Cost("P2", id_waste, "tokens spent on unlabelled IDs"))

    for f in findings:
        if f.rule in MEASURED or (f.rule == "S7" and measured_response):
            continue  # measured above, or S7's guess superseded by a real response
        if f.rule == "P5" and max((p.tokens for p in ordinary), default=0) <= CONCISE_MODE_INFO:
            continue  # only requested-size probes were big
        tokens = _fixed_cost(f)
        if tokens:
            costs.append(Cost(f.rule, tokens, _label(f)))

    waste = sum(c.tokens for c in costs)
    s = to_score(waste)
    costs.sort(key=lambda c: -c.tokens)
    return ToolScore(tool=tool.name, score=s, grade=grade(s), waste=waste, costs=costs)


@dataclass
class ServerScore:
    score: int
    grade: str
    waste: int
    tools: list[ToolScore]
    probed: bool  # False means static-only: response problems weren't measured

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score, "grade": self.grade, "waste_tokens": self.waste,
            "probed": self.probed, "half_life_tokens": HALF_LIFE,
            "tools": [t.to_dict() for t in self.tools],
        }


TOOLS_USED_PER_SESSION = 3  # distinct tools a typical session calls


def server_waste(scores: list[ToolScore]) -> int:
    """Estimated tokens a session wastes on this server.

    Definition overhead is paid every session whichever tools are used, so it
    is summed. Every other cost is paid only when that tool is called, so it
    is averaged over tools (fixed costs are already per session of use;
    assumes any tool is equally likely) and multiplied by TOOLS_USED_PER_SESSION
    (capped at the number of tools).
    """
    if not scores:
        return 0
    definitions = sum(c.tokens for s in scores for c in s.costs if c.source == "definition")
    usage = sum(c.tokens for s in scores for c in s.costs if c.source != "definition")
    return round(definitions + usage / len(scores) * min(TOOLS_USED_PER_SESSION, len(scores)))


def score_server(tools: list[ToolDef], findings: list[Finding],
                 probes: list[ProbeResult] | None) -> ServerScore:
    """Server score from estimated waste per session (see server_waste)."""
    probes = probes or []
    scores = [
        score_tool(t, [f for f in findings if f.tool == t.name],
                   [p for p in probes if p.tool == t.name and not p.expect_error])
        for t in tools
    ]
    scores.sort(key=lambda s: (s.score, -s.waste))
    waste = server_waste(scores)
    s = to_score(waste, SERVER_HALF_LIFE)
    return ServerScore(score=s, grade=grade(s), waste=waste, tools=scores, probed=bool(probes))
