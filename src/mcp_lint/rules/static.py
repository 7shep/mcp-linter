"""Static rules: checks on tool definitions alone, no tool calls.

Each rule takes a ``ToolDef`` and returns a list of ``Finding``.
Based on Anthropic's "Writing effective tools for agents":
https://www.anthropic.com/engineering/writing-tools-for-agents
"""

from __future__ import annotations

from collections import Counter

from mcp_lint.models import Finding, Severity, ToolDef
from mcp_lint.text import (
    definition_json,
    estimate_tokens,
    naming_style,
    similarity_matrix,
    split_name,
)

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


# --- Tool-set rules: these look at all tools together -------------------------

# S4: a pair overlaps when BOTH its TF-IDF text similarity (name + description)
# and its parameter-name overlap (Jaccard) clear these bars. Text alone flags
# templated descriptions ("Create a new X in a repo") for unrelated tools;
# requiring shared parameters removes most of those. Tuned on 8 official
# reference servers (105 tools).
DUPLICATE_TEXT_THRESHOLD = 0.5
DUPLICATE_PARAM_THRESHOLD = 0.5

# Leading words that are actions, not service prefixes.
VERBS = frozenset(
    """get list search find fetch read write create update delete remove add set put
    post patch run execute start stop trigger send echo query lookup upload download
    move copy rename edit open close print toggle enable disable check validate
    generate make build compute calculate convert summarize annotate sample retrieve
    insert upsert save load sync navigate click type take describe show count""".split()
)
PREFIX_COVERAGE = 0.5  # a prefix is "the" prefix once half the tools use it

# S6 thresholds, in estimated tokens for all definitions combined.
DEFINITION_TOKENS_WARN = 10_000
DEFINITION_TOKENS_ERROR = 25_000

# S7: parameter-name words that bound or narrow a listing.
LIMIT_WORDS = frozenset(
    "limit max top first last count size n cursor page offset token per".split()
)
FILTER_WORDS = frozenset(
    "query q filter filters search where since until before after status state "
    "sort order match pattern name prefix contains".split()
)


def _param_overlap(a: ToolDef, b: ToolDef) -> float:
    pa, pb = set(a.params), set(b.params)
    union = pa | pb
    return len(pa & pb) / len(union) if union else 1.0


def _different_actions(a: ToolDef, b: ToolDef) -> bool:
    """True if both names contain action verbs and the verbs differ.

    'retrieve-a-block' vs 'delete-a-block' or 'screencast_start' vs
    'screencast_stop' share parameters and wording but do opposite things.
    Pairs with the same verb (read_file / read_text_file) still count.
    """
    va = set(split_name(a.name)) & VERBS
    vb = set(split_name(b.name)) & VERBS
    return bool(va and vb and va != vb)


def s4_near_duplicates(tools: list[ToolDef]) -> list[Finding]:
    """S4: pairs of tools with similar descriptions that take similar parameters."""
    sims = similarity_matrix(tools)
    findings = []
    for i, a in enumerate(tools):
        for j in range(i + 1, len(tools)):
            b = tools[j]
            if _different_actions(a, b):
                continue
            text = round(sims[i][j], 2)
            params = round(_param_overlap(a, b), 2)
            if text >= DUPLICATE_TEXT_THRESHOLD and params >= DUPLICATE_PARAM_THRESHOLD:
                findings.append(
                    Finding(
                        rule="S4",
                        severity=Severity.WARNING,
                        tool=a.name,
                        related=[b.name],
                        message=f"Overlaps with '{b.name}' (text similarity {text:.2f}, "
                        f"{params:.0%} shared parameters); an agent may not know "
                        "which to pick.",
                        hint="Merge them into one tool with a parameter, or say in each "
                        "description when to use it instead of the other.",
                    )
                )
    return findings


def s5_name_prefixes(tools: list[ToolDef]) -> list[Finding]:
    """S5: missing or inconsistent service prefixes and naming styles."""
    if not tools:
        return []
    findings = []
    words = {t.name: split_name(t.name) for t in tools}
    prefixes = Counter(
        w[0] for w in words.values() if len(w) > 1 and w[0] not in VERBS
    )
    top = prefixes.most_common(1)
    if top and top[0][1] >= 2 and top[0][1] / len(tools) >= PREFIX_COVERAGE:
        prefix = top[0][0]
        for t in tools:
            if words[t.name][:1] != [prefix]:
                findings.append(
                    Finding(
                        rule="S5",
                        severity=Severity.WARNING,
                        tool=t.name,
                        message=f"Missing the '{prefix}' prefix that "
                        f"{top[0][1]}/{len(tools)} tools use.",
                        hint=f"Rename to start with '{prefix}' so agents see it "
                        "belongs to the same service.",
                    )
                )
    else:
        findings.append(
            Finding(
                rule="S5",
                severity=Severity.INFO,
                tool=None,
                message="Tool names have no shared service prefix.",
                hint="Prefix names by service (e.g. 'github_create_issue') so they "
                "stay distinct when an agent has many servers loaded. Some clients "
                "add a namespace for you.",
            )
        )
    styles = Counter(s for s in (naming_style(t.name) for t in tools) if s)
    if len(styles) > 1:
        mix = ", ".join(f"{s} ({c})" for s, c in styles.most_common())
        findings.append(
            Finding(
                rule="S5",
                severity=Severity.INFO,
                tool=None,
                message=f"Mixed naming styles: {mix}.",
                hint="Pick one style for all tool names.",
            )
        )
    return findings


def s6_definition_tokens(tools: list[ToolDef]) -> list[Finding]:
    """S6: total (estimated) tokens all tool definitions cost on every request."""
    sizes = sorted(
        ((estimate_tokens(definition_json(t)), t.name) for t in tools), reverse=True
    )
    total = sum(s for s, _ in sizes)
    if total <= DEFINITION_TOKENS_WARN:
        return []
    severity = Severity.ERROR if total > DEFINITION_TOKENS_ERROR else Severity.WARNING
    heaviest = ", ".join(f"{name} (~{size:,})" for size, name in sizes[:3])
    return [
        Finding(
            rule="S6",
            severity=severity,
            tool=None,
            message=f"Tool definitions total ~{total:,} tokens (estimated); "
            f"heaviest: {heaviest}.",
            hint="Consolidate overlapping tools and trim long descriptions or schemas; "
            "every definition is sent with every request.",
        )
    ]


def _is_list_tool(words: list[str]) -> bool:
    if not words:
        return False
    if words[0] == "list" or (len(words) > 1 and words[1] == "list" and words[0] not in VERBS):
        return True
    return any(a in {"get", "fetch", "read", "retrieve", "dump"} and b == "all"
               for a, b in zip(words, words[1:]))


def s7_unbounded_lists(tools: list[ToolDef]) -> list[Finding]:
    """S7: list_* / get_all_* tools with no limit, paging, or filter parameter."""
    findings = []
    for t in tools:
        if not _is_list_tool(split_name(t.name)):
            continue
        param_words = {w for p in t.params for w in split_name(p)}
        if param_words & (LIMIT_WORDS | FILTER_WORDS):
            continue
        findings.append(
            Finding(
                rule="S7",
                severity=Severity.WARNING,
                tool=t.name,
                message="Lists items but has no limit, paging, or filter parameter.",
                hint="Add a filter or search parameter and a 'limit' (or cursor) so "
                "agents can avoid huge responses. Ignore if the list is always short.",
            )
        )
    return findings


STATIC_RULES = [s1_description_length, s2_vague_param_names, s3_param_documentation]
TOOLSET_RULES = [s4_near_duplicates, s5_name_prefixes, s6_definition_tokens, s7_unbounded_lists]
