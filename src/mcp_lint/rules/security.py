"""Security rules: text in tool metadata that a model reads but a user never sees.

A malicious server can hide instructions in a description, a nested schema
field, a parameter name, or an enum value. Approval screens show users little
of that, but the model reads all of it. These checks are static: they flag
suspicious text and never call a tool.

S8 is a security finding, not a token-waste one, so ``score.py`` gives it no
token cost.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from mcp_lint.models import Finding, Severity, ToolDef

MAX_SNIPPET = 80
MAX_CODES = 5

# Unicode code point ranges.
TAG_RANGE = (0xE0000, 0xE007F)  # TAG block: invisible, but spells ASCII
BIDI_RANGES = ((0x202A, 0x202E), (0x2066, 0x2069))  # bidi overrides and isolates
ZERO_WIDTH_RANGES = ((0x200B, 0x200F), (0x2060, 0x2064), (0xFEFF, 0xFEFF))

# Locations under inputSchema.properties.<name> name the parameter.
PROPERTIES_PATH = "inputSchema.properties"

SECRET_PATHS = (
    "~/.ssh", ".ssh/", "id_rsa", "id_ed25519", ".aws/credentials", ".netrc",
    ".git-credentials", ".npmrc", "mcp.json", "claude_desktop_config.json",
)

MODEL_DIRECTIVE_PATTERNS = (
    # Needs "the user" (not "the user's"), so "Never show user passwords" passes.
    r"(?:do\s+not|don['\u2019]t|never)\s+(?:tell|inform|mention|reveal|notify|show)\b[^.]{0,30}?"
    r"\bthe\s+user\b(?!['\u2019]s)",
    r"without\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?user",
    r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+(?:instructions|rules|messages)",
    r"before\s+(?:using|calling)\s+(?:this|any)\s+tool,?\s+(?:you\s+must\s+)?(?:first\s+)?"
    r"(?:read|send|pass|include)",
    r"<\s*/?\s*important\s*>",
    r"keep\s+(?:this|it)\s+(?:secret|hidden|confidential)\s+from",
    r"(?:the\s+)?user\s+(?:must\s+not|should\s+not|shouldn['\u2019]t|doesn['\u2019]t\s+need\s+to)"
    r"\s+(?:know|see|be\s+told)",
)

SHADOWING_PATTERNS = (
    r"always\s+use\s+this\s+tool",
    r"use\s+this\s+tool\s+instead\s+of\s+(?:any|all|the)\s+other",
    r"instead\s+of\s+(?:any|all)\s+other\s+tools?",
    r"(?:ignore|never\s+use|do\s+not\s+use|don['\u2019]t\s+use)\s+(?:any|all|the)\s+other\s+tools?",
    r"(?:overrides?|takes?\s+precedence\s+over)\s+(?:any|all|the)\s+other",
)

HTML_COMMENT_RE = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL | re.IGNORECASE)
STRONG_PATH_RE = re.compile("|".join(re.escape(p) for p in SECRET_PATHS), re.IGNORECASE)
WEAK_PATH_RE = re.compile(r"(?<![\w.])\.env\b", re.IGNORECASE)
MODEL_DIRECTIVE_RES = tuple(re.compile(p, re.IGNORECASE) for p in MODEL_DIRECTIVE_PATTERNS)
SHADOWING_RES = tuple(re.compile(p, re.IGNORECASE) for p in SHADOWING_PATTERNS)
# "some_tool tool" or "some-tool tool": a mention of another tool by name.
TOOL_MENTION_RE = re.compile(r"\b([a-z][a-z0-9]*(?:[_-][a-z0-9]+)+)\s+tool\b", re.IGNORECASE)

HINTS = {
    "invisible_text": "Remove the hidden characters. Decode them and read what they say first.",
    "html_comment": "Remove the comment. The model reads it, and users never see it.",
    "secret_path": "Tool metadata has no reason to name credential or config files. Remove the reference.",
    "model_directive": "Describe what the tool does. Don't give the model instructions about the user.",
    "shadowing": "Describe this tool only. Don't claim priority over other servers' tools.",
    "shadowing_info": "Check that the named tool exists on this server. If it lives on another server, "
    "the reference may be steering the agent.",
}


def _in_ranges(cp: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(lo <= cp <= hi for lo, hi in ranges)


def _is_tag(cp: int) -> bool:
    return _in_ranges(cp, (TAG_RANGE,))


def _is_error_char(cp: int) -> bool:
    return _is_tag(cp) or _in_ranges(cp, BIDI_RANGES)


def _is_invisible(cp: int) -> bool:
    return _is_error_char(cp) or _in_ranges(cp, ZERO_WIDTH_RANGES)


def _escape(text: str) -> str:
    """Make text printable: invisible and non-printable chars become \\uXXXX escapes."""
    out = []
    for ch in text:
        cp = ord(ch)
        if _is_invisible(cp) or not ch.isprintable():
            out.append(f"\\U{cp:08X}" if cp > 0xFFFF else f"\\u{cp:04X}")
        else:
            out.append(ch)
    return "".join(out)


def _clip(text: str, limit: int = MAX_SNIPPET) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _quote(text: str) -> str:
    """Printable, truncated, double-quoted snippet for a message."""
    return '"' + _clip(_escape(text)) + '"'


def _codes(cps: list[int]) -> str:
    """Distinct U+XXXX codes in order of first appearance, at most MAX_CODES shown."""
    unique = list(dict.fromkeys(cps))
    shown = ", ".join(f"U+{cp:04X}" for cp in unique[:MAX_CODES])
    extra = len(unique) - MAX_CODES
    return shown + (f", +{extra} more" if extra > 0 else "")


def _finding(tool: ToolDef, param: str | None, kind: str, severity: Severity,
             message: str, related: list[str] | None = None, hint: str | None = None) -> Finding:
    return Finding(
        rule="S8",
        severity=severity,
        tool=tool.name,
        message=message,
        param=_escape(param) if param else None,  # printable: reports print it
        hint=hint or HINTS[kind],
        related=related,
        kind=kind,
    )


def _strip_invisible(text: str) -> str:
    return "".join(ch for ch in text if not _is_invisible(ord(ch)))


def _invisible_finding(tool: ToolDef, where: str, param: str | None, text: str) -> Finding | None:
    cps = [ord(ch) for ch in text if _is_invisible(ord(ch))]
    if not cps:
        return None
    tag_cps = [cp for cp in cps if _is_tag(cp)]
    if tag_cps:
        decoded = "".join(chr(cp - 0xE0000) for cp in tag_cps if 0xE0020 <= cp <= 0xE007E)
        message = (f"Hidden TAG-block text in {where} ({len(cps)} invisible chars, "
                   f"decodes to: '{_clip(_escape(decoded))}'). Codes: {_codes(cps)}.")
    else:
        kind_word = ("incl. bidi controls" if any(_is_error_char(cp) for cp in cps)
                     else "zero-width only")
        message = (f"{len(cps)} invisible characters ({kind_word}) in {where}. "
                   f"Codes: {_codes(cps)}.")
    severity = Severity.ERROR if any(_is_error_char(cp) for cp in cps) else Severity.WARNING
    return _finding(tool, param, "invisible_text", severity, message)


def _first_match(patterns: tuple[re.Pattern[str], ...], text: str) -> re.Match[str] | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match
    return None


def _text_findings(tool: ToolDef, where: str, param: str | None, text: str,
                   known: set[str]) -> list[Finding]:
    """At most one finding per kind for one string. ``known`` holds lowercase tool and param names."""
    found: list[Finding] = []

    invisible = _invisible_finding(tool, where, param, text)
    if invisible:
        found.append(invisible)
    # Text checks run on a copy without invisible chars, so "ignore\u200b previous"
    # still matches. Snippets come from this copy, so they hold no invisible chars.
    text = _strip_invisible(text)

    comment = HTML_COMMENT_RE.search(text)
    if comment:
        found.append(_finding(tool, param, "html_comment", Severity.WARNING,
                              f"HTML comment in {where}: {_quote(comment.group(0))}."))

    strong = STRONG_PATH_RE.search(text)
    weak = None if strong else WEAK_PATH_RE.search(text)
    if strong:
        found.append(_finding(tool, param, "secret_path", Severity.WARNING,
                              f"Reference to a credential or config file in {where}: "
                              f"{_quote(strong.group(0))}."))
    elif weak:
        found.append(_finding(tool, param, "secret_path", Severity.INFO,
                              f"Mentions a '.env' file in {where}: {_quote(weak.group(0))}."))

    directive = _first_match(MODEL_DIRECTIVE_RES, text)
    if directive:
        found.append(_finding(tool, param, "model_directive", Severity.WARNING,
                              f"Instruction to the model about the user in {where}: "
                              f"{_quote(directive.group(0))}."))

    shadow = _first_match(SHADOWING_RES, text)
    if shadow:
        found.append(_finding(tool, param, "shadowing", Severity.WARNING,
                              f"Claims priority over other tools in {where}: "
                              f"{_quote(shadow.group(0))}."))
    else:
        unknown = [m for m in TOOL_MENTION_RE.finditer(text) if m.group(1).lower() not in known]
        if unknown:
            names = list(dict.fromkeys(m.group(1) for m in unknown))
            found.append(_finding(tool, param, "shadowing", Severity.INFO,
                                  f"Refers to tool '{_escape(names[0])}', which is not on this "
                                  f"server, in {where}: {_quote(unknown[0].group(0))}.",
                                  related=names, hint=HINTS["shadowing_info"]))
    return found


def _strings(node: object, path: str, param: str | None) -> Iterator[tuple[str, str | None, str]]:
    """Yield (location, param, text) for every string key and string value under ``node``."""
    if isinstance(node, str):
        yield path, param, node
    elif isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                continue
            child = f"{path}.{key}"
            # The first name under inputSchema.properties is the parameter's name.
            child_param = key if (path == PROPERTIES_PATH and param is None) else param
            # The key gets its own location, so a finding on a string value under
            # it is reported too instead of colliding with the key's.
            yield f"{child} (key)", child_param, key
            yield from _strings(value, child, child_param)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _strings(item, f"{path}[{i}]", param)


def _metadata_strings(tool: ToolDef) -> Iterator[tuple[str, str | None, str]]:
    if isinstance(tool.description, str):
        yield "description", None, tool.description
    yield from _strings(tool.input_schema, "inputSchema", None)
    yield from _strings(tool.annotations, "annotations", None)


def s8_hidden_text(tools: list[ToolDef]) -> list[Finding]:
    """S8: hidden or misleading text in tool metadata, aimed at the model rather than the user."""
    all_names = {t.name.lower() for t in tools}
    findings: list[Finding] = []
    for tool in tools:
        known = all_names | {p.lower() for p in tool.params}
        # _text_findings gives at most one finding per kind for each string, and
        # every string has its own location, so nothing needs deduplicating.
        for loc, param, text in _metadata_strings(tool):
            findings.extend(_text_findings(tool, _escape(loc), param, text, known))
    return findings


SECURITY_RULES = [s8_hidden_text]
