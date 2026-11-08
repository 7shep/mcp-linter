"""Candidate tagging rules for the trifecta benchmark (prototype).

Evidence comes from the tool's name, its input schema's structure (property
names, types, enum/const/pattern) and its MCP annotations. Descriptions are
deliberately not read: the brief is name/schema/annotations, and free text is
noisy and written by the server.

Annotations can only ADD evidence. They are hints the server sets (the MCP spec
tells clients to treat them as untrusted), so ``readOnlyHint: true`` or
``openWorldHint: false`` never removes a tag that the name or schema earned.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from itertools import combinations
from typing import Any, Iterable, Mapping

from mcp_lint.models import MAX_NESTING, ToolDef, nesting_depth
from mcp_lint.text import split_name


class Tag(str, Enum):
    PRIVATE_READ = "PRIVATE_READ"
    UNTRUSTED_READ = "UNTRUSTED_READ"
    EXTERNAL_WRITE = "EXTERNAL_WRITE"


ALL_TAGS = frozenset(Tag)
HIGH, MEDIUM = "high", "medium"
PROFILES = {"strict": {HIGH}, "inclusive": {HIGH, MEDIUM}}


@dataclass(frozen=True)
class Evidence:
    tag: Tag
    confidence: str
    rule: str
    detail: str


HTTP_WRITE_METHODS = frozenset("post put patch delete".split())  # GET stays: it is a read verb
NOUNISH_VERBS = frozenset("email mail post tweet dm share".split())  # service prefix if a verb follows

READ_VERBS = frozenset(
    "get list read search find fetch retrieve view query show open browse lookup scan "
    "scrape crawl extract convert map research navigate take".split()
)
SEND_VERBS = frozenset(
    "send post publish share email notify tweet reply forward upload broadcast dm mail resend".split()
)
WRITE_VERBS = frozenset(
    "create update add delete remove set write edit insert append move rename merge fork "
    "push commit patch put".split()
)
ALL_VERBS = READ_VERBS | SEND_VERBS | WRITE_VERBS

# Objects other people can read once created, or that other people wrote.
SHARED_OBJECTS = frozenset("issue pr comment review message tweet gist ticket post discussion thread".split())
THIRD_PARTY_NOUNS = SHARED_OBJECTS | frozenset("email mail inbox feed webpage".split())
PRIVATE_NOUNS_HIGH = frozenset(
    "email mail inbox contact calendar secret credential password env database table customer "
    "drive memory note entity relation graph".split()
)
PRIVATE_NOUNS_MEDIUM = frozenset("page block user node config setting history document data_source".split())
FILE_NOUNS = frozenset("file document attachment".split())
FILE_META_NOUNS = frozenset("directory folder tree".split())
BROWSER_NOUNS = frozenset("browser snapshot dom html console".split())
EXEC_NAME = frozenset("exec execute shell bash terminal eval evaluate".split())
EXEC_PARAMS = frozenset("command cmd script shell code function expression js javascript python".split())
URL_PARAMS = frozenset("url urls uri uris href link endpoint".split())
PATH_PARAMS = frozenset("path paths file file_path filepath filename repo_path".split())
QUERY_PARAMS = frozenset("query q".split())
RECIPIENT_PARAMS = frozenset(
    "recipient recipients cc bcc webhook webhook_url callback_url phone email_to destination_url target_url".split()
)
# Too common alone (move(from, to), relations, date ranges): need a content sibling, top level.
WEAK_RECIPIENT_PARAMS = frozenset("to channel channel_id".split())
CONTENT_PARAMS = frozenset("content body files message title description comments comment text rich_text subject note".split())
VCS_CONTENT_READS = frozenset("diff log show".split())


def _singular(word: str) -> str:
    return word[:-1] if len(word) > 3 and word.endswith("s") and not word.endswith(("ss", "us", "is")) else word


def name_tokens(name: str) -> list[str]:
    """Lower-case name words, singular, without an ``API-<method>-`` operationId prefix."""
    words = [_singular(w) for w in split_name(name)]
    if len(words) > 2 and words[0] == "api":
        words = words[2:] if words[1] in HTTP_WRITE_METHODS else words[1:]
    return words


def _verb(words: list[str]) -> str | None:
    """The tool's verb: the first known verb in the first two words (a service prefix may lead)."""
    for index, word in enumerate(words[:2]):
        if word in ALL_VERBS:
            if index == 0 and word in NOUNISH_VERBS and len(words) > 1 and words[1] in ALL_VERBS:
                continue
            return word
    return None


def _properties(schema: Any) -> dict[str, dict[str, Any]]:
    """Top-level properties, tolerating malformed schemas (attacker-controlled input)."""
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return {}
    return {str(k): (v if isinstance(v, dict) else {}) for k, v in props.items()}


def _props_ci(props: dict[str, dict[str, Any]], lowered: str) -> dict[str, Any]:
    """The spec of the top-level property whose lower-case name is ``lowered``, or {}."""
    for key, spec in props.items():
        if key.lower() == lowered:
            return spec
    return {}


def _all_param_names(schema: Any) -> set[str]:
    """Property names at any depth, walked iteratively and capped at MAX_NESTING."""
    found: set[str] = set()
    stack: list[tuple[Any, int]] = [(schema, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_NESTING:
            continue
        if isinstance(node, dict):
            props = node.get("properties")
            if isinstance(props, dict):
                found.update(str(k).lower() for k in props)
            stack.extend((v, depth + 1) for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node if isinstance(v, (dict, list)))
    return found


NON_TEXT_TYPES = frozenset("integer number boolean null".split())


def _constrained(spec: dict[str, Any]) -> bool:
    """True only for a limit that really narrows the value; a malformed one counts as none."""
    enum = spec.get("enum")
    if "const" in spec or (isinstance(enum, list) and enum):
        return True
    pattern = spec.get("pattern")
    return (isinstance(pattern, str) and pattern.startswith("^") and pattern.endswith("$")
            and ".*" not in pattern and ".+" not in pattern)


def _carries_data(spec: dict[str, Any]) -> bool:
    """Can the model put arbitrary text in this parameter?"""
    if _constrained(spec):
        return False
    kind = spec.get("type")
    kinds = kind if isinstance(kind, list) else [kind]
    # An odd or empty "type" is malformed, so it counts as able to carry text (fail closed).
    return not (kinds and all(isinstance(k, str) and k in NON_TEXT_TYPES for k in kinds))


def has_data_param(tool: ToolDef) -> bool:
    """False only when the schema's declared properties rule out arbitrary text."""
    schema = tool.input_schema
    if not isinstance(schema, dict) or not isinstance(schema.get("properties"), dict):
        return True  # nothing usable declared: unknown, so fail closed
    extras = schema.get("additionalProperties")
    if schema.get("patternProperties") or extras not in (None, False):
        return True  # undeclared properties are explicitly allowed
    props = _properties(schema)
    if not props:
        return extras is not False
    return any(_carries_data(s) for s in props.values())


def _malformed_schema(schema: Any) -> bool:
    """Not an object, ``properties`` of the wrong shape, or nested past what the CLI accepts."""
    if not isinstance(schema, dict):
        return True
    return ("properties" in schema and not isinstance(schema["properties"], dict)
            or nesting_depth(schema) > MAX_NESTING)


def tag_tool(tool: ToolDef) -> list[Evidence]:
    words = name_tokens(tool.name if isinstance(tool.name, str) else "")
    word_set = set(words)
    if {"data", "source"} <= word_set:
        word_set.add("data_source")
    verb = _verb(words)
    props = _properties(tool.input_schema)
    top = {k.lower() for k in props}
    every = _all_param_names(tool.input_schema)
    ann = tool.annotations if isinstance(tool.annotations, dict) else {}
    out: list[Evidence] = []

    def add(tag: Tag, conf: str, rule: str, detail: str) -> None:
        out.append(Evidence(tag, conf, rule, detail))

    if _malformed_schema(tool.input_schema):
        for tag in Tag:
            add(tag, MEDIUM, "X-MALFORMED", "schema is malformed or too deeply nested to inspect")

    data = has_data_param(tool)
    is_read = verb in READ_VERBS
    is_write = verb in WRITE_VERBS
    is_send = verb in SEND_VERBS

    # Checked per declared key, so a constrained "URL" can't shadow an open "url".
    url_params = sorted({k.lower() for k, s in props.items() if k.lower() in URL_PARAMS and not _constrained(s)})
    url_mode = any(p.endswith("url") and p != "url" and _props_ci(props, p).get("type") == "boolean" for p in top)
    is_forge = {"owner", "repo"} <= top
    pr_noun = {"pull", "request"} <= word_set or "pr" in word_set
    shared = (word_set & SHARED_OBJECTS) | ({"pull_request"} if pr_noun else set())
    third_party = (word_set & THIRD_PARTY_NOUNS) | ({"pull_request"} if pr_noun else set())
    browser = bool(word_set & BROWSER_NOUNS) or "navigate" in word_set

    # ---- EXTERNAL_WRITE ----
    exec_params = sorted(every & EXEC_PARAMS)
    if word_set & EXEC_NAME or exec_params:
        why = ", ".join(sorted(word_set & EXEC_NAME) + exec_params)
        add(Tag.EXTERNAL_WRITE, HIGH, "E-EXEC", f"runs code or commands ({why})")
        add(Tag.PRIVATE_READ, MEDIUM, "P-EXEC", f"code can read local data ({why})")
        add(Tag.UNTRUSTED_READ, MEDIUM, "U-EXEC", f"code can pull in outside content ({why})")
    if data:
        if is_send:
            add(Tag.EXTERNAL_WRITE, HIGH, "E-SEND", f"send verb '{verb}'")
        if (is_write or verb == "open") and verb != "merge" and shared and every & CONTENT_PARAMS:
            add(Tag.EXTERNAL_WRITE, HIGH, "E-SHARED-OBJECT", f"{verb} on {sorted(shared)}")
        if is_forge and is_write and verb != "merge" and top & CONTENT_PARAMS and not shared:
            add(Tag.EXTERNAL_WRITE, HIGH, "E-FORGE-WRITE", f"{verb} to owner/repo with {sorted(top & CONTENT_PARAMS)}")
        recipients = sorted(every & RECIPIENT_PARAMS)
        if top & WEAK_RECIPIENT_PARAMS and top & CONTENT_PARAMS and "from" not in top:
            recipients += sorted(top & WEAK_RECIPIENT_PARAMS)
        if recipients:
            add(Tag.EXTERNAL_WRITE, HIGH, "E-RECIPIENT", f"recipient param {recipients}")
        if url_params or url_mode:
            add(Tag.EXTERNAL_WRITE, MEDIUM, "E-URL-EGRESS", f"data can leave in a URL ({url_params or 'url mode'})")
        if ann.get("readOnlyHint") is not True and ann.get("openWorldHint") is True:
            add(Tag.EXTERNAL_WRITE, MEDIUM, "E-OPEN-WRITE", "not read-only and openWorldHint: true")

    # ---- UNTRUSTED_READ ----
    if is_read and third_party:
        add(Tag.UNTRUSTED_READ, HIGH, "U-THIRD-PARTY", f"{verb} on {sorted(third_party)}")
    if not is_write and not is_send and (url_params or url_mode):
        add(Tag.UNTRUSTED_READ, HIGH if is_read else MEDIUM, "U-URL-READ",
            f"reads a caller-chosen URL ({url_params or 'url mode'})")
    if browser and not is_write:
        add(Tag.UNTRUSTED_READ, HIGH if "browser" in word_set and is_read else MEDIUM, "U-BROWSER",
            f"browser content ({sorted(word_set & (BROWSER_NOUNS | {'navigate'}))})")
    if word_set & {"web", "internet"} and not is_write:
        add(Tag.UNTRUSTED_READ, HIGH, "U-WEB", "web in the name")
    corpus_nouns = word_set & (PRIVATE_NOUNS_HIGH | PRIVATE_NOUNS_MEDIUM | FILE_NOUNS | FILE_META_NOUNS)
    if verb == "search" and top & QUERY_PARAMS and not top & PATH_PARAMS and not corpus_nouns and not third_party:
        add(Tag.UNTRUSTED_READ, MEDIUM, "U-SEARCH", "free-text search over an unnamed corpus")
    if is_forge and is_read and not third_party:
        add(Tag.UNTRUSTED_READ, MEDIUM, "U-FORGE-READ", "reads any owner/repo, which may be public")
    if ann.get("readOnlyHint") is True and ann.get("openWorldHint") is True:
        add(Tag.UNTRUSTED_READ, MEDIUM, "U-OPEN-READ", "read-only and openWorldHint: true")

    # ---- PRIVATE_READ ----
    has_path = bool(top & PATH_PARAMS)
    if not is_write and not is_send and has_path:
        if is_read and word_set & FILE_NOUNS and verb != "search" and "info" not in word_set and not is_forge:
            add(Tag.PRIVATE_READ, HIGH, "P-FILE-READ", f"{verb} file content by path")
        elif word_set & (FILE_NOUNS | FILE_META_NOUNS | {"search"}) and not is_forge:
            add(Tag.PRIVATE_READ, MEDIUM, "P-FILE-META", "file names, metadata or matches under a path")
    if "git" in word_set and "repo_path" in top and not is_write:
        if word_set & VCS_CONTENT_READS:
            add(Tag.PRIVATE_READ, HIGH, "P-VCS-READ", "local repository content")
        elif word_set & {"status", "branch"}:
            add(Tag.PRIVATE_READ, MEDIUM, "P-VCS-META", "local repository metadata")
    if is_read:
        if is_forge:
            if word_set & {"file", "content"}:
                add(Tag.PRIVATE_READ, HIGH, "P-FORGE-CONTENT", "reads repository content; the token may reach private repos")
            else:
                add(Tag.PRIVATE_READ, MEDIUM, "P-FORGE-READ", "reads any owner/repo, which may be private")
        high = word_set & PRIVATE_NOUNS_HIGH
        if high:
            add(Tag.PRIVATE_READ, HIGH, "P-NOUN", f"{verb} on {sorted(high)}")
        medium = (word_set & PRIVATE_NOUNS_MEDIUM) - (BROWSER_NOUNS if browser else set())
        if medium and not high and not is_forge and not browser:
            add(Tag.PRIVATE_READ, MEDIUM, "P-NOUN-AMBIGUOUS", f"{verb} on {sorted(medium)}")
        if {"tool", "call"} <= word_set:
            add(Tag.PRIVATE_READ, MEDIUM, "P-CALL-HISTORY", "returns recorded tool calls")
        if "output" in word_set and "process" in word_set:
            add(Tag.PRIVATE_READ, MEDIUM, "P-PROCESS-OUTPUT", "returns process output")
    return out


def tags_for(evidence: Iterable[Evidence], profile: str = "inclusive") -> frozenset[Tag]:
    allowed = PROFILES[profile]
    return frozenset(e.tag for e in evidence if e.confidence in allowed)


def minimal_trifecta_sets(server_tags: Mapping[str, Iterable[Tag]]) -> list[tuple[str, ...]]:
    """All smallest server sets whose tags, together, hold all three legs."""
    useful = {name: frozenset(tags) for name, tags in server_tags.items() if tags}
    names = sorted(useful)
    for size in range(1, 4):
        found = [combo for combo in combinations(names, size)
                 if frozenset().union(*(useful[n] for n in combo)) >= ALL_TAGS]
        if found:
            return found
    return []
