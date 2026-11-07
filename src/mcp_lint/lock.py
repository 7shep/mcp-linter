"""Tool lockfile: record a server's tool definitions and report what changed.

A server can change its tools after a user approved them (a "rug pull"): a
description gains an instruction, or a new required parameter appears. The
lock stores a canonical copy of each tool, and the server's instructions. A
later check compares the live server with it and classifies each change, so CI
can fail on it.

The file is written with ``ensure_ascii`` so hidden Unicode shows up as
``\\uXXXX`` escapes in a git diff instead of invisible characters.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
from collections import Counter
from collections.abc import Iterable
from typing import Any

from mcp_lint.models import Finding, Severity, ToolDef

LOCK_VERSION = 1
LOCK_RULE = "LOCK"
MAX_QUOTE = 80
MAX_REASONS = 5
CONTEXT_BEFORE = 20  # characters shown before the changed part of a description
MAX_DIFF_TOKENS = 2000  # per side; above this, skip the word diff
MAX_DIFF_CELLS = 250_000  # old tokens x new tokens; above this, skip the word diff

# Schema keys that limit what is accepted: removing one widens the schema.
# (enum and const are compared on their own, see _widening_reasons.)
LIMIT_KEYS = ("pattern", "format", "maxLength", "minLength", "maxItems", "minItems",
              "maxProperties", "minProperties", "maximum", "minimum", "exclusiveMaximum",
              "exclusiveMinimum", "multipleOf", "uniqueItems", "maxContains", "minContains")
MAX_KEYS = ("maxLength", "maxItems", "maxProperties", "maxContains", "maximum", "exclusiveMaximum")
MIN_KEYS = ("minLength", "minItems", "minProperties", "minContains", "minimum", "exclusiveMinimum")
# JSON Schema keywords that aren't text. Any other key (description, title, default, examples,
# $comment, x-*, hint, an unknown one...) may hold text the model reads, so a string under it
# is treated as text. Numbers and booleans under such a key are not text.
STRUCTURAL_KEYS = frozenset((
    "type", "enum", "const", "required", "properties", "patternProperties",
    "additionalProperties", "items", "prefixItems", "additionalItems", "contains",
    "minContains", "maxContains", "unevaluatedItems", "unevaluatedProperties", "propertyNames",
    "dependentSchemas", "dependentRequired", "dependencies", "allOf", "anyOf", "oneOf", "not",
    "if", "then", "else", "$ref", "$dynamicRef", "$defs", "definitions", "$id", "$anchor",
    "$dynamicAnchor", "$schema", "$vocabulary", "format", "pattern", "maxLength", "minLength",
    "maxItems", "minItems", "maxProperties", "minProperties", "maximum", "minimum",
    "exclusiveMaximum", "exclusiveMinimum", "multipleOf", "uniqueItems", "readOnly", "writeOnly",
    "deprecated", "nullable", "contentEncoding", "contentMediaType", "contentSchema",
))
# Keys whose value is a map of names to schemas (names are data), and keys whose value is data.
MAP_KEYS = ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas",
            "dependencies")
# Maps whose entry names are model-visible: a new entry is reported as text.
ENTRY_NAME_KEYS = ("$defs", "definitions", "dependentSchemas")
ENTRY_MARK = "<entry name>"
DATA_KEYS = ("const", "enum", "default", "examples")
# Keys holding a schema, or a list of schemas, that the text walker descends into.
SCHEMA_KEYS = ("items", "prefixItems", "additionalProperties", "additionalItems",
               "unevaluatedProperties", "unevaluatedItems", "contains", "propertyNames",
               "then", "else", "if", "not", "allOf", "anyOf", "oneOf", "contentSchema")
# Keys whose difference at any path counts as a widening (see _widening_reasons).
REF_KEYS = ("$ref", "$dynamicRef", "$anchor", "$dynamicAnchor", "$id", "dependentRequired")
# Single-schema keywords compared at the same path (a list means one schema per index).
SUBSCHEMA_KEYS = ("items", "prefixItems", "additionalProperties", "additionalItems",
                  "unevaluatedProperties", "unevaluatedItems", "contains", "propertyNames",
                  "then", "else")
META_FIELDS = ("_meta", "icons", "execution")
# Keys a locked tool definition must carry, by value type (see _validate_lock).
TEXT_FIELDS = ("name", "title", "description")
OBJECT_FIELDS = ("inputSchema", "annotations", "outputSchema")
SEVERITY_MARK = {Severity.ERROR: "x", Severity.WARNING: "!", Severity.INFO: "-"}


class LockError(Exception):
    """The lock file is missing, unreadable, or not a version 1 lock."""


# ---------------------------------------------------------------- canonical form

def canonical(tool: ToolDef) -> dict[str, Any]:
    """The part of a tool that the lock records and hashes."""
    return {
        "name": tool.name,
        "title": tool.title or "",
        "description": tool.description or "",
        "inputSchema": _norm_schema(tool.input_schema or {}),
        "annotations": tool.annotations or {},
        "outputSchema": _norm_schema(tool.output_schema or {}),
        "_meta": tool.meta or {},
        "icons": tool.icons or [],
        "execution": tool.execution or {},
    }


def _sorted_values(values: list[Any]) -> list[Any]:
    return sorted(values, key=lambda v: json.dumps(v, sort_keys=True))


def _norm_schema(node: Any, is_map: bool = False) -> Any:
    """A schema in a form where semantically equal schemas hash equal.

    Drops empty description/title strings and sorts ``required``, a list-valued
    ``type`` and the branches of ``anyOf``/``oneOf``/``allOf`` (their order means
    nothing). Values under enum, const, default and examples are data: left alone.
    """
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if is_map:  # a name the server chose, whatever it is called
                out[key] = _norm_schema(value)
                continue
            if key in ("description", "title") and isinstance(value, str) and value == "":
                continue
            if key in DATA_KEYS:
                out[key] = value
                continue
            value = _norm_schema(value, is_map=key in MAP_KEYS)
            if key in ("required", "type", "anyOf", "oneOf", "allOf") and isinstance(value, list):
                value = _sorted_values(value)
            out[key] = value
        return out
    if isinstance(node, list):
        return [_norm_schema(v) for v in node]
    return node


def _digest(obj: Any) -> str:
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def tool_hash(tool: ToolDef) -> str:
    return _digest(canonical(tool))


def command_hash(command: Any) -> str | None:
    """Hash of the server launch command. The lock stores this, never the command itself."""
    if command is None:
        return None
    text = json.dumps(command, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def duplicate_names(tools: list[ToolDef]) -> list[str]:
    seen: dict[str, int] = {}
    for t in tools:
        seen[t.name] = seen.get(t.name, 0) + 1
    return sorted(name for name, count in seen.items() if count > 1)


def build_lock(server: dict[str, Any], tools: Iterable[ToolDef]) -> dict[str, Any]:
    tools = list(tools)
    dups = duplicate_names(tools)
    if dups:
        raise LockError("duplicate tool names: " + ", ".join(dups))
    return {
        "version": LOCK_VERSION,
        "server": {
            "name": server.get("name"),
            "version": server.get("version"),
            "command_sha256": command_hash(server.get("command")),
            # The text the model reads at connect time. None means unknown (a --from file).
            "instructions": server.get("instructions"),
        },
        "tools": {
            t.name: {"hash": tool_hash(t), "definition": canonical(t)} for t in tools
        },
    }


# --------------------------------------------------------------------- file I/O

def write_lock(path: str, lock: dict[str, Any]) -> None:
    """Write the lock atomically: serialise first, then replace the file in one step."""
    # ensure_ascii and "\n" keep the bytes identical on every OS. A RecursionError from a
    # deeply nested schema is raised here, before any file is touched.
    # allow_nan=False makes NaN and Infinity (not valid JSON) a ValueError, again before any write.
    text = json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def read_lock(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise LockError(f"lock file not found: {path} (create it with mcp-lint lock)") from None
    except OSError as exc:
        raise LockError(f"cannot read {path}: {exc.strerror or exc}") from None
    except ValueError as exc:  # JSON syntax or decoding errors
        raise LockError(f"{path} is not valid JSON: {exc}") from None

    if not isinstance(data, dict):
        raise LockError(f"{path} is not a mcp-lint lock file")
    version = data.get("version")
    if type(version) is not int or version != LOCK_VERSION:
        raise LockError(f"{path} is lock version {version!r}; this mcp-lint reads version {LOCK_VERSION}")
    _validate_lock(path, data)
    return data


def _validate_lock(path: str, data: dict[str, Any]) -> None:
    """Reject a hand-edited or damaged lock before any of its values reach the rules."""

    def fail(message: str) -> None:
        raise LockError(f"{path}: {message}")

    if not isinstance(data.get("server"), dict):
        fail("'server' must be an object")
    instructions = data["server"].get("instructions")
    if instructions is not None and not isinstance(instructions, str):
        fail("'server.instructions' must be a string or null")
    tools = data.get("tools")
    if not isinstance(tools, dict):
        fail("'tools' must be an object")
    for name, entry in tools.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("hash"), str) \
                or not isinstance(entry.get("definition"), dict):
            fail(f"tool {name!r} needs a string 'hash' and an object 'definition'")
        definition = entry["definition"]
        for key in TEXT_FIELDS:
            if not isinstance(definition.get(key), str):
                fail(f"tool {name!r}: '{key}' must be a string")
        for key in OBJECT_FIELDS:
            if not isinstance(definition.get(key), dict):
                fail(f"tool {name!r}: '{key}' must be an object")
        # Absent in older locks, where they count as empty.
        for key, kind, label in (("_meta", dict, "an object"), ("icons", list, "a list"),
                                 ("execution", dict, "an object")):
            if key in definition and not isinstance(definition[key], kind):
                fail(f"tool {name!r}: '{key}' must be {label}")
        if definition["name"] != name:
            fail(f"tool {name!r} has a definition for {definition['name']!r}")
        if _digest(definition) != entry["hash"]:
            fail(f"hash doesn't match definition for '{name}'; the lock was edited by hand, "
                 "re-create it with mcp-lint lock")


# ------------------------------------------------------------------ diffing

def diff_lock(lock: dict[str, Any], server: dict[str, Any], tools: Iterable[ToolDef]) -> list[Finding]:
    """Every way the current server differs from the lock."""
    findings = _server_findings(lock.get("server") or {}, server)
    tools = list(tools)
    locked = lock["tools"]
    current = {t.name: t for t in tools}  # a duplicated name is diffed by its last entry

    for name in duplicate_names(tools):
        count = sum(1 for t in tools if t.name == name)
        findings.append(_finding("duplicate_tool", Severity.ERROR, name,
                                 f"{count} tools share this name; clients may pick either one"))

    for name, tool in current.items():
        entry = locked.get(name)
        if entry is None:
            # A new (or renamed) tool brings new text the model reads.
            shown = _snippet(tool.description) if tool.description else "(none)"
            findings.append(_finding("tool_added", Severity.ERROR, name,
                                     f"New tool, not in the lock. Description: {shown}"))
            continue
        old, new = _definition(entry["definition"]), canonical(tool)
        if _digest(old) != _digest(new):
            findings.extend(_tool_findings(name, old, new))

    for name in locked:
        if name not in current:
            findings.append(_finding("tool_removed", Severity.INFO, name,
                                     "Tool in the lock is no longer served"))
    return findings


def _definition(raw: dict[str, Any]) -> dict[str, Any]:
    """A locked definition with missing or null fields filled in as canonical() would."""
    return {
        "name": raw.get("name"),
        "title": raw.get("title") or "",
        "description": raw.get("description") or "",
        "inputSchema": _norm_schema(raw.get("inputSchema") or {}),
        "annotations": raw.get("annotations") or {},
        "outputSchema": _norm_schema(raw.get("outputSchema") or {}),
        "_meta": raw.get("_meta") or {},
        "icons": raw.get("icons") or [],
        "execution": raw.get("execution") or {},
    }


def _server_findings(locked: dict[str, Any], server: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    parts = []
    current_version = server.get("version")
    if current_version is not None and locked.get("version") != current_version:
        parts.append(f"version {json.dumps(locked.get('version'))} -> {json.dumps(current_version)}")
    # The command is compared by hash and never printed, since it may hold secrets.
    current_command = command_hash(server.get("command"))
    if current_command is not None and locked.get("command_sha256") != current_command:
        parts.append("launch command changed (not shown)")
    if parts:
        out.append(_finding("server_changed", Severity.INFO, None, "Server changed: " + "; ".join(parts)))

    # Instructions go into the model's context. None means unknown.
    old_text, new_text = locked.get("instructions"), server.get("instructions")
    if isinstance(old_text, str) and new_text is None:
        out.append(_finding("instructions_unchecked", Severity.WARNING, None,
                            "server instructions weren't checked: this tools file doesn't include them"))
    elif old_text is None and isinstance(new_text, str) and new_text:
        out.append(_finding("instructions_changed", Severity.ERROR, None,
                            f"Server instructions not in lock ({len(new_text.split())} words): "
                            f"{_snippet(new_text)}"))
    elif isinstance(old_text, str) and isinstance(new_text, str) and old_text != new_text:
        if new_text:
            out.append(_finding(
                "instructions_changed", Severity.ERROR, None,
                f"Server instructions changed ({len(old_text.split())} -> {len(new_text.split())} "
                f"words): {_changed_quote(old_text, new_text)}"))
        else:
            out.append(_finding("instructions_changed", Severity.INFO, None,
                                f"Server instructions removed ({len(old_text.split())} words)"))
    return out


def _tool_findings(name: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    if old["description"] != new["description"]:
        out.append(_description_finding(name, old["description"], new["description"]))
    if old["title"] != new["title"]:
        out.append(_finding("title_changed", Severity.ERROR, name,
                            f"Title changed from {_snippet(old['title'])} to {_snippet(new['title'])}"))

    input_text = _schema_text_changes(old["inputSchema"], new["inputSchema"], "inputSchema")
    output_text = _schema_text_changes(old["outputSchema"], new["outputSchema"], "outputSchema")
    if input_text or output_text:
        out.append(_schema_text_finding(name, input_text + output_text))
    widened = _schema_widened_finding(name, old["inputSchema"], new["inputSchema"])
    if widened:
        out.append(widened)
    # schema_changed covers a change that isn't text and isn't a widening, even when it comes
    # with a text edit: compare the schemas with every text leaf removed.
    if (not widened and _digest(_split_text(old["inputSchema"], (), {}))
            != _digest(_split_text(new["inputSchema"], (), {}))):
        out.append(_finding("schema_changed", Severity.WARNING, name,
                            "Input schema changed structurally (review the diff)"))

    # Values are compared by digest: Python treats 1 == True == 1.0, JSON does not.
    if _digest(old["annotations"]) != _digest(new["annotations"]):
        safer = _claims_safer(old["annotations"], new["annotations"])
        # annotations.title is shown to the user in approval dialogs, so it is text.
        title = _digest(old["annotations"].get("title")) != _digest(new["annotations"].get("title"))
        message = (f"Annotations changed: {_snippet(json.dumps(old['annotations'], sort_keys=True))} -> "
                   f"{_snippet(json.dumps(new['annotations'], sort_keys=True))}")
        if safer:
            message += " (now claims to be safer)"
        if title:
            message += " (title text changed)"
        out.append(_finding("annotations_changed", Severity.ERROR if safer or title else Severity.WARNING,
                            name, message))

    if _digest(old["outputSchema"]) != _digest(new["outputSchema"]):
        out.append(_finding("output_schema_changed", Severity.WARNING, name, "Output schema changed"))

    changed_meta = [f for f in META_FIELDS if _digest(old[f]) != _digest(new[f])]
    if changed_meta:
        shown = "; ".join(
            f"{f}: {_snippet(json.dumps(old[f], sort_keys=True))} -> {_snippet(json.dumps(new[f], sort_keys=True))}"
            for f in changed_meta)
        out.append(_finding("meta_changed", Severity.WARNING, name,
                            f"Tool metadata changed in {', '.join(changed_meta)}: {shown}"))

    if not out:
        # The hashes differ but nothing above explains it: fail closed.
        out.append(_finding("definition_changed", Severity.WARNING, name,
                            "definition changed in a way mcp-lint doesn't classify"))
    return out


def _truthy(value: Any) -> bool:
    """Truthiness the way a JavaScript host sees a hint: "true" and 1 are truthy, 0, "" and null not."""
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0 and value == value  # NaN is falsy
    if isinstance(value, str):
        return value != ""
    return True


def _claims_safer(old: dict[str, Any], new: dict[str, Any]) -> bool:
    """A hint that now claims more safety. Absent destructiveHint/openWorldHint default to true."""
    for key in ("readOnlyHint", "idempotentHint"):
        if _truthy(new.get(key)) and not _truthy(old.get(key)):
            return True
    for key in ("destructiveHint", "openWorldHint"):
        if _truthy(old.get(key, True)) and not _truthy(new.get(key, True)):
            return True
    return False


def _description_finding(name: str, old: str, new: str) -> Finding:
    return _finding("description_changed", Severity.ERROR, name,
                    f"Description changed ({len(old.split())} -> {len(new.split())} words): "
                    f"{_changed_quote(old, new)}")


def _changed_quote(old: str, new: str) -> str:
    """Quote the new text around its largest inserted or replaced span.

    The first difference may be a small edit with the payload further on, so
    the largest span is the one worth showing.
    """
    start = _largest_change_start(old, new)
    return _snippet(new, max(0, start - CONTEXT_BEFORE))


def _largest_change_start(old: str, new: str) -> int:
    first_diff = len(os.path.commonprefix([old, new]))
    old_tokens, new_tokens = re.findall(r"\s+|\S+", old), re.findall(r"\s+|\S+", new)
    if (max(len(old_tokens), len(new_tokens)) > MAX_DIFF_TOKENS
            or len(old_tokens) * len(new_tokens) > MAX_DIFF_CELLS):
        return first_diff  # too big to diff in reasonable time
    old_offsets, new_offsets = _offsets(old_tokens), _offsets(new_tokens)
    matcher = difflib.SequenceMatcher(None, old_tokens, new_tokens, autojunk=False)
    best_start, best_len = first_diff, 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag not in ("insert", "replace"):
            continue
        start, end = new_offsets[j1], new_offsets[j2]
        if tag == "replace":  # skip what the replaced words share with the old ones
            start += len(os.path.commonprefix([old[old_offsets[i1]:old_offsets[i2]], new[start:end]]))
        if end - start > best_len:
            best_start, best_len = start, end - start
    return best_start


def _offsets(tokens: list[str]) -> list[int]:
    out = [0]
    for token in tokens:
        out.append(out[-1] + len(token))
    return out


# ------------------------------------------------------------ schema text

_GONE = object()


def _split_text(node: Any, path: tuple, leaves: dict[tuple, str]) -> Any:
    """The schema with its text removed; every string that was text goes into ``leaves``.

    Text is any string under a key that isn't in STRUCTURAL_KEYS (description, hint, x-*,
    anything unknown). Property names and the like are data. The names of $defs and
    dependentSchemas entries are model-visible, so they are recorded as text too.
    """
    if isinstance(node, list):
        return [_split_text(v, path + (i,), leaves) for i, v in enumerate(node)]
    if not isinstance(node, dict):
        return node
    out: dict[str, Any] = {}
    for key, value in node.items():
        if key in MAP_KEYS:
            out[key] = _split_map(key, value, path + (key,), leaves)
        elif key in SCHEMA_KEYS:
            out[key] = _split_text(value, path + (key,), leaves)
        elif key in STRUCTURAL_KEYS:
            out[key] = value
        else:
            kept = _blank_text(value, path + (key,), leaves)
            if kept is not _GONE:
                out[key] = kept
    return out


def _split_map(key: str, value: Any, path: tuple, leaves: dict[tuple, str]) -> Any:
    if not isinstance(value, dict):
        return value
    out = {}
    for name, child in value.items():
        if key in ENTRY_NAME_KEYS:
            leaves[path + (name, ENTRY_MARK)] = name
        # an array-valued dependencies entry lists property names: data
        out[name] = child if isinstance(child, list) else _split_text(child, path + (name,), leaves)
    return out


def _blank_text(node: Any, path: tuple, leaves: dict[tuple, str]) -> Any:
    """Everything under a text key is text: record its strings and drop them."""
    if isinstance(node, str):
        leaves[path] = node
        return _GONE
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            kept = _blank_text(value, path + (key,), leaves)
            if kept is not _GONE:
                out[key] = kept
        return out
    if isinstance(node, list):
        kept_items = []
        for i, value in enumerate(node):
            kept = _blank_text(value, path + (i,), leaves)
            if kept is not _GONE:
                kept_items.append(kept)
        return kept_items
    return node


def _schema_text_changes(old: dict[str, Any], new: dict[str, Any], prefix: str) -> list[tuple[str, str]]:
    """(location, new text) for each text leaf that differs, sorted by location."""
    old_text: dict[tuple, str] = {}
    new_text: dict[tuple, str] = {}
    _split_text(old, (), old_text)
    _split_text(new, (), new_text)
    changed = []
    for path in set(old_text) | set(new_text):
        if path[-1] == ENTRY_MARK and path not in new_text:
            continue  # only a new entry is reported, not a removed one
        # A missing path counts as "", so a non-empty value on one side is a change.
        if old_text.get(path, "") != new_text.get(path, ""):
            where = prefix + "." + ".".join(str(x) for x in path)
            changed.append((where, new_text.get(path, "")))
    return sorted(changed)


def _schema_text_finding(name: str, changes: list[tuple[str, str]]) -> Finding:
    where, shown = changes[0]
    detail = _snippet(shown) if shown else "(removed)"
    extra = f" (and {len(changes) - 1} more)" if len(changes) > 1 else ""
    return _finding("schema_text_changed", Severity.ERROR, name,
                    f"Schema text changed at {where}: {detail}{extra}")


# ------------------------------------------------------------ widening

def _schema_widened_finding(name: str, old: dict[str, Any], new: dict[str, Any]) -> Finding | None:
    reasons: list[str] = []
    _widening_reasons(old, new, (), reasons)
    if not reasons:
        return None
    shown = "; ".join(reasons[:MAX_REASONS])
    more = f" (+{len(reasons) - MAX_REASONS} more)" if len(reasons) > MAX_REASONS else ""
    return _finding("schema_widened", Severity.ERROR, name, f"Schema widened: {shown}{more}")


def _where(path: tuple) -> str:
    return "(root)" if not path else "'" + ".".join(str(p) for p in path) + "'"


def _map(schema: dict[str, Any], key: str) -> dict[str, Any]:
    value = schema.get(key)
    return value if isinstance(value, dict) else {}


def _required(schema: dict[str, Any]) -> list[str]:
    req = schema.get("required")
    return [r for r in req if isinstance(r, str)] if isinstance(req, list) else []


def _type_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {t for t in value if isinstance(t, str)}
    return set()


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _widening_reasons(old: Any, new: Any, path: tuple, out: list[str]) -> None:
    """Append a reason for each way ``new`` accepts more, or asks for more, than ``old``.

    Walks both schemas in parallel and compares the nodes at the same path.
    A reason is added when in doubt, so a missed widening is the rarer mistake.
    """
    # Boolean schemas: true accepts anything ({}), false accepts nothing.
    if old is False:
        if new is not False:
            out.append(f"{_where(path)} now accepts values")
        return
    if new is False:
        return  # accepts no more than the old schema did
    if old is True:
        old = {}
    if new is True:
        new = {}  # accepts anything: it has lost its type, pattern, and so on
    if not isinstance(old, dict) or not isinstance(new, dict):
        return
    where = _where(path)

    _properties_reasons(old, new, path, out)
    _required_reasons(old, new, path, out)
    _enum_const_reasons(old, new, where, out)
    _limit_reasons(old, new, where, out)
    _type_reasons(old, new, where, out)

    # A reference can be retargeted without its string changing (an $anchor moved), so any
    # difference in these keys counts, whether added, removed or changed.
    for key in REF_KEYS:
        if (key in old) != (key in new) or _digest(old.get(key)) != _digest(new.get(key)):
            out.append(f"{where} {key} changed")
    # if and not can't be compared structurally, so any change counts.
    if any((k in old) != (k in new) or _digest(old.get(k)) != _digest(new.get(k)) for k in ("if", "not")):
        out.append(f"{where} if/not changed")

    # A missing additionalProperties means true (extra properties allowed).
    if old.get("additionalProperties") is False:
        if new.get("additionalProperties", True) is not False:
            out.append(f"{where} now allows extra properties")

    for key in SUBSCHEMA_KEYS:
        if key == "additionalProperties" and old.get(key) is False:
            continue
        _subschema_reasons(old, new, key, path, out)
    for key in ("patternProperties", "$defs", "definitions", "dependentSchemas", "dependencies"):
        _map_reasons(old, new, key, path, out)
    for key in ("anyOf", "oneOf", "allOf"):
        _branch_reasons(old, new, key, path, out)


def _properties_reasons(old: dict[str, Any], new: dict[str, Any], path: tuple, out: list[str]) -> None:
    old_props, new_props = _map(old, "properties"), _map(new, "properties")
    new_req = _required(new)
    for prop, child in new_props.items():
        if prop not in old_props:
            label = "new required parameter" if prop in new_req else "new parameter"
            out.append(f"{label} {_where(path + (prop,))}")
        else:
            _widening_reasons(old_props[prop], child, path + (prop,), out)


def _required_reasons(old: dict[str, Any], new: dict[str, Any], path: tuple, out: list[str]) -> None:
    old_props, new_props = _map(old, "properties"), _map(new, "properties")
    old_req = set(_required(old))
    for prop in dict.fromkeys(_required(new)):
        if prop in old_req:
            continue
        if prop in new_props and prop not in old_props:
            continue  # reported as a new required parameter
        if prop in new_props or prop in old_props:
            out.append(f"{_where(path + (prop,))} is now required")
        else:
            out.append(f"new required parameter {_where(path + (prop,))} (not declared)")


def _enum_const_reasons(old: dict[str, Any], new: dict[str, Any], where: str, out: list[str]) -> None:
    if "enum" in old:
        if "enum" in new:
            if isinstance(old["enum"], list) and isinstance(new["enum"], list):
                known = {_digest(v) for v in old["enum"]}
                if any(_digest(v) not in known for v in new["enum"]):
                    out.append(f"{where} enum widened")
        elif "const" in new:
            # Replacing an enum with one of its own values narrows it.
            if isinstance(old["enum"], list) and _digest(new["const"]) not in {_digest(v) for v in old["enum"]}:
                out.append(f"{where} enum widened")
        else:
            out.append(f"{where} enum widened")
    elif "const" in old:
        if "const" in new:
            if _digest(old["const"]) != _digest(new["const"]):
                out.append(f"{where} const changed")
        elif isinstance(new.get("enum"), list):
            if any(_digest(v) != _digest(old["const"]) for v in new["enum"]):
                out.append(f"{where} const widened to an enum")
        else:
            out.append(f"{where} lost const")


def _limit_reasons(old: dict[str, Any], new: dict[str, Any], where: str, out: list[str]) -> None:
    for key in LIMIT_KEYS:
        if key not in old:
            continue
        exclusive = key in ("exclusiveMaximum", "exclusiveMinimum")
        if key not in new:
            if (key == "uniqueItems" or exclusive) and old[key] is False:
                continue  # false is the default, so dropping it changes nothing
            out.append(f"{where} lost {key}")
            continue
        before, after = old[key], new[key]
        if _digest(before) == _digest(after):
            continue
        if key == "uniqueItems":
            if before is True:  # anything but exactly true is a relaxation
                out.append(f"{where} uniqueItems relaxed")
        elif exclusive and isinstance(before, bool):  # draft-04: a flag on maximum/minimum
            if before is True or not (after is True or _number(after)):
                out.append(f"{where} {key} relaxed")
        elif key in MAX_KEYS or key in MIN_KEYS:
            if not (_number(before) and _number(after)) or before != before or after != after:
                out.append(f"{where} {key} changed to a non-numeric value")
            elif key in MAX_KEYS and after > before:
                out.append(f"{where} {key} raised")
            elif key in MIN_KEYS and after < before:
                out.append(f"{where} {key} lowered")
        else:  # pattern, format, multipleOf
            out.append(f"{where} {key} changed")


def _type_reasons(old: dict[str, Any], new: dict[str, Any], where: str, out: list[str]) -> None:
    if "type" not in old:
        return
    if "type" not in new:
        out.append(f"{where} lost type")
        return
    old_types, new_types = _type_set(old["type"]), _type_set(new["type"])
    if "number" in old_types:
        old_types = old_types | {"integer"}  # every integer is a number
    if new_types - old_types:
        out.append(f"{where} type widened to {json.dumps(sorted(_type_set(new['type'])))}")


def _subschema_reasons(old: dict[str, Any], new: dict[str, Any], key: str, path: tuple,
                       out: list[str]) -> None:
    """Compare a keyword holding one schema, or a list of schemas matched by index."""
    if key not in old:
        return
    before = old[key]
    after = new[key] if key in new else True  # a missing keyword accepts anything
    if isinstance(before, list):
        if isinstance(after, list):
            pairs = [(b, after[i] if i < len(after) else True, path + (i,)) for i, b in enumerate(before)]
        elif after is True:
            pairs = [(b, True, path + (i,)) for i, b in enumerate(before)]
        elif isinstance(after, (dict, bool)):
            out.append(f"{_where(path)} {key} changed shape")
            return
        else:
            return
    elif isinstance(before, (dict, bool)):
        if isinstance(after, (dict, bool)):
            pairs = [(before, after, path)]
        elif isinstance(after, list):
            out.append(f"{_where(path)} {key} changed shape")
            return
        else:
            return
    else:
        return
    for old_child, new_child, child_path in pairs:
        _widening_reasons(old_child, new_child, child_path, out)


def _map_reasons(old: dict[str, Any], new: dict[str, Any], key: str, path: tuple, out: list[str]) -> None:
    old_map, new_map = _map(old, key), _map(new, key)
    for name, child in new_map.items():
        if name in old_map:
            if isinstance(old_map[name], list) or isinstance(child, list):
                # an array-valued dependencies entry is like dependentRequired
                if _digest(old_map[name]) != _digest(child):
                    out.append(f"{_where(path + (key, name))} {key} entry changed")
            else:
                _widening_reasons(old_map[name], child, path + (key, name), out)
        elif key == "patternProperties":
            out.append(f"new patternProperties {_where(path + (key, name))}")
        # a new $defs or dependentSchemas entry changes nothing until something refers to it
    if key in ("dependentSchemas", "dependencies"):
        # a removed entry is a dropped constraint: the schema now accepts more
        for name in old_map:
            if name not in new_map:
                out.append(f"{_where(path + (key, name))} {key} entry removed")


def _branch_reasons(old: dict[str, Any], new: dict[str, Any], key: str, path: tuple, out: list[str]) -> None:
    if not isinstance(old.get(key), list):
        return
    old_list = old[key]
    new_list = new[key] if key in new else []
    if not isinstance(new_list, list):
        return
    old_digests, new_digests = [_digest(b) for b in old_list], [_digest(b) for b in new_list]
    # Branches present on both sides are matched by digest, so reordering is no change.
    old_left = [b for b, d in zip(old_list, old_digests) if d not in new_digests]
    new_left = [b for b, d in zip(new_list, new_digests) if d not in old_digests]
    where = _where(path)
    if key == "allOf":
        if len(new_left) < len(old_left):
            out.append(f"{where} lost an allOf branch")
    elif key not in new:
        out.append(f"{where} lost {key}")
        return
    elif len(new_left) > len(old_left):
        out.append(f"{where} {key} gained a branch")
        return
    for old_branch, new_branch in zip(old_left, new_left):
        _widening_reasons(old_branch, new_branch, path, out)


# ------------------------------------------------------------ rendering

def render_changes(changes: list[Finding], lock_path: str, tool_count: int | None = None) -> str:
    if not changes:
        count = f" ({tool_count} tools)" if tool_count is not None else ""
        return f"No changes since {lock_path}{count}."
    ordered = sorted(changes, key=lambda f: (-f.severity.rank, f.tool or "", f.kind or ""))
    lines = []
    for f in ordered:
        label = _printable(f.tool) if f.tool is not None else "(server)"
        lines.append(f"  {SEVERITY_MARK[f.severity]} {f.kind or '-':<22} {label}: {f.message}")
    counts = Counter(f.severity for f in changes)
    lines.append("")
    lines.append(f"{counts[Severity.ERROR]} errors, {counts[Severity.WARNING]} warnings, "
                 f"{counts[Severity.INFO]} info")
    return "\n".join(lines)


def _finding(kind: str, severity: Severity, tool: str | None, message: str) -> Finding:
    return Finding(rule=LOCK_RULE, severity=severity, tool=tool,
                   message=_printable(message), kind=kind)


def _snippet(text: str, start: int = 0) -> str:
    """Quote up to MAX_QUOTE characters of text from start, marking any cut with '...'."""
    end = start + MAX_QUOTE
    pre = "..." if start > 0 else ""
    post = "..." if end < len(text) else ""
    return f'"{pre}{text[start:end]}{post}"'


def _printable(text: str) -> str:
    """Escape everything outside printable ASCII so findings print on any console."""
    out = []
    for ch in text:
        cp = ord(ch)
        if 0x20 <= cp <= 0x7E:
            out.append(ch)
        elif cp <= 0xFFFF:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(f"\\U{cp:08x}")
    return "".join(out)
