"""Probe fixtures: which tools to call, with which arguments.

A fixtures file is JSON:

    {
      "version": 1,
      "probes": [
        {"tool": "read_text_file", "label": "small file",
         "args": {"path": "${FIXTURES_DIR}/sandbox/notes.txt"}},
        {"tool": "read_text_file", "label": "missing path",
         "args": {"path": "/no/such/file"}, "expect_error": true},
        {"tool": "write_file", "args": {...}, "allow_destructive": true},
        {"tool": "move_file", "args": {...}, "skip": true}
      ]
    }

Only tools listed here are ever called. ``${FIXTURES_DIR}`` (the folder that
holds the fixtures file) and ``${NAME}`` environment variables are expanded in
string arguments, so fixtures can point at a local sandbox and avoid secrets.
"""

from __future__ import annotations

import json
import os
import string
from dataclasses import dataclass, field
from typing import Any

from mcp_lint.models import ToolDef

FIXTURES_VERSION = 1

_JSON_TYPES = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
    "null": type(None),
}


class FixtureError(ValueError):
    """The fixtures file itself is malformed."""


@dataclass
class Probe:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    label: str = ""
    expect_error: bool = False
    allow_destructive: bool = False
    skip: bool = False

    @property
    def display(self) -> str:
        return f"{self.tool} ({self.label})" if self.label else self.tool


def _expand(value: Any, mapping: dict[str, str]) -> Any:
    if isinstance(value, str):
        return string.Template(value).safe_substitute(mapping)
    if isinstance(value, list):
        return [_expand(v, mapping) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v, mapping) for k, v in value.items()}
    return value


def load_fixtures(path: str) -> list[Probe]:
    with open(path, encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise FixtureError(f"{path}: not valid JSON ({exc})") from exc
    if not isinstance(data, dict) or not isinstance(data.get("probes"), list):
        raise FixtureError(f"{path}: expected an object with a 'probes' list")
    if data.get("version", FIXTURES_VERSION) != FIXTURES_VERSION:
        raise FixtureError(f"{path}: unsupported fixtures version {data.get('version')!r}")

    mapping = dict(os.environ)
    mapping["FIXTURES_DIR"] = os.path.dirname(os.path.abspath(path)).replace("\\", "/")
    probes = []
    for i, raw in enumerate(data["probes"]):
        if not isinstance(raw, dict) or not isinstance(raw.get("tool"), str):
            raise FixtureError(f"{path}: probe #{i + 1} needs a 'tool' name")
        args = raw.get("args", {})
        if not isinstance(args, dict):
            raise FixtureError(f"{path}: probe #{i + 1} 'args' must be an object")
        probes.append(
            Probe(
                tool=raw["tool"],
                args=_expand(args, mapping),
                label=str(raw.get("label", "")),
                expect_error=bool(raw.get("expect_error", False)),
                allow_destructive=bool(raw.get("allow_destructive", False)),
                skip=bool(raw.get("skip", False)),
            )
        )
    return probes


def _type_ok(value: Any, schema: dict[str, Any]) -> bool:
    types = schema.get("type")
    if types is None:
        return True
    for name in types if isinstance(types, list) else [types]:
        py = _JSON_TYPES.get(name)
        if py is None:
            return True  # unknown type keyword: don't second-guess
        if isinstance(value, bool) and name in ("integer", "number"):
            continue  # bool is an int subclass in Python, not in JSON
        if isinstance(value, py):
            return True
    return False


def check_probe(probe: Probe, tools: dict[str, ToolDef]) -> list[str]:
    """Problems that stop a probe from running. Empty list means OK to call.

    Probes marked ``expect_error`` skip argument checks: sending bad arguments
    is the point of them.
    """
    tool = tools.get(probe.tool)
    if tool is None:
        return [f"server has no tool named '{probe.tool}'"]
    problems = []
    if not tool.read_only and not probe.allow_destructive:
        problems.append(
            "tool is not marked read-only, so it may change data; "
            "add \"allow_destructive\": true to run it (sandbox only)"
        )
    if not probe.expect_error:
        required = tool.input_schema.get("required") or []
        missing = [r for r in required if r not in probe.args]
        if missing:
            problems.append(f"missing required args: {', '.join(missing)}")
        for name, value in probe.args.items():
            spec = tool.params.get(name)
            if spec is not None and not _type_ok(value, spec):
                problems.append(f"arg '{name}' should be {spec.get('type')}")
    return problems


def _placeholder(spec: dict[str, Any]) -> Any:
    if "default" in spec:
        return spec["default"]
    if spec.get("enum"):
        return spec["enum"][0]
    kind = spec.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)
    return {
        "integer": 1,
        "number": 1,
        "boolean": False,
        "array": [],
        "object": {},
    }.get(kind, "TODO")


def template(tools: list[ToolDef]) -> dict[str, Any]:
    """A starter fixtures file: one skipped probe per tool, required args stubbed."""
    probes = []
    for t in tools:
        required = t.input_schema.get("required") or []
        probe: dict[str, Any] = {
            "tool": t.name,
            "label": "",
            "args": {r: _placeholder(t.params.get(r, {})) for r in required},
            "skip": True,
        }
        if not t.read_only:
            probe["_warning"] = "not marked read-only: may change data"
        probes.append(probe)
    return {
        "version": FIXTURES_VERSION,
        "_help": "Fill in args, then delete \"skip\" for each probe to run. "
        "Only listed tools are called. Tools not marked read-only also need "
        "\"allow_destructive\": true; only use that against a sandbox. "
        "${FIXTURES_DIR} expands to this file's folder.",
        "probes": probes,
    }
