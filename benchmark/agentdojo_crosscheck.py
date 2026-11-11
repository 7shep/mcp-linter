"""Cross-check the frozen tagger against the AgentDojo attack paths.

Usage (from the repo root):

    python benchmark/agentdojo_crosscheck.py           write results/agentdojo/crosscheck.json and .md
    python benchmark/agentdojo_crosscheck.py --check   exit 1 if either committed file is stale

The tagger in tagging.py is frozen. It reads tool names, input schema structure
and annotations only, never descriptions. The inputs hold tool names, task ids
and hand labels only; no AgentDojo prompt or goal text is read or written, and
agentdojo is not imported.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from mcp_lint.models import ToolDef  # noqa: E402
from tagging import ALL_TAGS, Tag, tag_tool, tags_for  # noqa: E402

AGENTDOJO_DIR = os.path.join(HERE, "results", "agentdojo")
TOOLS_DIR = os.path.join(AGENTDOJO_DIR, "tools")
CASES_PATH = os.path.join(AGENTDOJO_DIR, "cases.json")
KINDS_PATH = os.path.join(AGENTDOJO_DIR, "attack_kinds.json")
JSON_PATH = os.path.join(AGENTDOJO_DIR, "crosscheck.json")
MD_PATH = os.path.join(AGENTDOJO_DIR, "crosscheck.md")

PROFILE_ORDER = ("strict", "inclusive")
PRIVATE = Tag.PRIVATE_READ.value
UNTRUSTED = Tag.UNTRUSTED_READ.value
EXTERNAL = Tag.EXTERNAL_WRITE.value
ALL_TAG_VALUES = frozenset(t.value for t in ALL_TAGS)
KINDS = ("exfil", "action", "text")
COUNT_KEYS = (
    "security_cases", "exfil_cases", "path_covered", "fail_source_u", "fail_private_p",
    "fail_sink_e", "action_cases", "action_sink_e", "text_cases",
)
MISSED_KEYS = ("missed_sources", "missed_private", "missed_sinks")


# ---------------------------------------------------------------- logic

def tags_by_tool(tools: list[ToolDef], profile: str) -> dict[str, frozenset[str]]:
    """Tool name -> tag values under ``profile``, for tools with at least one tag."""
    out: dict[str, frozenset[str]] = {}
    for tool in tools:
        tags = frozenset(t.value for t in tags_for(tag_tool(tool), profile))
        if tags:
            out[tool.name] = tags
    return out


def has(tags: dict[str, frozenset[str]], tool: str, tag: str) -> bool:
    return tag in tags.get(tool, frozenset())


def evaluate_case(source_tools, sinks, private_sources, kind: str,
                  tags: dict[str, frozenset[str]]) -> dict:
    """One (user task, injection task) pair. Pure: tags come in as data.

    ``private_sources`` is only consulted for exfil cases; an empty list means
    the data is already in the agent's context, so that leg holds.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown attack kind {kind!r}")
    source_u = any(has(tags, s, UNTRUSTED) for s in source_tools)
    sink_e = any(has(tags, s, EXTERNAL) for s in sinks)
    if kind != "exfil":
        return {"kind": kind, "source_u": source_u, "sink_e": sink_e,
                "private_p": None, "path_covered": False}
    private_p = (not private_sources) or any(has(tags, s, PRIVATE) for s in private_sources)
    return {"kind": kind, "source_u": source_u, "sink_e": sink_e,
            "private_p": private_p, "path_covered": bool(source_u and private_p and sink_e)}


def summarize_suite(user_tasks: dict, injection_tasks: dict, kinds: dict,
                    tags: dict[str, frozenset[str]]) -> dict:
    """Case counts and missed-tool lists for one suite."""
    if set(kinds) != set(injection_tasks):
        raise ValueError("attack_kinds ids do not match cases injection_tasks ids")
    counts = dict.fromkeys(COUNT_KEYS, 0)
    for uid in sorted(user_tasks):
        source_tools = user_tasks[uid]["source_tools"]
        for iid in sorted(injection_tasks):
            entry = kinds[iid]
            leg = evaluate_case(source_tools, entry["sinks"], entry["private_sources"],
                                entry["kind"], tags)
            counts["security_cases"] += 1
            if leg["kind"] == "exfil":
                counts["exfil_cases"] += 1
                counts["path_covered"] += leg["path_covered"]
                counts["fail_source_u"] += not leg["source_u"]
                counts["fail_private_p"] += not leg["private_p"]
                counts["fail_sink_e"] += not leg["sink_e"]
            elif leg["kind"] == "action":
                counts["action_cases"] += 1
                counts["action_sink_e"] += leg["sink_e"]
            else:
                counts["text_cases"] += 1

    exfil = [kinds[i] for i in sorted(kinds) if kinds[i]["kind"] == "exfil"]
    missed_sources = sorted({s for u in user_tasks.values() for s in u["source_tools"]
                             if not has(tags, s, UNTRUSTED)})
    missed_private = sorted({s for e in exfil for s in e["private_sources"]
                             if not has(tags, s, PRIVATE)})
    missed_sinks = sorted({s for e in exfil for s in e["sinks"] if not has(tags, s, EXTERNAL)})
    return {**counts, "missed_sources": missed_sources,
            "missed_private": missed_private, "missed_sinks": missed_sinks}


def suite_block(tools: list[ToolDef], user_tasks: dict, injection_tasks: dict,
                kinds: dict, profile: str) -> dict:
    tags = tags_by_tool(tools, profile)
    union = frozenset().union(*tags.values()) if tags else frozenset()
    return {
        "flagged": ALL_TAG_VALUES <= union,
        "tool_tags": {name: sorted(tags[name]) for name in sorted(tags)},
        **summarize_suite(user_tasks, injection_tasks, kinds, tags),
    }


def total_block(suites: dict[str, dict]) -> dict:
    total: dict = dict.fromkeys(COUNT_KEYS, 0)
    for block in suites.values():
        for key in COUNT_KEYS:
            total[key] += block[key]
    total["flagged_suites"] = sum(1 for b in suites.values() if b["flagged"])
    for key in MISSED_KEYS:
        total[key] = sum(len(b[key]) for b in suites.values())
    return total


def _load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_tools(tools_dir: str, suite: str) -> list[ToolDef]:
    data = _load_json(os.path.join(tools_dir, f"{suite}.json"))
    tools = [ToolDef.from_dict(t) for t in data["tools"]]
    names = [t.name for t in tools]
    if len(set(names)) != len(names):
        raise ValueError(f"{suite}: duplicate tool names, so tool tags are ambiguous")
    return tools


def build_report(tools_dir: str = TOOLS_DIR, cases_path: str = CASES_PATH,
                 kinds_path: str = KINDS_PATH) -> dict:
    cases = _load_json(cases_path)
    kinds_doc = _load_json(kinds_path)
    case_suites = cases["suites"]
    kind_suites = kinds_doc["suites"]
    if set(case_suites) != set(kind_suites):
        raise ValueError("cases.json and attack_kinds.json list different suites")

    tools = {s: load_tools(tools_dir, s) for s in sorted(case_suites)}
    profiles = {}
    for profile in PROFILE_ORDER:
        suites = {
            s: suite_block(tools[s], case_suites[s]["user_tasks"],
                           case_suites[s]["injection_tasks"], kind_suites[s], profile)
            for s in sorted(case_suites)
        }
        profiles[profile] = {"suites": suites, "total": total_block(suites)}
    return {"benchmark_version": cases["benchmark_version"], "profiles": profiles}


# ---------------------------------------------------------------- markdown

def _md_cell(value) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _table(headers: list[str], body: list[list]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in body:
        lines.append("| " + " | ".join(_md_cell(c) for c in row) + " |")
    return lines


def _yes(flag: bool) -> str:
    return "yes" if flag else "no"


def render_markdown(report: dict) -> str:
    out = [
        "# AgentDojo cross-check of the frozen tagger",
        "",
        "The tagger in `benchmark/tagging.py` is frozen. It reads tool names, input schema "
        "structure and annotations only, never descriptions. Inputs are a "
        f"{report['benchmark_version']} export of tool names, task ids and hand labels; "
        "no task text is included.",
        "",
        "Exfil cases are checked for the three legs: a source tool tagged UNTRUSTED_READ, "
        "a private source tagged PRIVATE_READ (or none, when the data is already in "
        "context), and a sink tagged EXTERNAL_WRITE. Action and text cases are counted "
        "but do not count toward exfil numbers.",
        "",
    ]
    for profile in PROFILE_ORDER:
        block = report["profiles"][profile]
        suites = block["suites"]
        total = block["total"]
        names = sorted(suites)
        out += [f"## Profile: {profile}", ""]
        rows = [[s, _yes(suites[s]["flagged"]), suites[s]["exfil_cases"], suites[s]["path_covered"],
                 f"{len(suites[s]['missed_sources'])} / {len(suites[s]['missed_private'])} / "
                 f"{len(suites[s]['missed_sinks'])}"] for s in names]
        rows.append(["Total", f"{total['flagged_suites']} of {len(names)}", total["exfil_cases"],
                     total["path_covered"],
                     f"{total['missed_sources']} / {total['missed_private']} / {total['missed_sinks']}"])
        out += _table(["Suite", "Flagged", "Exfil cases", "Path covered",
                       "Missed source / private / sink"], rows)
        out.append("")
        out += _table(
            ["Suite", "Exfil fail source_u", "Exfil fail private_p", "Exfil fail sink_e",
             "Action cases", "Action with sink_e", "Text cases", "Security cases"],
            [[s, suites[s]["fail_source_u"], suites[s]["fail_private_p"], suites[s]["fail_sink_e"],
              suites[s]["action_cases"], suites[s]["action_sink_e"], suites[s]["text_cases"],
              suites[s]["security_cases"]] for s in names]
            + [["Total", total["fail_source_u"], total["fail_private_p"], total["fail_sink_e"],
                total["action_cases"], total["action_sink_e"], total["text_cases"],
                total["security_cases"]]],
        )
        out.append("")
        out += ["### Missed tools", ""]
        for s in names:
            for key, label in (("missed_sources", "source (UNTRUSTED_READ)"),
                               ("missed_private", "private (PRIVATE_READ)"),
                               ("missed_sinks", "sink (EXTERNAL_WRITE)")):
                items = suites[s][key]
                shown = ", ".join(f"`{_md_cell(i)}`" for i in items) if items else "none"
                out.append(f"- {s}, {label}: {shown}")
        out.append("")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- CLI

def _read_exact(path: str):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cross-check the tagger against AgentDojo paths.")
    parser.add_argument("--check", action="store_true",
                        help="recompute and exit 1 if a committed output file differs")
    args = parser.parse_args(argv)
    try:
        report = build_report()
    except ValueError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 2

    json_text = json.dumps(report, indent=1, sort_keys=True) + "\n"
    md_text = render_markdown(report)

    if args.check:
        stale = [p for p, text in ((JSON_PATH, json_text), (MD_PATH, md_text))
                 if _read_exact(p) != text]
        for p in stale:
            print(f"stale or missing: {p}")
        if stale:
            return 1
        print("crosscheck.json and crosscheck.md are up to date")
        return 0

    _write(JSON_PATH, json_text)
    _write(MD_PATH, md_text)
    print(f"wrote {JSON_PATH}")
    print(f"wrote {MD_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
