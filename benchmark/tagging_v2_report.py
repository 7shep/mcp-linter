"""Diff the draft v2 tagger against v1 on the 18 saved survey tool lists.

Usage (from the repo root):

    python benchmark/tagging_v2_report.py           write results/tagging_v2_survey_diff.json and .md
    python benchmark/tagging_v2_report.py --check   exit 1 if either committed file is stale

For every tool, both taggers run in both profiles. A tool is listed when its tag
set changed under a profile, with the v1 and v2 tags and the v2 rule ids that
produced the new evidence. Each server records whether its trifecta flag
(its tools' tags together hold all three) changed.

The v2 rules were tuned on the AgentDojo export, not on these lists, but the
survey was already used to tune v1, so this is a check on v2, not a holdout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import tag_survey  # noqa: E402
import tagging  # noqa: E402
import tagging_v2  # noqa: E402
from tagging import ALL_TAGS, PROFILES, tags_for  # noqa: E402

RESULTS_DIR = tag_survey.RESULTS_DIR
JSON_PATH = os.path.join(RESULTS_DIR, "tagging_v2_survey_diff.json")
MD_PATH = os.path.join(RESULTS_DIR, "tagging_v2_survey_diff.md")
PROFILE_ORDER = tag_survey.PROFILE_ORDER


def _values(tags) -> list[str]:
    return sorted(t.value for t in tags)


def _new_rules(v1_evidence, v2_evidence, profile: str) -> list[str]:
    """Rule ids of v2-only evidence that counts under ``profile``."""
    old = set(v1_evidence)
    allowed = PROFILES[profile]
    return sorted({e.rule for e in v2_evidence if e not in old and e.confidence in allowed})


def build_report(tools_dir: str = tag_survey.TOOLS_DIR) -> dict:
    servers = tag_survey.load_servers(tools_dir)
    names = sorted(servers)

    server_block: dict = {}
    changed_totals = {p: 0 for p in PROFILE_ORDER}
    gains = {p: 0 for p in PROFILE_ORDER}
    losses = {p: 0 for p in PROFILE_ORDER}
    trifecta_v1 = {p: 0 for p in PROFILE_ORDER}
    trifecta_v2 = {p: 0 for p in PROFILE_ORDER}
    trifecta_changed: dict[str, list[str]] = {p: [] for p in PROFILE_ORDER}
    tool_count = 0

    for server in names:
        changed: list[dict] = []
        union_v1 = {p: set() for p in PROFILE_ORDER}
        union_v2 = {p: set() for p in PROFILE_ORDER}
        tools = servers[server]
        tool_count += len(tools)
        for tool in tools:
            v1 = tagging.tag_tool(tool)
            v2 = tagging_v2.tag_tool(tool)
            for p in PROFILE_ORDER:
                a = tags_for(v1, p)
                b = tags_for(v2, p)
                union_v1[p] |= a
                union_v2[p] |= b
                if a == b:
                    continue
                gains[p] += len(b - a)
                losses[p] += len(a - b)
                changed_totals[p] += 1
                changed.append({
                    "tool": tool.name,
                    "profile": p,
                    "v1_tags": _values(a),
                    "v2_tags": _values(b),
                    "new_rules": _new_rules(v1, v2, p),
                })
        trifecta = {}
        for p in PROFILE_ORDER:
            was = ALL_TAGS <= union_v1[p]
            now = ALL_TAGS <= union_v2[p]
            trifecta_v1[p] += was
            trifecta_v2[p] += now
            if was != now:
                trifecta_changed[p].append(server)
            trifecta[p] = {"v1": was, "v2": now}
        server_block[server] = {
            "split": tag_survey.split_of(server),
            "tools": len(tools),
            "changed_tools": changed,
            "trifecta": trifecta,
        }

    totals = {
        "servers": len(names),
        "tools": tool_count,
        "profiles": {
            p: {
                "tools_changed": changed_totals[p],
                "tag_gains": gains[p],
                "tag_losses": losses[p],
                "servers_trifecta_v1": trifecta_v1[p],
                "servers_trifecta_v2": trifecta_v2[p],
                "servers_trifecta_changed": trifecta_changed[p],
            }
            for p in PROFILE_ORDER
        },
    }
    return {"tagger": tagging_v2.VERSION, "totals": totals, "servers": server_block}


# ---------------------------------------------------------------- markdown

def _md_cell(value) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _table(headers: list[str], body: list[list]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in body:
        lines.append("| " + " | ".join(_md_cell(c) for c in row) + " |")
    return lines


def _tags_text(values: list[str]) -> str:
    return ", ".join(values) if values else "none"


def _yes(flag: bool) -> str:
    return "yes" if flag else "no"


def render_markdown(report: dict) -> str:
    totals = report["totals"]
    servers = report["servers"]
    names = sorted(servers)
    out = [
        "# Draft v2 tagger against v1: survey diff",
        "",
        "Draft v2 (`benchmark/tagging_v2.py`) is v1 plus new evidence, so no tag is lost. "
        "The rules were tuned on AgentDojo; these 18 survey lists are a check, not a holdout, "
        "and v1 was already tuned on them.",
        "",
        "## Totals",
        "",
    ]
    body = []
    for p in PROFILE_ORDER:
        t = totals["profiles"][p]
        body.append([p, t["tools_changed"], t["tag_gains"], t["tag_losses"],
                     f"{t['servers_trifecta_v1']} -> {t['servers_trifecta_v2']}",
                     _tags_text(t["servers_trifecta_changed"])])
    out += [f"Servers: {totals['servers']}. Tools: {totals['tools']}.", ""]
    out += _table(["Profile", "Tools changed", "Tags gained", "Tags lost",
                   "Servers with trifecta (v1 -> v2)", "Trifecta flag changed"], body)
    out.append("")

    out += ["## Per server", ""]
    out += _table(
        ["Server", "Split", "Tools", "Tools changed strict", "Tools changed inclusive",
         "Trifecta strict (v1 -> v2)", "Trifecta inclusive (v1 -> v2)"],
        [[s, servers[s]["split"], servers[s]["tools"],
          sum(1 for c in servers[s]["changed_tools"] if c["profile"] == "strict"),
          sum(1 for c in servers[s]["changed_tools"] if c["profile"] == "inclusive"),
          f"{_yes(servers[s]['trifecta']['strict']['v1'])} -> {_yes(servers[s]['trifecta']['strict']['v2'])}",
          f"{_yes(servers[s]['trifecta']['inclusive']['v1'])} -> {_yes(servers[s]['trifecta']['inclusive']['v2'])}"]
         for s in names],
    )
    out.append("")

    out += ["## Changed tools", ""]
    rows = [[s, c["tool"], c["profile"], _tags_text(c["v1_tags"]), _tags_text(c["v2_tags"]),
             _tags_text(c["new_rules"])]
            for s in names for c in servers[s]["changed_tools"]]
    if rows:
        out += _table(["Server", "Tool", "Profile", "v1 tags", "v2 tags", "New rules"], rows)
    else:
        out.append("No tool changed.")
    out.append("")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- CLI

def _read_exact(path: str):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:  # universal newlines: a CRLF checkout is not stale
        return f.read()


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diff the draft v2 tagger against v1 on the survey.")
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
        print("tagging_v2_survey_diff.json and .md are up to date")
        return 0

    os.makedirs(RESULTS_DIR, exist_ok=True)
    _write(JSON_PATH, json_text)
    _write(MD_PATH, md_text)
    print(f"wrote {JSON_PATH}")
    print(f"wrote {MD_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
