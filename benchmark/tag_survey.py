"""Tag the 18 saved tool lists in survey/tools/ and write the tagging survey.

Usage (from the repo root):

    python benchmark/tag_survey.py           write results/tagging_survey.json and .md
    python benchmark/tag_survey.py --check   exit 1 if the committed JSON is stale

The tagger in tagging.py is frozen. Reviewed false positives and false negatives
live in results/survey_review.json and are checked against the tagger's output
before they are counted.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from mcp_lint.models import ToolDef  # noqa: E402
from tagging import ALL_TAGS, Tag, minimal_trifecta_sets, tag_tool, tags_for  # noqa: E402

REPO = os.path.dirname(HERE)
TOOLS_DIR = os.path.join(REPO, "survey", "tools")
RESULTS_DIR = os.path.join(HERE, "results")
REVIEW_PATH = os.path.join(RESULTS_DIR, "survey_review.json")
JSON_PATH = os.path.join(RESULTS_DIR, "tagging_survey.json")
MD_PATH = os.path.join(RESULTS_DIR, "tagging_survey.md")

RULES_NOTE = "Rules were tuned while reading the dev lists and frozen before the holdout lists were tagged."
DEV_SERVERS = frozenset(
    "filesystem git fetch memory time everything github desktop-commander notion".split()
)
PROFILE_ORDER = ("strict", "inclusive")
SPLIT_ORDER = ("dev", "holdout", "all")
TAG_ORDER = tuple(t.value for t in Tag)
TAG_VALUES = frozenset(TAG_ORDER)
REVIEW_KEYS = frozenset({"apparent_false_positives", "apparent_false_negatives"})
REVIEW_ENTRY_KEYS = frozenset({"server", "tool", "tag", "reason"})
MINIMAL_SET_LIMIT = 25


def split_of(server: str) -> str:
    return "dev" if server in DEV_SERVERS else "holdout"


def load_servers(tools_dir: str) -> dict[str, list[ToolDef]]:
    """Map each survey file's stem (the server name) to its tools, in file order."""
    servers: dict[str, list[ToolDef]] = {}
    for path in sorted(glob.glob(os.path.join(tools_dir, "*.json"))):
        server = os.path.splitext(os.path.basename(path))[0]
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        tools = [ToolDef.from_dict(t) for t in data["tools"]]
        names = [t.name for t in tools]
        if len(set(names)) != len(names):
            raise ValueError(f"{server}: duplicate tool names, so (server, tool) is ambiguous")
        servers[server] = tools
    return servers


def _evidence_json(evidence) -> list[dict]:
    ordered = sorted(evidence, key=lambda e: (e.tag.value, e.confidence, e.rule))
    return [{"tag": e.tag.value, "confidence": e.confidence, "rule": e.rule, "detail": e.detail}
            for e in ordered]


def _server_stats(rows, profile: str, removed=frozenset()) -> dict:
    """Tagged tool count, per-tag tool counts and the set of tags a server holds.

    ``rows`` is [(tool name, evidence)]; ``removed`` holds (server, tool, tag)
    assignments to ignore, applied through the caller's server name in ``rows``.
    """
    tagged = 0
    per_tag = dict.fromkeys(TAG_ORDER, 0)
    held: set[Tag] = set()
    for name, server, evidence in rows:
        tags = {t for t in tags_for(evidence, profile) if (server, name, t.value) not in removed}
        if tags:
            tagged += 1
        for t in tags:
            per_tag[t.value] += 1
        held |= tags
    return {"tagged": tagged, "per_tag": per_tag, "held": held}


def _minimal_block(held_by_server: dict[str, set[Tag]]) -> dict:
    sets = sorted(sorted(s) for s in minimal_trifecta_sets(held_by_server))
    return {
        "size": len(sets[0]) if sets else None,
        "count": len(sets),
        "sets": sets[:MINIMAL_SET_LIMIT],
    }


def _rate(part: int, whole: int):
    return round(part / whole, 4) if whole else None


def _review(path: str, servers: dict[str, list[ToolDef]]):
    """Validate the reviewed entries; return (false positives, false negatives).

    Each returned item is (public entry dict, {profile: bool counted under it}).
    """
    with open(path, encoding="utf-8") as f:
        review = json.load(f)
    if not isinstance(review, dict) or set(review) != REVIEW_KEYS:
        raise ValueError(f"{path}: expected exactly the keys {sorted(REVIEW_KEYS)}")

    evidence = {(s, t.name): tag_tool(t) for s, tools in servers.items() for t in tools}
    fps: list = []
    fns: list = []
    for kind, key, out in (
        ("false positive", "apparent_false_positives", fps),
        ("false negative", "apparent_false_negatives", fns),
    ):
        items = review[key]
        if not isinstance(items, list):
            raise ValueError(f"{path}: {key} must be a list")
        for entry in items:
            if (not isinstance(entry, dict) or set(entry) != REVIEW_ENTRY_KEYS
                    or not all(isinstance(v, str) for v in entry.values())):
                raise ValueError(f"{kind} entry needs string server, tool, tag and reason: {entry!r}")
            server, tool, tag = entry["server"], entry["tool"], entry["tag"]
            label = f"{kind} {server}/{tool} {tag}"
            if (server, tool) not in evidence:
                raise ValueError(f"{label}: no such tool in the survey")
            if tag not in TAG_VALUES:
                raise ValueError(f"{label}: unknown tag {tag!r}")
            ev = evidence[(server, tool)]
            assigned_inclusive = tags_for(ev, "inclusive")
            if kind == "false positive" and Tag(tag) not in assigned_inclusive:
                raise ValueError(f"{label}: the tagger did not assign {tag} under inclusive")
            if kind == "false negative" and Tag(tag) in assigned_inclusive:
                raise ValueError(f"{label}: the tagger already assigns {tag} under inclusive")
            counted = {p: Tag(tag) in tags_for(ev, p) for p in PROFILE_ORDER}
            public = {
                "server": server,
                "tool": tool,
                "tag": tag,
                "reason": entry["reason"],
                "split": split_of(server),
                "in_strict": counted["strict"],
            }
            out.append((public, counted))
    return fps, fns


def build_report(tools_dir: str = TOOLS_DIR, review_path: str = REVIEW_PATH) -> dict:
    """Tag every saved tool list and return the survey as plain JSON-ready data."""
    servers = load_servers(tools_dir)
    rows = {s: [(t.name, s, tag_tool(t)) for t in tools] for s, tools in servers.items()}
    names = sorted(servers)
    split = {s: split_of(s) for s in names}

    stats = {p: {s: _server_stats(rows[s], p) for s in names} for p in PROFILE_ORDER}

    server_block = {}
    for s in names:
        server_block[s] = {
            "split": split[s],
            "tools": len(rows[s]),
            "tagged": {p: stats[p][s]["tagged"] for p in PROFILE_ORDER},
            "per_tag": {p: stats[p][s]["per_tag"] for p in PROFILE_ORDER},
            "trifecta": {p: ALL_TAGS <= stats[p][s]["held"] for p in PROFILE_ORDER},
        }

    tools_block = {}
    for s in names:
        tools_block[s] = [
            {"tool": name, "evidence": _evidence_json(ev)}
            for (name, _, ev) in rows[s] if ev
        ]

    totals = {}
    for p in PROFILE_ORDER:
        totals[p] = {}
        for sp in SPLIT_ORDER:
            members = [s for s in names if sp in ("all", split[s])]
            per_tag = dict.fromkeys(TAG_ORDER, 0)
            for s in members:
                for tag, count in stats[p][s]["per_tag"].items():
                    per_tag[tag] += count
            totals[p][sp] = {
                "tools": sum(len(rows[s]) for s in members),
                "tagged": sum(stats[p][s]["tagged"] for s in members),
                "per_tag": per_tag,
                "servers_trifecta": sum(ALL_TAGS <= stats[p][s]["held"] for s in members),
            }

    minimal_before = {
        p: _minimal_block({s: stats[p][s]["held"] for s in names}) for p in PROFILE_ORDER
    }

    hits: dict[tuple[str, str, str], int] = {}
    for s in names:
        for _, _, ev in rows[s]:
            for key in {(e.rule, e.tag.value, e.confidence) for e in ev}:
                hits[key] = hits.get(key, 0) + 1
    rule_hits = [
        {"rule": r, "tag": t, "confidence": c, "tools": n}
        for (r, t, c), n in sorted(hits.items())
    ]

    fps, fns = _review(review_path, servers)

    fp_block: dict = {"entries": [e for e, _ in fps], "by_profile": {}}
    for p in PROFILE_ORDER:
        fp_block["by_profile"][p] = {}
        for sp in SPLIT_ORDER:
            in_split = [s for s in names if sp in ("all", split[s])]
            assigned = dict.fromkeys(TAG_ORDER, 0)
            for s in in_split:
                for tag, count in stats[p][s]["per_tag"].items():
                    assigned[tag] += count
            apparent = dict.fromkeys(TAG_ORDER, 0)
            for entry, counted in fps:
                if (sp == "all" or entry["split"] == sp) and counted[p]:
                    apparent[entry["tag"]] += 1
            total_assigned = sum(assigned.values())
            total_fp = sum(apparent.values())
            fp_block["by_profile"][p][sp] = {
                "assigned": total_assigned,
                "apparent_fp": total_fp,
                "rate": _rate(total_fp, total_assigned),
                "per_tag": {
                    t: {"assigned": assigned[t], "apparent_fp": apparent[t],
                        "rate": _rate(apparent[t], assigned[t])}
                    for t in TAG_ORDER
                },
            }

    fn_block = {
        "entries": [e for e, _ in fns],
        "by_split": {sp: sum(1 for e, _ in fns if sp == "all" or e["split"] == sp)
                     for sp in SPLIT_ORDER},
    }

    after = {}
    for p in PROFILE_ORDER:
        removed = {(e["server"], e["tool"], e["tag"]) for e, counted in fps if counted[p]}
        held_after = {
            s: _server_stats(rows[s], p, removed)["held"] for s in names
        }
        after[p] = {
            "trifecta_servers": sorted(s for s in names if ALL_TAGS <= held_after[s]),
            "minimal_sets": _minimal_block(held_after),
            # Singletons hide every multi-server combination, so also search without them.
            "minimal_sets_without_singletons": _minimal_block(
                {s: held for s, held in held_after.items() if not ALL_TAGS <= held}),
        }

    return {
        "rules_note": RULES_NOTE,
        "servers": server_block,
        "tools": tools_block,
        "totals": totals,
        "rule_hits": rule_hits,
        "minimal_sets": minimal_before,
        "false_positives": fp_block,
        "false_negatives": fn_block,
        "trifecta_after_review": after,
    }


# ---------------------------------------------------------------- markdown

def _md_cell(value) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _table(headers: list[str], body: list[list]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in body:
        lines.append("| " + " | ".join(_md_cell(c) for c in row) + " |")
    return lines


def _pct(rate) -> str:
    return "n/a" if rate is None else f"{rate:.1%}"


def _yes(flag: bool) -> str:
    return "yes" if flag else "no"


def _pue(per_tag: dict) -> str:
    return "/".join(str(per_tag[t]) for t in TAG_ORDER)


def _minimal_lines(title: str, block: dict) -> list[str]:
    lines = [f"### {title}", ""]
    if block["size"] is None:
        lines.append("No set of one to three servers holds all three tags.")
    else:
        lines.append(f"Smallest size: {block['size']} server(s). {block['count']} set(s) in total; "
                     f"first {len(block['sets'])} shown.")
    lines.append("")
    lines.extend(f"- {' + '.join(s)}" for s in block["sets"])
    lines.append("")
    return lines


def render_markdown(report: dict) -> str:
    servers = report["servers"]
    names = sorted(servers)
    out = ["# Tagging survey: 18 saved MCP tool lists", "", report["rules_note"], ""]

    out += ["## Per server", ""]
    out += _table(
        ["Server", "Split", "Tools", "Tagged strict", "Tagged inclusive", "P/U/E strict",
         "P/U/E inclusive", "Trifecta strict", "Trifecta inclusive"],
        [[s, servers[s]["split"], servers[s]["tools"],
          servers[s]["tagged"]["strict"], servers[s]["tagged"]["inclusive"],
          _pue(servers[s]["per_tag"]["strict"]), _pue(servers[s]["per_tag"]["inclusive"]),
          _yes(servers[s]["trifecta"]["strict"]), _yes(servers[s]["trifecta"]["inclusive"])]
         for s in names],
    )
    out += ["", "P/U/E = PRIVATE_READ / UNTRUSTED_READ / EXTERNAL_WRITE tool counts.", ""]

    out += ["## Totals", ""]
    body = []
    for sp in SPLIT_ORDER:
        for p in PROFILE_ORDER:
            t = report["totals"][p][sp]
            body.append([sp, p, t["tools"], t["tagged"], t["per_tag"]["PRIVATE_READ"],
                         t["per_tag"]["UNTRUSTED_READ"], t["per_tag"]["EXTERNAL_WRITE"],
                         t["servers_trifecta"]])
    out += _table(["Split", "Profile", "Tools", "Tools tagged", "PRIVATE_READ",
                   "UNTRUSTED_READ", "EXTERNAL_WRITE", "Servers with trifecta"], body)
    out.append("")

    out += ["## Rule hits", ""]
    out += _table(["Rule", "Tag", "Confidence", "Tools"],
                  [[h["rule"], h["tag"], h["confidence"], h["tools"]] for h in report["rule_hits"]])
    out.append("")

    out += ["## False positives", ""]
    body = []
    for p in PROFILE_ORDER:
        for sp in SPLIT_ORDER:
            block = report["false_positives"]["by_profile"][p][sp]
            body.append([p, sp, "(all)", block["assigned"], block["apparent_fp"], _pct(block["rate"])])
            for t in TAG_ORDER:
                row = block["per_tag"][t]
                body.append([p, sp, t, row["assigned"], row["apparent_fp"], _pct(row["rate"])])
    out += _table(["Profile", "Split", "Tag", "Assigned", "Apparent FP", "Rate"], body)
    out.append("")

    out += ["## False-positive entries", ""]
    fp_entries = report["false_positives"]["entries"]
    if fp_entries:
        out += _table(["Server", "Tool", "Tag", "Split", "In strict", "Reason"],
                      [[e["server"], e["tool"], e["tag"], e["split"], _yes(e["in_strict"]), e["reason"]]
                       for e in fp_entries])
    else:
        out.append("No entries.")
    out.append("")

    out += ["## False-negative entries", ""]
    fn_entries = report["false_negatives"]["entries"]
    if fn_entries:
        out += _table(["Server", "Tool", "Tag", "Split", "Reason"],
                      [[e["server"], e["tool"], e["tag"], e["split"], e["reason"]] for e in fn_entries])
    else:
        out.append("No entries.")
    out.append("")

    out += ["## Minimal sets before review", ""]
    for p in PROFILE_ORDER:
        out += _minimal_lines(p, report["minimal_sets"][p])

    out += ["## Minimal sets after review", ""]
    for p in PROFILE_ORDER:
        after = report["trifecta_after_review"][p]
        trifecta = ", ".join(after["trifecta_servers"]) or "none"
        out.append(f"Servers with a trifecta after review ({p}): {trifecta}")
        out.append("")
        out += _minimal_lines(p, after["minimal_sets"])
        out += ["Leaving out servers that hold all three alone:", ""]
        out += _minimal_lines(p, after["minimal_sets_without_singletons"])

    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- CLI

def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def _diff_paths(expected, actual, path: str = "", found: list[str] | None = None) -> list[str]:
    """Paths where ``actual`` differs from ``expected`` (first few only)."""
    if found is None:
        found = []
    if len(found) >= 10:
        return found
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual)):
            sub = f"{path}.{key}" if path else str(key)
            if key in expected and key in actual:
                _diff_paths(expected[key], actual[key], sub, found)
            else:
                found.append(f"{sub} (only in {'committed' if key in expected else 'recomputed'})")
    elif isinstance(expected, list) and isinstance(actual, list) and len(expected) == len(actual):
        for i, (a, b) in enumerate(zip(expected, actual)):
            _diff_paths(a, b, f"{path}[{i}]", found)
    elif type(expected) is not type(actual) or expected != actual:
        found.append(path or "(root)")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Tag survey/tools and write the tagging survey.")
    parser.add_argument("--check", action="store_true",
                        help="recompute and exit 1 if the committed JSON differs")
    args = parser.parse_args(argv)
    try:
        report = build_report(TOOLS_DIR, REVIEW_PATH)
    except ValueError as exc:
        print(f"review error: {exc}", file=sys.stderr)
        return 2

    if args.check:
        if not os.path.exists(JSON_PATH):
            print(f"missing {JSON_PATH}; run without --check first", file=sys.stderr)
            return 1
        with open(JSON_PATH, encoding="utf-8") as f:
            committed = json.load(f)
        current = json.loads(json.dumps(report))
        diffs = _diff_paths(committed, current)
        if diffs:
            print("tagging_survey.json is stale; differs at:")
            for d in diffs:
                print(f"  {d}")
            return 1
        print("tagging_survey.json is up to date")
        return 0

    os.makedirs(RESULTS_DIR, exist_ok=True)
    _write(JSON_PATH, json.dumps(report, indent=2, sort_keys=True) + "\n")
    _write(MD_PATH, render_markdown(report))
    print(f"wrote {JSON_PATH}")
    print(f"wrote {MD_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
