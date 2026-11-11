"""Score the v1 and draft v2 taggers once against the blind holdout labels.

Usage (from the repo root):

    python benchmark/holdout_score.py           write results/holdout_score.json and .md
    python benchmark/holdout_score.py --check   exit 1 if the committed outputs are stale

Labels in benchmark/holdout/labels/ were written and committed before either
tagger was run on these servers. Each tool has a yes/no label for P (private
read), U (untrusted read) and E (external write). The score compares those
with each tagger's tags per tool, per profile, and with each server's
trifecta flag (the union of its tools' tags holds all three).
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from mcp_lint.models import ToolDef  # noqa: E402
import tagging  # noqa: E402
import tagging_v2  # noqa: E402

HOLDOUT = os.path.join(HERE, "holdout")
RESULTS = os.path.join(HERE, "results")
JSON_PATH = os.path.join(RESULTS, "holdout_score.json")
MD_PATH = os.path.join(RESULTS, "holdout_score.md")
LEGS = {"P": tagging.Tag.PRIVATE_READ, "U": tagging.Tag.UNTRUSTED_READ, "E": tagging.Tag.EXTERNAL_WRITE}
TAGGERS = {"v1": tagging.tag_tool, "v2": tagging_v2.tag_tool}
PROFILES = ("strict", "inclusive")


def wilson(k: int, n: int) -> list[float] | None:
    if n == 0:
        return None
    z = 1.959963984540054
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def rate(k: int, n: int) -> dict:
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "wilson": wilson(k, n)}


def load_labels() -> dict[str, dict[str, dict]]:
    labels: dict[str, dict[str, dict]] = {}
    for path in sorted(glob.glob(os.path.join(HOLDOUT, "labels", "*.json"))):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        labels.setdefault(data["server"], {}).update(data["tools"])
    return labels


def load_tools() -> dict[str, list[ToolDef]]:
    servers = {}
    for path in sorted(glob.glob(os.path.join(HOLDOUT, "tools", "*.json"))):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        servers[os.path.splitext(os.path.basename(path))[0]] = [ToolDef.from_dict(t) for t in data["tools"]]
    return servers


def confusion(pairs: list[tuple[bool, bool]]) -> dict:
    tp = sum(1 for truth, got in pairs if truth and got)
    fp = sum(1 for truth, got in pairs if not truth and got)
    fn = sum(1 for truth, got in pairs if truth and not got)
    tn = len(pairs) - tp - fp - fn
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": rate(tp, tp + fn), "precision": rate(tp, tp + fp)}


def build() -> dict:
    tools = load_tools()
    labels = load_labels()
    if set(tools) != set(labels):
        raise SystemExit(f"servers with tools {sorted(tools)} != servers with labels {sorted(labels)}")
    for server, defs in tools.items():
        names = {t.name for t in defs}
        if names != set(labels[server]):
            raise SystemExit(f"{server}: tool names and label names differ")

    out: dict = {"servers": {s: len(t) for s, t in tools.items()}, "results": {}}
    for tagger_name, tag_tool in TAGGERS.items():
        evidence = {s: {t.name: tag_tool(t) for t in defs} for s, defs in tools.items()}
        for profile in PROFILES:
            got = {s: {n: tagging.tags_for(ev, profile) for n, ev in per.items()} for s, per in evidence.items()}
            legs = {}
            for leg, tag in LEGS.items():
                pooled = [(bool(labels[s][n][leg]), tag in got[s][n]) for s in tools for n in got[s]]
                per_server = {s: confusion([(bool(labels[s][n][leg]), tag in got[s][n]) for n in got[s]])
                              for s in tools}
                macro = [c["recall"]["rate"] for c in per_server.values() if c["recall"]["rate"] is not None]
                legs[leg] = {"pooled": confusion(pooled), "per_server": per_server,
                             "macro_recall": round(math.fsum(macro) / len(macro), 4) if macro else None}
            flags = {}
            for s in tools:
                truth = all(any(labels[s][n][leg] for n in got[s]) for leg in LEGS)
                flagged = frozenset().union(*got[s].values()) >= tagging.ALL_TAGS
                flags[s] = {"labelled_trifecta": truth, "flagged": flagged}
            out["results"][f"{tagger_name}/{profile}"] = {"legs": legs, "server_flags": flags}
    return out


def render_md(data: dict) -> str:
    lines = ["# Holdout score: v1 vs draft v2 tagger", "",
             "Blind labels were committed before either tagger ran on these servers. "
             "Tool counts: " + ", ".join(f"{s} {n}" for s, n in data["servers"].items()) + ".", "",
             "## Pooled per-tool recall and precision", "",
             "| Tagger/profile | Leg | Recall | Precision | TP | FP | FN | Macro recall over servers |",
             "|---|---|---|---|---|---|---|---|"]
    for key, res in data["results"].items():
        for leg, d in res["legs"].items():
            c = d["pooled"]
            fmt = lambda r: "n/a" if r["rate"] is None else f"{r['rate']:.0%} ({r['k']}/{r['n']})"  # noqa: E731
            lines.append(f"| {key} | {leg} | {fmt(c['recall'])} | {fmt(c['precision'])} | "
                         f"{c['tp']} | {c['fp']} | {c['fn']} | {d['macro_recall']} |")
    lines += ["", "## Server trifecta flag", "", "| Server | Labelled trifecta | " +
              " | ".join(data["results"]) + " |", "|---|---|" + "---|" * len(data["results"])]
    for s in data["servers"]:
        first = next(iter(data["results"].values()))["server_flags"][s]
        cells = ["yes" if r["server_flags"][s]["flagged"] else "no" for r in data["results"].values()]
        lines.append(f"| {s} | {'yes' if first['labelled_trifecta'] else 'no'} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = build()
    text_json = json.dumps(data, indent=1, sort_keys=True) + "\n"
    text_md = render_md(data)
    if args.check:
        stale = []
        for path, text in ((JSON_PATH, text_json), (MD_PATH, text_md)):
            try:
                with open(path, encoding="utf-8") as f:  # universal newlines: a CRLF checkout is not stale
                    if f.read() != text:
                        stale.append(path)
            except FileNotFoundError:
                stale.append(path)
        if stale:
            print("stale: " + ", ".join(stale))
            return 1
        print("holdout_score.json and .md are up to date")
        return 0
    for path, text in ((JSON_PATH, text_json), (MD_PATH, text_md)):
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    print(f"wrote {JSON_PATH} and {MD_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
