"""Eval mode: does fixing what mcp-lint flags help an agent?

    mcp-lint eval --setup                       # build sandbox + repo, write eval/tasks/
    mcp-lint eval --run --split test --runs 3   # run claude -p per task x condition
    mcp-lint eval --report                      # aggregate results into tables

The agent under test is Claude Code itself, run headless (``claude -p``) with
only the server under test connected and the built-in tools turned off, so it
must use MCP tools. Each condition gets its own temporary MCP config:

- ``baseline``: the server directly (through ``mcp_lint.safe_exec`` so it gets
  a minimal environment, not Claude Code's).
- ``fixed``: the same server behind ``mcp-lint proxy`` with every fix on.
- ``paging_only`` / ``descriptions_only`` / ``errors_only``: one fix at a time.

Results go to a JSONL file, one line per run. The runner is resumable: runs
already in the file are skipped. It stops launching runs at the first usage or
rate-limit error. Token, turn and cost numbers are what Claude Code reports.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from mcp_lint.evaltasks import Task, build, check_answer, extract_answer, load_tasks, make_tasks, paths_for, save_tasks

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL_DIR = REPO_ROOT / "eval"
DEFAULT_BASE = Path(tempfile.gettempdir()) / "mcp-lint-eval"
SERVER_KEY = "srv"  # same in every condition, so tool names are identical

SERVERS: dict[str, dict[str, Any]] = {
    "filesystem": {
        "label": "@modelcontextprotocol/server-filesystem 2.1.0",
        # Allowed directory = the eval base folder, the same folder Claude Code sends
        # as its MCP root (its cwd). server-filesystem swaps its allowed directories
        # for the client's roots, and the proxy's upstream client sends none, so
        # anything else would give baseline and fixed different access.
        "cmd": ["npx", "-y", "@modelcontextprotocol/server-filesystem@2.1.0", "{BASE}"],
        # Read-only tools only (all annotated readOnlyHint); write tools stay listed but denied.
        "allow": ["read_file", "read_text_file", "read_multiple_files", "list_directory",
                  "list_directory_with_sizes", "directory_tree", "search_files", "get_file_info",
                  "list_allowed_directories"],
        "fixes": "server-filesystem.json",
    },
    "markitdown": {
        "label": "markitdown-mcp 0.0.1a7",
        "cmd": ["uvx", "markitdown-mcp@0.0.1a7"],
        "allow": ["convert_to_markdown"],  # unannotated, but it only reads/converts
        "fixes": "markitdown-mcp.json",
    },
    "git": {
        "label": "mcp-server-git 2026.10.28",
        "cmd": ["uvx", "mcp-server-git@2026.10.28", "--repository", "{REPO}"],
        "allow": ["git_status", "git_diff_unstaged", "git_diff_staged", "git_diff", "git_log",
                  "git_show", "git_branch"],
        "fixes": "mcp-server-git.json",
    },
}

CONDITIONS: dict[str, list[str]] = {  # proxy flags; None = no proxy
    "fixed": [],
    "paging_only": ["--no-errors"],
    "descriptions_only": ["--no-paging", "--no-errors"],
    "errors_only": ["--no-paging"],
}
USES_DESCRIPTIONS = {"fixed", "descriptions_only"}

PROMPT_SUFFIX = ("\n\nUse the tools from the connected MCP server to find out; don't guess. "
                 "Finish your reply with one final line of exactly this form:\nANSWER: <your answer>")

LIMIT_ERROR = re.compile(r"usage limit|rate[ _-]?limit|limit reached|\b429\b|overloaded|"
                         r"out of (extra )?usage|credit balance", re.IGNORECASE)
TRUNCATION = re.compile(r"exceeds maximum allowed tokens|too large|truncated|was cut",
                        re.IGNORECASE)


# ---- building one run ----

def server_command(server: str, paths: dict[str, str]) -> list[str]:
    return [part.format(**paths) for part in SERVERS[server]["cmd"]]


def mcp_config(server: str, condition: str, paths: dict[str, str],
               proxy_log: str | None = None, python: str = sys.executable) -> dict[str, Any]:
    upstream = server_command(server, paths)
    if condition == "baseline":
        args = ["-m", "mcp_lint.safe_exec", "--", *upstream]
    else:
        args = ["-m", "mcp_lint", "proxy", *CONDITIONS[condition]]
        if condition in USES_DESCRIPTIONS:
            args += ["--descriptions", str(EVAL_DIR / "fixes" / SERVERS[server]["fixes"])]
        if proxy_log:
            args += ["--log", proxy_log]
        args += ["--", *upstream]
    return {"mcpServers": {SERVER_KEY: {"type": "stdio", "command": python, "args": args}}}


def claude_command(config_path: str, server: str, model: str, max_turns: int,
                   claude: str = "claude") -> list[str]:
    allowed = ",".join(f"mcp__{SERVER_KEY}__{t}" for t in SERVERS[server]["allow"])
    return [
        claude, "-p",
        "--output-format", "stream-json", "--verbose",
        "--model", model,
        "--max-turns", str(max_turns),
        "--mcp-config", config_path, "--strict-mcp-config",
        "--tools", "",  # no built-in tools: the agent must use the MCP server
        "--allowedTools", allowed,
        "--permission-mode", "dontAsk", "--permission-prompts", "none",
        "--setting-sources", "project",  # the scratch cwd has none: user settings stay out
        "--disable-slash-commands",
        "--no-session-persistence",
    ]


# ---- parsing claude's output ----

def _block_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict))
    return ""


def parse_stream(stdout: str) -> dict[str, Any]:
    """Parse ``--output-format stream-json`` (or plain ``json``) output.

    The final ``result`` event carries the same fields as ``--output-format
    json``: result text, num_turns, usage, total_cost_usd. Tool calls and the
    size of each tool result come from the assistant/user events before it.
    """
    result: dict[str, Any] | None = None
    calls: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = event.get("type")
        if kind == "result":
            result = event
        elif kind == "assistant":
            for block in (event.get("message") or {}).get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    call = {"tool": block.get("name", ""),
                            "args": json.dumps(block.get("input"))[:300]}
                    calls.append(call)
                    by_id[block.get("id", "")] = call
        elif kind == "user":
            for block in (event.get("message") or {}).get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    text = _block_text(block.get("content"))
                    call = by_id.get(block.get("tool_use_id", ""))
                    if call is not None:
                        call["result_chars"] = len(text)
                        call["is_error"] = bool(block.get("is_error"))
                        call["truncated"] = bool(TRUNCATION.search(text[:2000] + text[-2000:]))
                        call["preview"] = text[:200]
    if result is None:
        raise ValueError("no result event in claude output")
    usage = result.get("usage") or {}
    tokens = {k: int(usage.get(k) or 0) for k in
              ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens")}
    return {
        "result_text": result.get("result") or "",
        "subtype": result.get("subtype"),
        "is_error": bool(result.get("is_error")),
        "turns": result.get("num_turns"),
        "duration_ms": result.get("duration_ms"),
        "cost_usd": result.get("total_cost_usd"),
        **tokens,
        "total_tokens": sum(tokens.values()),
        "models": sorted((result.get("modelUsage") or {}).keys()),
        "tool_calls": calls,
    }


# ---- running ----

@dataclass
class Completed:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int


Runner = Callable[[list[str], str, str, float], Completed]


def subprocess_runner(cmd: list[str], stdin: str, cwd: str, timeout: float) -> Completed:
    start = time.perf_counter()
    exe = shutil.which(cmd[0]) or cmd[0]
    proc = subprocess.run([exe, *cmd[1:]], input=stdin, cwd=cwd, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=timeout)
    return Completed(proc.returncode, proc.stdout, proc.stderr,
                     round((time.perf_counter() - start) * 1000))


class LimitReached(Exception):
    pass


def run_key(task_id: str, condition: str, model: str, run: int) -> tuple[str, str, str, int]:
    return (task_id, condition, model, run)


def load_results(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # a line cut off by an interruption
    return rows


def valid_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rows that count: no limit hit or infra error, first row per run key."""
    seen: set[tuple[str, str, str, int]] = set()
    out = []
    for r in rows:
        if r.get("limit_hit") or r.get("infra_error") or r.get("excluded"):
            continue
        key = run_key(r["task"], r["condition"], r["model"], r["run"])
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def _read_proxy_log(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return {"calls": len(rows), "paged": sum(r["paged"] for r in rows),
            "error_flagged": sum(r["error_flagged"] for r in rows),
            "upstream_tokens": sum(r["upstream_tokens"] for r in rows),
            "returned_tokens": sum(r["returned_tokens"] for r in rows)}


def run_one(task: Task, condition: str, run: int, *, model: str, base: Path, max_turns: int,
            runner: Runner, timeout: float, claude: str = "claude") -> dict[str, Any]:
    paths = {**paths_for(base), "BASE": str(base.resolve())}
    work = base / "runs" / uuid.uuid4().hex[:12]
    work.mkdir(parents=True)
    proxy_log = work / "proxy.jsonl"
    config = mcp_config(task.server, condition, paths,
                        proxy_log=str(proxy_log) if condition != "baseline" else None)
    config_path = work / "mcp.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    cmd = claude_command(str(config_path), task.server, model, max_turns, claude)
    record: dict[str, Any] = {
        "task": task.id, "server": task.server, "split": task.split, "kind": task.kind,
        "condition": condition, "model": model, "run": run, "expected": task.answer,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        # cwd is the base folder (not a git repo, no settings), shared by all runs.
        done = runner(cmd, task.render(paths) + PROMPT_SUFFIX, str(base), timeout)
    except subprocess.TimeoutExpired:
        record.update(success=False, answer=None, error=f"timeout after {timeout:.0f}s")
        shutil.rmtree(work, ignore_errors=True)
        return record
    try:
        parsed = parse_stream(done.stdout)
    except ValueError as exc:
        parsed = None
        record.update(success=False, answer=None,
                      error=f"{exc}; exit {done.returncode}; stderr: {done.stderr.strip()[:500]}")
    if parsed is not None:
        text = parsed.pop("result_text")
        answer = extract_answer(text)
        record.update(parsed)
        record.update(success=check_answer(task, answer), answer=answer,
                      final_text=text[-500:], error=None)
        if parsed["is_error"]:
            record["error"] = f"{parsed['subtype']}: {text[:300]}"
    record["wall_ms"] = done.duration_ms
    record["proxy"] = _read_proxy_log(proxy_log)
    if condition != "baseline" and record["proxy"] is None and not record.get("tool_calls"):
        # The proxy never handled a call and the agent made none: almost always
        # the proxy failing to start. Not an agent result, so it is re-run.
        record["infra_error"] = "proxy handled no calls and the agent made none"
    shutil.rmtree(work, ignore_errors=True)
    err = (record.get("error") or "") + ("" if parsed else done.stderr)
    if (record.get("is_error") or parsed is None) and LIMIT_ERROR.search(err):
        record["limit_hit"] = True
    return record


def run_eval(tasks: list[Task], conditions: list[str], runs: int, results: Path, *,
             model: str = "haiku", base: Path = DEFAULT_BASE, max_turns: int = 25,
             runner: Runner = subprocess_runner, timeout: float = 600, workers: int = 1,
             max_new: int | None = None, claude: str = "claude",
             log: Callable[[str], None] = print) -> dict[str, int]:
    """Run every (task, condition, run) not already in ``results``.

    Order is run index, then task, then condition, so a partial run is still
    balanced across conditions. Stops launching at the first usage/rate limit.
    """
    done = {run_key(r["task"], r["condition"], r["model"], r["run"]) for r in load_results(results)
            if not r.get("limit_hit") and not r.get("infra_error")}
    todo = [(t, c, r) for r in range(1, runs + 1) for t in tasks for c in conditions
            if run_key(t.id, c, model, r) not in done]
    skipped = len(tasks) * len(conditions) * runs - len(todo)
    if max_new is not None:
        todo = todo[:max_new]
    results.parent.mkdir(parents=True, exist_ok=True)
    lock_path = results.with_name(results.name + ".lock")
    try:  # one runner per results file, or runs get duplicated
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise RuntimeError(f"{lock_path} exists: another runner may be using {results}. "
                           "Delete the lock file if not.") from None
    os.write(fd, str(os.getpid()).encode())
    os.close(fd)
    try:
        return _run_todo(todo, results, stats_init={"skipped": skipped}, model=model, base=base,
                         max_turns=max_turns, runner=runner, timeout=timeout, workers=workers,
                         claude=claude, log=log)
    finally:
        os.remove(lock_path)


def _run_todo(todo: list[tuple[Task, str, int]], results: Path, *, stats_init: dict[str, int],
              model: str, base: Path, max_turns: int, runner: Runner, timeout: float,
              workers: int, claude: str, log: Callable[[str], None]) -> dict[str, int]:
    lock = threading.Lock()
    stop = threading.Event()
    stats = {**stats_init, "ran": 0, "infra_error": 0, "limit": 0}

    def work(item: tuple[Task, str, int]) -> None:
        task, cond, run = item
        if stop.is_set():
            return
        rec = run_one(task, cond, run, model=model, base=base, max_turns=max_turns,
                      runner=runner, timeout=timeout, claude=claude)
        with lock:
            with open(results, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
            stats["ran"] += 1
            stats["infra_error"] += bool(rec.get("infra_error"))
            if rec.get("limit_hit"):
                stats["limit"] += 1
                stop.set()
            tok = rec.get("total_tokens")
            log(f"[{stats['ran']}/{len(todo)}] {task.id} {cond} run{run}: "
                f"{'OK ' if rec['success'] else 'FAIL'} answer={rec.get('answer')!r} "
                f"turns={rec.get('turns')} tokens={tok:,}" if tok is not None else
                f"[{stats['ran']}/{len(todo)}] {task.id} {cond} run{run}: ERROR {rec.get('error')}")

    if workers <= 1:
        for item in todo:
            work(item)
            if stop.is_set():
                break
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(work, todo))
    if stop.is_set():
        log("Stopped: hit a usage or rate limit. Re-run the same command later to resume.")
    return stats


# ---- aggregation ----

def _mean(xs: list[float]) -> float | None:
    return statistics.fmean(xs) if xs else None


def _sd(xs: list[float]) -> float | None:
    return statistics.stdev(xs) if len(xs) > 1 else None


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Success rate and Claude Code-reported usage for one group of runs."""
    by_rep: dict[int, list[bool]] = {}
    for r in rows:
        by_rep.setdefault(r["run"], []).append(bool(r["success"]))
    rep_rates = [sum(v) / len(v) for _, v in sorted(by_rep.items())]
    measured = [r for r in rows if r.get("total_tokens") is not None]

    def col(name: str) -> list[float]:
        return [float(r[name]) for r in measured if r.get(name) is not None]

    tokens, turns, cost = col("total_tokens"), col("turns"), col("cost_usd")
    return {
        "runs": len(rows),
        "success": sum(bool(r["success"]) for r in rows) / len(rows) if rows else None,
        "success_rep_sd": _sd(rep_rates),
        "tokens_mean": _mean(tokens), "tokens_sd": _sd(tokens),
        "tokens_median": statistics.median(tokens) if tokens else None,
        "turns_mean": _mean(turns), "turns_sd": _sd(turns),
        "cost_mean": _mean(cost), "cost_total": sum(cost),
        "errors": sum(1 for r in rows if r.get("error")),
    }


def paired_diff(rows: list[dict[str, Any]], metric: str, a: str, b: str,
                reps: int = 2000, seed: int = 0) -> dict[str, Any] | None:
    """Mean per-task difference (b - a) with a bootstrap 95% CI over tasks."""
    per_task: dict[str, dict[str, list[float]]] = {}
    for r in rows:
        v = r.get(metric)
        if metric == "success":
            v = float(bool(r["success"]))
        if v is None:
            continue
        per_task.setdefault(r["task"], {}).setdefault(r["condition"], []).append(float(v))
    diffs = [statistics.fmean(c[b]) - statistics.fmean(c[a])
             for c in per_task.values() if c.get(a) and c.get(b)]
    if not diffs:
        return None
    rng = random.Random(seed)
    boots = sorted(statistics.fmean(rng.choices(diffs, k=len(diffs))) for _ in range(reps))
    return {"tasks": len(diffs), "mean": statistics.fmean(diffs),
            "ci_low": boots[int(0.025 * reps)], "ci_high": boots[int(0.975 * reps) - 1]}


def _fmt(v: float | None, kind: str = "num") -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "n/a"
    if kind == "pct":
        return f"{v * 100:.0f}%"
    if kind == "usd":
        return f"${v:.3f}"
    if kind == "tok":
        return f"{v:,.0f}"
    return f"{v:.1f}"


def report_tables(rows: list[dict[str, Any]], split: str = "test") -> str:
    rows = [r for r in rows if r.get("split") == split]
    if not rows:
        return f"No results for split '{split}'."
    servers = [s for s in SERVERS if any(r["server"] == s for r in rows)]
    conds = [c for c in ["baseline", *CONDITIONS] if any(r["condition"] == c for r in rows)]
    out = ["| Server | Condition | Runs | Success (± SD over reps) | Tokens / task, mean ± SD (median) "
           "| Turns, mean ± SD | Cost / task | Errors |",
           "|---|---|---|---|---|---|---|---|"]
    for server in [*servers, "all"]:
        for cond in conds:
            group = [r for r in rows if r["condition"] == cond and (server == "all" or r["server"] == server)]
            if not group:
                continue
            s = summarize(group)
            sd = f" ± {s['success_rep_sd'] * 100:.0f}" if s["success_rep_sd"] is not None else ""
            name = f"**{server}**" if server == "all" else server
            out.append(f"| {name} | {cond} | {s['runs']} | {_fmt(s['success'], 'pct')}{sd} "
                       f"| {_fmt(s['tokens_mean'], 'tok')} ± {_fmt(s['tokens_sd'], 'tok')} "
                       f"({_fmt(s['tokens_median'], 'tok')}) "
                       f"| {_fmt(s['turns_mean'])} ± {_fmt(s['turns_sd'])} "
                       f"| {_fmt(s['cost_mean'], 'usd')} | {s['errors']} |")
    out.append("")
    out.append("Paired per-task differences vs baseline (mean of per-task means; 95% bootstrap CI over tasks):")
    out.append("")
    out.append("| Server | Condition | Tasks | Success Δ (pts) | Tokens Δ | Turns Δ | Cost Δ |")
    out.append("|---|---|---|---|---|---|---|")
    for server in [*servers, "all"]:
        group = [r for r in rows if server == "all" or r["server"] == server]
        for cond in conds:
            if cond == "baseline":
                continue
            cells = []
            n = 0
            for metric, kind in [("success", "pct"), ("total_tokens", "tok"), ("turns", "num"),
                                 ("cost_usd", "usd")]:
                d = paired_diff(group, metric, "baseline", cond)
                if d is None:
                    cells.append("n/a")
                    continue
                n = d["tasks"]
                if kind == "pct":
                    cells.append(f"{d['mean'] * 100:+.0f} [{d['ci_low'] * 100:+.0f}, {d['ci_high'] * 100:+.0f}]")
                elif kind == "tok":
                    cells.append(f"{d['mean']:+,.0f} [{d['ci_low']:+,.0f}, {d['ci_high']:+,.0f}]")
                elif kind == "usd":
                    cells.append(f"{d['mean']:+.3f} [{d['ci_low']:+.3f}, {d['ci_high']:+.3f}]")
                else:
                    cells.append(f"{d['mean']:+.1f} [{d['ci_low']:+.1f}, {d['ci_high']:+.1f}]")
            if n:
                name = f"**{server}**" if server == "all" else server
                out.append(f"| {name} | {cond} | {n} | " + " | ".join(cells) + " |")
    return "\n".join(out)


def per_task_table(rows: list[dict[str, Any]], split: str = "test") -> str:
    rows = [r for r in rows if r.get("split") == split]
    conds = [c for c in ["baseline", *CONDITIONS] if any(r["condition"] == c for r in rows)]
    out = ["| Task | Kind | " + " | ".join(f"{c} ok" for c in conds) + " | "
           + " | ".join(f"{c} tokens" for c in conds) + " |",
           "|---|---|" + "---|" * (2 * len(conds))]
    for task in sorted({r["task"] for r in rows}):
        tr = [r for r in rows if r["task"] == task]
        oks, toks = [], []
        for c in conds:
            g = [r for r in tr if r["condition"] == c]
            oks.append(f"{sum(bool(r['success']) for r in g)}/{len(g)}" if g else "-")
            t = [r["total_tokens"] for r in g if r.get("total_tokens") is not None]
            toks.append(f"{statistics.fmean(t):,.0f}" if t else "-")
        out.append(f"| {task} | {tr[0].get('kind', '')} | " + " | ".join(oks) + " | " + " | ".join(toks) + " |")
    return "\n".join(out)


# ---- CLI ----

def add_eval_parser(sub: Any) -> None:
    ev = sub.add_parser("eval", help="run the before/after agent eval (see eval/REPORT.md)")
    mode = ev.add_mutually_exclusive_group(required=True)
    mode.add_argument("--setup", action="store_true", help="build the sandbox and repo, write task files")
    mode.add_argument("--run", action="store_true", help="run claude -p for each task and condition")
    mode.add_argument("--report", action="store_true", help="print result tables")
    ev.add_argument("--base", default=str(DEFAULT_BASE), help=f"sandbox/repo folder (default: {DEFAULT_BASE})")
    ev.add_argument("--tasks", default=str(EVAL_DIR / "tasks"), help="task folder")
    ev.add_argument("--results", default=str(EVAL_DIR / "results" / "results.jsonl"))
    ev.add_argument("--split", default="test", choices=["dev", "test", "all"])
    ev.add_argument("--servers", default=",".join(SERVERS), help="comma-separated servers")
    ev.add_argument("--task-ids", help="comma-separated task ids (overrides --split/--servers)")
    ev.add_argument("--conditions", default="baseline,fixed",
                    help=f"comma-separated: baseline,{','.join(CONDITIONS)}")
    ev.add_argument("--runs", type=int, default=3, help="runs per task per condition")
    ev.add_argument("--model", default="haiku")
    ev.add_argument("--max-turns", type=int, default=25)
    ev.add_argument("--max-runs", type=int, help="launch at most this many new runs")
    ev.add_argument("--workers", type=int, default=1, help="runs in parallel")
    ev.add_argument("--timeout", type=float, default=600, help="seconds per run")
    ev.add_argument("--claude", default="claude", help="claude executable")
    ev.add_argument("--out", metavar="PATH", help="--report: write the tables here (UTF-8)")


def eval_main(args: argparse.Namespace) -> int:
    base, task_dir = Path(args.base), Path(args.tasks)
    if args.setup:
        sb, shas = build(base)
        tasks = make_tasks(sb, shas)
        for p in save_tasks(tasks, task_dir):
            print(f"wrote {p}")
        print(f"sandbox and repo ready under {base}")
        return 0
    if args.report:
        rows = valid_rows(load_results(Path(args.results)))
        text = report_tables(rows, args.split) + "\n\n" + per_task_table(rows, args.split) + "\n"
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"wrote {args.out}")
        else:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")  # the tables use "Δ"
            print(text)
        return 0
    build(base)  # make sure the sandbox exists (no-op when it does)
    tasks = load_tasks(task_dir)
    if args.task_ids:
        wanted = args.task_ids.split(",")
        tasks = [t for t in tasks if t.id in wanted]
    else:
        servers = args.servers.split(",")
        tasks = [t for t in tasks if t.server in servers and (args.split == "all" or t.split == args.split)]
    conditions = args.conditions.split(",")
    bad = [c for c in conditions if c != "baseline" and c not in CONDITIONS]
    if bad or not tasks:
        print(f"mcp-lint: unknown conditions {bad}" if bad else "mcp-lint: no tasks selected", file=sys.stderr)
        return 2
    stats = run_eval(tasks, conditions, args.runs, Path(args.results), model=args.model, base=base,
                     max_turns=args.max_turns, timeout=args.timeout, workers=args.workers,
                     max_new=args.max_runs, claude=args.claude)
    print(json.dumps(stats))
    return 3 if stats["limit"] else 0
