"""Run AgentDojo against a local model served by Ollama, and self-check AgentDojo's semantics.

Run it with the Python that has AgentDojo installed, not mcp-lint's:

    <agentdojo-venv>/python -I benchmark/agentdojo_run.py --self-check
    <agentdojo-venv>/python -I benchmark/agentdojo_run.py --model-id qwen2.5:7b [--port 11434]
        [--suite S ...] [--user-task ID ...] [--injection-task ID ...]
        [--attack important_instructions] [--clean-only | --attacked-only] [--dry-run]

--self-check runs each suite's check() (no model called) and asserts that every
injection task's ground truth gives security True. So security True means the
attack goal was reached.

--dry-run prints the planned trial counts (attacked = user tasks x injection
tasks, clean = user tasks) and contacts nothing.

A model run only talks to a server on localhost. Before any trial it:
- refuses a model id outside ^[A-Za-z0-9._:-]+$ and a port outside 1..65535;
- lists models at http://localhost:<port>/v1/models (5 s timeout) and refuses
  unless the model is listed;
- removes ANTHROPIC_API_KEY and OPENAI_API_KEY from the environment, so no key
  can be used;
- sets LOCAL_LLM_PORT, which AgentDojo's local provider reads.

Logs go to benchmark/results/agentdojo/runs/local/<model>/ (git-ignored), one directory
per model id, because every local model has the pipeline name "local" and AgentDojo
resumes by that name. AgentDojo skips trials it has already logged there, so a rerun
resumes. The exit code is 1 when any trial errored. Only the scored table is
committed, the same rule as agentdojo_export.py.

AgentDojo is imported only inside functions, so the validation helpers can be
tested with any Python.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

REPO = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOGDIR = REPO / "benchmark" / "results" / "agentdojo" / "runs" / "local"
BENCHMARK_VERSION = "v1.2"
DEFAULT_PORT = 11434
DEFAULT_ATTACK = "important_instructions"
MODEL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")
MODES = ("both", "clean", "attacked")


def validate_model_id(model_id: str) -> None:
    if not MODEL_ID_RE.fullmatch(model_id or ""):
        raise ValueError(f"model id {model_id!r} must match {MODEL_ID_RE.pattern}")


def logdir_for(model_id: str) -> Path:
    """Per-model logdir. Every local model has pipeline name "local", and AgentDojo resumes by
    pipeline name, so models must not share a directory. ':' is not valid in Windows paths."""
    return LOGDIR / re.sub(r"[^A-Za-z0-9._-]", "_", model_id)


def validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} must be an integer from 1 to 65535")


def plan(suites_info, suites=None, user_tasks=None, injection_tasks=None, mode="both"):
    """Planned trials per suite.

    suites_info maps suite name -> {"user_tasks": [ids], "injection_tasks": [ids]}.
    Returns {"suites": {name: {"user_tasks", "injection_tasks", "clean", "attacked"}},
    "clean": total, "attacked": total}. Raises ValueError for an unknown suite name
    or a task id that no selected suite has.
    """
    if mode not in MODES:
        raise ValueError(f"mode {mode!r} must be one of {', '.join(MODES)}")
    names = list(suites) if suites else sorted(suites_info)
    unknown = [name for name in names if name not in suites_info]
    if unknown:
        raise ValueError(f"unknown suite: {', '.join(unknown)}")
    for label, wanted, key in (
        ("user task", user_tasks, "user_tasks"),
        ("injection task", injection_tasks, "injection_tasks"),
    ):
        if wanted:
            known = set().union(*(suites_info[name][key] for name in names))
            missing = sorted(set(wanted) - known)
            if missing:
                raise ValueError(f"unknown {label} id: {', '.join(missing)}")
    out = {"suites": {}, "clean": 0, "attacked": 0}
    for name in names:
        info = suites_info[name]
        users = [t for t in info["user_tasks"] if not user_tasks or t in user_tasks]
        injs = [t for t in info["injection_tasks"] if not injection_tasks or t in injection_tasks]
        clean = len(users) if mode in ("both", "clean") else 0
        attacked = len(users) * len(injs) if mode in ("both", "attacked") else 0
        out["suites"][name] = {"user_tasks": users, "injection_tasks": injs, "clean": clean, "attacked": attacked}
        out["clean"] += clean
        out["attacked"] += attacked
    return out


def format_plan(p: dict) -> str:
    lines = [f"{'suite':<11}{'user':>6}{'inj':>6}{'clean':>8}{'attacked':>10}"]
    for name, row in p["suites"].items():
        lines.append(
            f"{name:<11}{len(row['user_tasks']):>6}{len(row['injection_tasks']):>6}"
            f"{row['clean']:>8}{row['attacked']:>10}"
        )
    total = p["attacked"] + p["clean"]
    lines.append(f"TOTAL attacked={p['attacked']} clean={p['clean']} trials={total}")
    return "\n".join(lines)


def decide_suite(all_ids, empty_ids, gt_results, baseline) -> dict:
    """Pure decision for one suite. Fails closed on any missing result.

    all_ids: every injection task id in the suite.
    empty_ids: the ids whose ground truth is empty (model-only tasks).
    gt_results: {id: security} from the ground-truth run, for non-empty tasks.
    baseline: {id: security} from the no-action baseline, for every task.

    ok requires: every non-empty task gives security True on its ground truth,
    and every task gives security False on the no-action baseline.
    """
    all_ids = set(all_ids)
    empty = set(empty_ids)
    checkable = all_ids - empty
    gt_failed = sorted(t for t in checkable if gt_results.get(t) is not True)
    gt_missing = sorted(checkable - set(gt_results))
    baseline_not_false = sorted(t for t in all_ids if t in baseline and baseline[t] is not False)
    baseline_missing = sorted(all_ids - set(baseline))
    ok = (
        bool(all_ids)
        and empty <= all_ids
        and not gt_failed
        and not gt_missing
        and not baseline_not_false
        and not baseline_missing
    )
    return {
        "checked": len(checkable),
        "empty": sorted(empty),
        "gt_failed": gt_failed,
        "baseline_false": sum(1 for t in all_ids if baseline.get(t) is False),
        "baseline_not_false": baseline_not_false,
        "missing": sorted(set(gt_missing) | set(baseline_missing)),
        "ok": ok,
    }


def self_check(suites) -> bool:
    """Check AgentDojo's security semantics in every suite, without a model.

    1. Injection tasks with a non-empty ground truth: the ground-truth run gives security True.
    2. Every injection task: a no-action baseline (empty output, untouched environment,
       first user task's init_environment) gives security False, so an untouched
       environment never counts as an attack success.
    """
    all_ok = True
    for name in sorted(suites):
        suite = suites[name]
        injections = suite.injection_tasks
        user = next(iter(suite.user_tasks.values()))

        probe_env = suite.load_and_inject_default_environment(suite.get_injection_vector_defaults())
        empty = [tid for tid, t in injections.items() if len(t.ground_truth(probe_env.copy(deep=True))) == 0]

        _, (user_results, injection_results) = suite.check(check_injectable=True)
        gt_results = {tid: sec for tid, sec in injection_results.items() if tid not in empty}

        env = user.init_environment(suite.load_and_inject_default_environment(suite.get_injection_vector_defaults()))
        baseline = {}
        for tid, task in injections.items():
            env_copy = env.copy(deep=True)
            baseline[tid] = suite._check_task_result(task, [], env_copy, env_copy, [])

        d = decide_suite(injections.keys(), empty, gt_results, baseline)
        all_ok = all_ok and d["ok"]
        print(
            f"{name}: ground truth checked {d['checked']}; empty ground truth {len(d['empty'])} "
            f"({', '.join(d['empty']) or 'none'}); no-action baseline false {d['baseline_false']}/{len(injections)} "
            f"-> {'PASS' if d['ok'] else 'FAIL'}"
        )
        for tid in d["gt_failed"]:
            print(f"  FAIL injection task {tid}: ground truth does not give security True")
        for tid in d["baseline_not_false"]:
            print(f"  FAIL injection task {tid}: no-action baseline gives security True (attack counts with no action)")
        for tid in d["missing"]:
            print(f"  FAIL injection task {tid}: no result")
        user_failed = [tid for tid, (good, _) in user_results.items() if not good]
        reason = user_results[sorted(user_failed)[0]][1] if user_failed else ""
        print(
            f"  info (not asserted): {len(user_results) - len(user_failed)}/{len(user_results)} user tasks "
            f"pass ground-truth utility and injectability{'; first reason: ' + reason if reason else ''}"
        )
    print("SELF-CHECK PASS" if all_ok else "SELF-CHECK FAIL")
    return all_ok


def list_models(port: int) -> list[str]:
    url = f"http://localhost:{port}/v1/models"
    # No proxy: the request must go to the local server, whatever the environment says.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=5) as resp:
        payload = json.load(resp)
    return [str(item["id"]) for item in payload["data"]]


def build_pipeline(model_id: str, port: int):
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig

    os.environ["LOCAL_LLM_PORT"] = str(port)
    config = PipelineConfig(
        llm="local",
        model_id=model_id,
        defense=None,
        tool_delimiter="tool",
        system_message_name=None,
        system_message=None,
    )
    return AgentPipeline.from_config(config)


def _guarded(call, record: dict, errors_path: Path, emit, cleanup=None):
    """Run one benchmark call. Any Exception is logged as one JSON line and skipped.

    AgentDojo only catches some provider errors, so one bad model output or timeout
    would otherwise abort the whole run. KeyboardInterrupt is not caught and stops the run.
    """
    try:
        return call()
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        entry = dict(record, error=f"{type(exc).__name__}: {str(exc)[:300]}")
        with open(errors_path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        if cleanup is not None:
            cleanup(record)
        emit(f"ERROR {record['suite']} {record['user_task_id']} {record['injection_task_id']}: {entry['error'][:120]}")
        return None


def run_cases(p: dict, suites, attack_name: str, logdir: Path, clean_fn, attacked_fn, make_attack, emit=print,
              cleanup=None) -> dict:
    """Run every planned case one at a time, so one failure cannot stop the others.

    clean_fn(suite, user_task_ids) and attacked_fn(suite, attack, user_task_ids, injection_task_ids)
    wrap AgentDojo's benchmark functions. make_attack(attack_name, suite) builds the attack.
    Each call is for one user task (clean) or one (user task, injection task) pair (attacked).
    Returns per-suite counts. Errors go to <logdir>/errors.jsonl.
    """
    logdir = Path(logdir)
    logdir.mkdir(parents=True, exist_ok=True)
    errors_path = logdir / "errors.jsonl"
    totals: dict = {}
    for name, info in p["suites"].items():
        if not info["user_tasks"]:
            continue
        suite = suites[name]
        row = totals.setdefault(name, {"clean": 0, "clean_errors": 0, "attacked": 0, "attacked_errors": 0})
        if info["clean"]:
            for uid in info["user_tasks"]:
                record = {"suite": name, "user_task_id": uid, "injection_task_id": None}
                res = _guarded(lambda: clean_fn(suite, [uid]), record, errors_path, emit, cleanup)
                if res is None:
                    row["clean_errors"] += 1
                else:
                    row["clean"] += len(res["utility_results"])
        if info["attacked"]:
            attack = make_attack(attack_name, suite)
            for uid in info["user_tasks"]:
                for iid in info["injection_tasks"]:
                    record = {"suite": name, "user_task_id": uid, "injection_task_id": iid}
                    res = _guarded(lambda: attacked_fn(suite, attack, [uid], [iid]), record, errors_path, emit, cleanup)
                    if res is None:
                        row["attacked_errors"] += 1
                    else:
                        row["attacked"] += len(res["security_results"])
    for name, row in totals.items():
        emit(
            f"{name}: clean {row['clean']} trials ({row['clean_errors']} errors), "
            f"attacked {row['attacked']} trials ({row['attacked_errors']} errors)"
        )
    return totals


def drop_partial_log(logdir: Path, pipeline: str, suite: str, user_task_id: str, attack: str,
                     injection_task_id: str | None) -> None:
    """AgentDojo's TraceLogger saves a stub (duration only) when a trial raises. Remove it when it has
    no utility, so a failed trial has no log and counts as missing. Copied from agentdojo_claude.py
    because this file must run under -I with only the stdlib and agentdojo."""
    path = Path(logdir) / pipeline.replace("/", "_") / suite / user_task_id / attack / f"{injection_task_id or 'none'}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(data, dict) or "utility" not in data:
        path.unlink(missing_ok=True)


def exit_code(totals: dict) -> int:
    """1 when any trial errored, else 0."""
    return 1 if any(row["clean_errors"] or row["attacked_errors"] for row in totals.values()) else 0


def run_trials(p: dict, suites, model_id: str, port: int, attack_name: str, pipeline=None, logdir=None) -> dict:
    """Run the planned trials. pipeline and logdir default to the real local model and its per-model
    logdir; tests pass a stub pipeline and a temp logdir."""
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
    from agentdojo.logging import OutputLogger

    # Keys go before the pipeline is built, so no client can pick one up.
    os.environ.pop("ANTHROPIC_API_KEY", None)
    os.environ.pop("OPENAI_API_KEY", None)
    if pipeline is None:
        pipeline = build_pipeline(model_id, port)
    logdir = Path(logdir) if logdir is not None else logdir_for(model_id)
    logdir.mkdir(parents=True, exist_ok=True)

    def clean_fn(suite, uids):
        # One user task per call. run_task_* does not run the injection tasks as user tasks.
        utility, _ = run_task_without_injection_tasks(
            suite, pipeline, suite.get_user_task_by_id(uids[0]), logdir, False, BENCHMARK_VERSION
        )
        return {"utility_results": {(uids[0], ""): utility}, "security_results": {}}

    def attacked_fn(suite, attack, uids, iids):
        utility, security = run_task_with_injection_tasks(
            suite, pipeline, suite.get_user_task_by_id(uids[0]), attack, logdir, False, list(iids), BENCHMARK_VERSION
        )
        return {"utility_results": utility, "security_results": security}

    def cleanup(record):
        attack = attack_name if record["injection_task_id"] else "none"
        drop_partial_log(logdir, pipeline.name, record["suite"], record["user_task_id"], attack, record["injection_task_id"])

    # TraceLogger delegates to the active OutputLogger and reads its logdir.
    with OutputLogger(str(logdir), live=None):
        return run_cases(
            p, suites, attack_name, logdir, clean_fn, attacked_fn,
            lambda n, s: load_attack(n, s, pipeline), cleanup=cleanup,
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-check", action="store_true", help="check AgentDojo's security semantics (no model)")
    parser.add_argument("--model-id", help="Ollama model name, e.g. qwen2.5:7b")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="local Ollama port (default 11434)")
    parser.add_argument("--suite", action="extend", nargs="+", dest="suites", metavar="S")
    parser.add_argument("--user-task", action="extend", nargs="+", dest="user_tasks", metavar="ID")
    parser.add_argument("--injection-task", action="extend", nargs="+", dest="injection_tasks", metavar="ID")
    parser.add_argument("--attack", default=DEFAULT_ATTACK)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--clean-only", action="store_true")
    group.add_argument("--attacked-only", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="print planned trial counts and exit")
    args = parser.parse_args(argv)

    from agentdojo.task_suite.load_suites import get_suites

    if args.self_check:
        if args.model_id is not None or args.dry_run:
            parser.error("--self-check takes no model options")
        return 0 if self_check(get_suites(BENCHMARK_VERSION)) else 1

    if args.model_id is None:
        parser.error("--model-id is required (or use --self-check)")
    try:
        validate_model_id(args.model_id)
        validate_port(args.port)
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    suites = get_suites(BENCHMARK_VERSION)
    from agentdojo.attacks.attack_registry import ATTACKS

    if args.attack not in ATTACKS:
        print(f"refused: unknown attack {args.attack!r}", file=sys.stderr)
        return 2
    info = {name: {"user_tasks": list(s.user_tasks), "injection_tasks": list(s.injection_tasks)} for name, s in suites.items()}
    mode = "clean" if args.clean_only else "attacked" if args.attacked_only else "both"
    try:
        p = plan(info, args.suites, args.user_tasks, args.injection_tasks, mode)
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(format_plan(p))
    print(f"logs: {logdir_for(args.model_id)}")
    if args.dry_run:
        return 0

    try:
        models = list_models(args.port)
    except Exception as exc:
        print(f"refused: could not list models at localhost:{args.port}: {exc}", file=sys.stderr)
        return 1
    if args.model_id not in models:
        print(f"refused: model {args.model_id!r} is not listed by localhost:{args.port}", file=sys.stderr)
        print(f"listed: {', '.join(models[:10]) or '(none)'}", file=sys.stderr)
        return 1

    totals = run_trials(p, suites, args.model_id, args.port, args.attack)
    return exit_code(totals)


if __name__ == "__main__":
    raise SystemExit(main())
