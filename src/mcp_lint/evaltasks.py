"""Eval tasks: a seeded sandbox, a scratch git repo, and tasks with exact answers.

Everything is generated from a fixed seed, and every answer is computed here in
Python from the generated files, never by a model. Task prompts hold
placeholders ({SANDBOX}, {SANDBOX_URI}, {REPO}) that are filled in at run time,
so the committed task files don't depend on where the sandbox was built.

Content is pseudo-random (request IDs, SKUs, ticket numbers) so answers can't
be guessed from a pattern, the way "line number N" in the survey's big.txt can.
"""

from __future__ import annotations

import json
import os
import random
import re
import string
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SEED = 20261104
HELD_OUT_PER_SERVER = 5

LOG_LINES = 8_000
CSV_ROWS = 3_000
HTML_SECTIONS = 400
SUB_FILES = 300
GIT_COMMITS = 900

SERVICES = ["auth", "billing", "search", "gateway", "media", "notify", "orders", "users"]
LEVELS = ["INFO"] * 7 + ["WARN"] * 2 + ["ERROR"]
WAREHOUSES = ["Reno", "Austin", "Leeds", "Osaka", "Lyon", "Perth"]
ADJ = ("amber brisk calm dusty eager faint gentle hollow ivory jolly keen lunar mellow "
       "nimble olive proud quiet rapid silver tidy umber vivid woven young zesty").split()
NOUN = ("anchor basket candle drum easel funnel garnet hinge island jacket kettle lantern "
        "mirror needle orchard pebble quill ribbon saddle thimble urn violin wagon yarrow").split()
VERBS = ["Fix", "Add", "Update", "Refactor", "Remove", "Tune", "Document", "Rename"]
COMPONENTS = ["parser", "cache", "router", "scheduler", "exporter", "auth", "cli", "indexer"]
AUTHORS = [("Ada Moreno", "ada@example.test"), ("Bilal Haddad", "bilal@example.test"),
           ("Chen Wei", "chen@example.test"), ("Dana Okafor", "dana@example.test"),
           ("Emil Novak", "emil@example.test"), ("Farah Siddiqui", "farah@example.test")]


@dataclass
class Task:
    id: str
    server: str
    split: str  # "dev" | "test" (held-out)
    prompt: str  # with {SANDBOX}/{SANDBOX_URI}/{REPO} placeholders
    answer: str
    match: str = "exact"  # "exact" | "int" | "num" | "sha"
    kind: str = ""

    def render(self, paths: dict[str, str]) -> str:
        out = self.prompt
        for key, value in paths.items():
            out = out.replace("{" + key + "}", value)
        return out


@dataclass
class Sandbox:
    """Facts about the generated files that tasks are built from."""

    log: list[dict[str, Any]] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    sub_files: list[str] = field(default_factory=list)
    commits: list[dict[str, Any]] = field(default_factory=list)  # oldest first


def _token(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _unique(rng: random.Random, make, count: int) -> list[Any]:
    seen: set[Any] = set()
    out = []
    while len(out) < count:
        v = make()
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def generate(seed: int = SEED) -> Sandbox:
    """Generate the sandbox content in memory (deterministic)."""
    rng = random.Random(seed)
    sb = Sandbox()
    reqs = _unique(rng, lambda: "r-" + _token(rng, 6), LOG_LINES)
    for i in range(LOG_LINES):
        secs = i * 7
        ts = f"2026-03-{1 + secs // 86400:02d}T{secs % 86400 // 3600:02d}:{secs % 3600 // 60:02d}:{secs % 60:02d}"
        sb.log.append({"ts": ts, "level": rng.choice(LEVELS), "svc": rng.choice(SERVICES),
                       "req": reqs[i], "user": f"u{rng.randint(1000, 9999)}",
                       "latency": rng.randint(1, 2000)})
    skus = _unique(rng, lambda: f"SKU-{rng.randint(10000, 99999)}", CSV_ROWS)
    for sku in skus:
        sb.rows.append({"sku": sku, "name": f"{rng.choice(ADJ)} {rng.choice(NOUN)}",
                        "qty": rng.randint(0, 999), "price": f"{rng.randint(100, 99999) / 100:.2f}",
                        "warehouse": rng.choice(WAREHOUSES)})
    titles = _unique(rng, lambda: " ".join(w.capitalize() for w in
                                           (rng.choice(ADJ), rng.choice(NOUN), rng.choice(NOUN))),
                     HTML_SECTIONS)
    sb.sections = titles
    sb.sub_files = [f"file_{i}.txt" for i in range(1, SUB_FILES + 1)]
    tickets = _unique(rng, lambda: f"TCK-{rng.randint(1000, 9999)}", GIT_COMMITS)
    notes = _unique(rng, lambda: "note-" + _token(rng, 6), GIT_COMMITS)
    for i in range(GIT_COMMITS):
        name, email = rng.choice(AUTHORS)
        sb.commits.append({
            "index": i + 1, "author": name, "email": email,
            "time": 1735689600 + i * 5 * 3600,  # 2025-01-01, every 5 hours
            "message": f"{rng.choice(VERBS)} {rng.choice(COMPONENTS)}: "
                       f"{rng.choice(ADJ)} {rng.choice(NOUN)} ({tickets[i]})",
            "ticket": tickets[i], "note": notes[i], "counter": rng.randint(100, 99999),
        })
    return sb


def log_line(r: dict[str, Any]) -> str:
    return f"{r['ts']} {r['level']:<5} {r['svc']} req={r['req']} user={r['user']} latency={r['latency']}ms"


def _lorem(rng: random.Random, words: int) -> str:
    return " ".join(rng.choice(ADJ + NOUN) for _ in range(words)).capitalize() + "."


def write_sandbox(sb: Sandbox, root: Path, seed: int = SEED) -> None:
    root.mkdir(parents=True, exist_ok=True)
    with open(root / "log.txt", "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(log_line(r) + "\n" for r in sb.log)
    with open(root / "inventory.csv", "w", encoding="utf-8", newline="\n") as fh:
        fh.write("sku,name,qty,price,warehouse\n")
        fh.writelines(f"{r['sku']},{r['name']},{r['qty']},{r['price']},{r['warehouse']}\n"
                      for r in sb.rows)
    rng = random.Random(seed + 7)
    with open(root / "report.html", "w", encoding="utf-8", newline="\n") as fh:
        fh.write("<!doctype html>\n<html><head><title>Quarterly report</title></head><body>\n"
                 "<h1>Quarterly report</h1>\n")
        for i, title in enumerate(sb.sections, 1):
            fh.write(f"<h2>Section {i}: {title}</h2>\n<p>{_lorem(rng, 45)}</p>\n")
        fh.write("</body></html>\n")
    (root / "sub").mkdir(exist_ok=True)
    for name in sb.sub_files:
        (root / "sub" / name).touch()


def _git(repo: Path, *args: str, input: bytes | None = None) -> str:
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    out = subprocess.run(["git", "-C", str(repo), *args], input=input, env=env,
                         capture_output=True, check=True)
    return out.stdout.decode("utf-8")


def write_repo(sb: Sandbox, repo: Path) -> dict[int, str]:
    """Build the scratch repo with git fast-import; return {commit index: full SHA}.

    Commits carry fixed authors and timestamps, so the SHAs are the same on
    every machine.
    """
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    stream: list[bytes] = []
    notes: list[str] = []
    for c in sb.commits:
        notes.append(f"- {c['note']}")
        files = {"counter.txt": f"{c['counter']}\n", "notes.md": "# Notes\n\n" + "\n".join(notes) + "\n"}
        msg = c["message"].encode()
        stream.append(b"commit refs/heads/main\n")
        stream.append(f"mark :{c['index']}\n".encode())
        who = f"{c['author']} <{c['email']}> {c['time']} +0000\n".encode()
        stream.append(b"author " + who + b"committer " + who)
        stream.append(f"data {len(msg)}\n".encode() + msg + b"\n")
        if c["index"] > 1:
            stream.append(f"from :{c['index'] - 1}\n".encode())
        for path, content in files.items():
            data = content.encode()
            stream.append(f"M 100644 inline {path}\ndata {len(data)}\n".encode() + data + b"\n")
        stream.append(b"\n")
    _git(repo, "fast-import", "--quiet", input=b"".join(stream))
    _git(repo, "checkout", "-q", "-f", "main")
    shas = _git(repo, "rev-list", "--reverse", "main").split()
    return {i + 1: sha for i, sha in enumerate(shas)}


def build(base: Path, seed: int = SEED) -> tuple[Sandbox, dict[int, str]]:
    """Write the sandbox and repo under ``base`` (rebuilt from scratch if missing)."""
    sb = generate(seed)
    sandbox, repo = base / "sandbox", base / "repo"
    if not (sandbox / "report.html").exists():
        write_sandbox(sb, sandbox, seed)
    if not (repo / ".git").exists():
        shas = write_repo(sb, repo)
    else:
        shas = {i + 1: s for i, s in enumerate(_git(repo, "rev-list", "--reverse", "main").split())}
    if len(shas) != GIT_COMMITS:
        raise RuntimeError(f"{repo} has {len(shas)} commits, expected {GIT_COMMITS}; delete it to rebuild")
    return sb, shas


def paths_for(base: Path) -> dict[str, str]:
    sandbox = (base / "sandbox").resolve()
    return {"SANDBOX": str(sandbox), "SANDBOX_URI": sandbox.as_uri(),
            "REPO": str((base / "repo").resolve())}


def _prefix_count(names: list[str], prefix: str) -> int:
    return sum(1 for n in names if n.startswith(prefix))


def make_tasks(sb: Sandbox, shas: dict[int, str], seed: int = SEED) -> list[Task]:
    rng = random.Random(seed + 1)
    tasks: list[Task] = []

    def add(server: str, kind: str, prompt: str, answer: Any, match: str = "exact") -> None:
        n = sum(1 for t in tasks if t.server == server) + 1
        tasks.append(Task(id=f"{server}-{n:02d}", server=server, split="dev", prompt=prompt,
                          answer=str(answer), match=match, kind=kind))

    def deep(lo: int, hi: int) -> int:
        return rng.randint(lo, hi)

    # filesystem: @modelcontextprotocol/server-filesystem on the sandbox
    log, rows = sb.log, sb.rows
    for line in [deep(40, 300)] + [deep(1500, LOG_LINES) for _ in range(3)]:
        add("filesystem", "log_line", f"In the file {{SANDBOX}}/log.txt, what is the request ID "
            f"(the value after req=) on line {line:,}?", log[line - 1]["req"])
    line = deep(1500, LOG_LINES)
    add("filesystem", "log_latency", f"In {{SANDBOX}}/log.txt, what is the latency in milliseconds on "
        f"line {line:,}? Answer with the number only.", log[line - 1]["latency"], "int")
    add("filesystem", "log_count", "How many lines does the file {SANDBOX}/log.txt have?",
        LOG_LINES, "int")
    add("filesystem", "log_last", "In {SANDBOX}/log.txt, what is the request ID (the value after "
        "req=) on the last line of the file?", log[-1]["req"])
    for prefix in ["file_1", "file_3", "file_25"]:
        add("filesystem", "sub_count", f"How many files in the folder {{SANDBOX}}/sub have names "
            f"starting with \"{prefix}\"?", _prefix_count(sb.sub_files, prefix), "int")
    for i in [deep(1200, CSV_ROWS - 1) for _ in range(3)]:
        add("filesystem", "csv_qty", f"In {{SANDBOX}}/inventory.csv, what is the qty of {rows[i]['sku']}?",
            rows[i]["qty"], "int")
    i = deep(1200, CSV_ROWS - 1)
    add("filesystem", "csv_warehouse", f"In {{SANDBOX}}/inventory.csv, which warehouse holds "
        f"{rows[i]['sku']}?", rows[i]["warehouse"])
    n = deep(250, HTML_SECTIONS)
    add("filesystem", "html_section", f"In {{SANDBOX}}/report.html, what is the title of Section {n}? "
        "Give the title only, without \"Section N:\".", sb.sections[n - 1])

    # markitdown: convert_to_markdown on file:// URIs into the sandbox
    for line in [deep(40, 300)] + [deep(1500, LOG_LINES) for _ in range(3)]:
        add("markitdown", "log_line", f"Convert {{SANDBOX_URI}}/log.txt to markdown. What is the request "
            f"ID (the value after req=) on line {line:,}?", log[line - 1]["req"])
    add("markitdown", "log_last", "Convert {SANDBOX_URI}/log.txt to markdown. What is the request ID "
        "(the value after req=) on the last line?", log[-1]["req"])
    for i in [deep(1200, CSV_ROWS - 1) for _ in range(3)]:
        add("markitdown", "csv_qty", f"Convert {{SANDBOX_URI}}/inventory.csv to markdown. What is the "
            f"qty of {rows[i]['sku']}?", rows[i]["qty"], "int")
    i = deep(1200, CSV_ROWS - 1)
    add("markitdown", "csv_price", f"Convert {{SANDBOX_URI}}/inventory.csv to markdown. What is the "
        f"price of {rows[i]['sku']}? Answer with the number only.", rows[i]["price"], "num")
    i = deep(1200, CSV_ROWS - 1)
    add("markitdown", "csv_warehouse", f"Convert {{SANDBOX_URI}}/inventory.csv to markdown. Which "
        f"warehouse holds {rows[i]['sku']}?", rows[i]["warehouse"])
    for n in [deep(20, 120)] + [deep(250, HTML_SECTIONS) for _ in range(3)]:
        add("markitdown", "html_section", f"Convert {{SANDBOX_URI}}/report.html to markdown. What is the "
            f"title of Section {n}? Give the title only, without \"Section N:\".", sb.sections[n - 1])
    add("markitdown", "html_count", "Convert {SANDBOX_URI}/report.html to markdown. How many numbered "
        "sections (\"Section N: ...\") does the report have?", HTML_SECTIONS, "int")

    # git: mcp-server-git on the scratch repo
    commits = sb.commits
    repo = "the git repository at {REPO}"
    picks = rng.sample(range(50, GIT_COMMITS - 50), 13)
    for k in picks[:5]:
        add("git", "commit_sha", f"In {repo}, which commit's message mentions {commits[k]['ticket']}? "
            "Give its commit hash (at least the first 7 characters).", shas[k + 1], "sha")
    for k in picks[5:8]:
        add("git", "commit_author", f"In {repo}, who is the author of the commit whose message mentions "
            f"{commits[k]['ticket']}? Give the author's name.", commits[k]["author"])
    for k in picks[8:10]:
        add("git", "counter_at", f"In {repo}, what number does counter.txt contain in the commit whose "
            f"message mentions {commits[k]['ticket']}?", commits[k]["counter"], "int")
    for k in picks[10:12]:
        add("git", "note_added", f"In {repo}, the commit whose message mentions {commits[k]['ticket']} "
            "added one line to notes.md. What note ID (note-xxxxxx) does that line hold?", commits[k]["note"])
    add("git", "commit_count", f"How many commits are on the main branch of {repo}?", GIT_COMMITS, "int")
    add("git", "first_commit", f"In {repo}, which ticket (TCK-NNNN) does the very first commit's "
        "message mention?", commits[0]["ticket"])
    who = AUTHORS[picks[12] % len(AUTHORS)][0]
    add("git", "author_count", f"How many commits on the main branch of {repo} were authored by {who}?",
        sum(1 for c in commits if c["author"] == who), "int")

    for server in ("filesystem", "markitdown", "git"):
        ids = [t.id for t in tasks if t.server == server]
        held = set(random.Random(f"{seed}-{server}").sample(ids, HELD_OUT_PER_SERVER))
        for t in tasks:
            if t.id in held:
                t.split = "test"
    return tasks


def save_tasks(tasks: list[Task], folder: Path) -> list[Path]:
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for server in sorted({t.server for t in tasks}):
        path = folder / f"{server}.json"
        items = [asdict(t) for t in tasks if t.server == server]
        path.write_text(json.dumps({"seed": SEED, "tasks": items}, indent=1) + "\n", encoding="utf-8")
        written.append(path)
    return written


def load_tasks(folder: Path) -> list[Task]:
    tasks = []
    for path in sorted(folder.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        tasks.extend(Task(**t) for t in data["tasks"])
    return tasks


# ---- answer checking ----

_ANSWER = re.compile(r"^\W*answer\W*:\s*(.*?)\s*$", re.IGNORECASE | re.MULTILINE)


def extract_answer(text: str | None) -> str | None:
    """The value on the last ``ANSWER: ...`` line, or None."""
    found = _ANSWER.findall(text or "")
    return found[-1] if found else None


def _normalize(value: str) -> str:
    v = value.strip()
    prev = None
    while v != prev:
        prev = v
        v = v.strip().strip("*`'\"").rstrip(".").strip()
    return " ".join(v.split()).casefold()


def check_answer(task: Task, answer: str | None) -> bool:
    if answer is None:
        return False
    got = _normalize(answer)
    if task.match == "int":
        nums = re.findall(r"-?\d[\d,]*", got)
        return len(nums) == 1 and nums[0].replace(",", "") == task.answer
    if task.match == "num":
        nums = re.findall(r"-?\d+(?:\.\d+)?", got.replace(",", ""))
        return len(nums) == 1 and abs(float(nums[0]) - float(task.answer)) < 1e-9
    if task.match == "sha":
        m = re.fullmatch(r"[0-9a-f]{7,40}", got)
        return bool(m) and task.answer.lower().startswith(got)
    return got == _normalize(task.answer)
