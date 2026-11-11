"""Save the tools/list of each holdout server (benchmark/holdout/servers.json).

Usage (from the repo root; run each server from a scratch folder):

    python benchmark/holdout_capture.py [--only NAME] [--workdir DIR]

Each server runs once at its pinned version, through mcp-lint's own client:
it gets only the SDK's minimal environment plus the placeholder variables in
servers.json, never real credentials, and no tool is called. The result goes
to benchmark/holdout/tools/<name>.json in the shape of survey/tools/*.json.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile

from mcp_lint.client import fetch_tools

HERE = os.path.dirname(os.path.abspath(__file__))
HOLDOUT = os.path.join(HERE, "holdout")
PLACEHOLDER = "placeholder-not-a-real-credential"


def write_placeholder_files(server: dict, workdir: str) -> dict[str, str]:
    """Create any placeholder files a server needs at startup; return env values that point at them."""
    env: dict[str, str] = {}
    for var, content in server.get("placeholder_files", {}).items():
        path = os.path.join(workdir, f"{server['name']}-{var.lower()}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(content, f)
        env[var] = path
    return env


async def capture(server: dict, workdir: str, timeout: float) -> dict:
    env = {var: (PLACEHOLDER if value is None else value) for var, value in server.get("env", {}).items()}
    env.update(write_placeholder_files(server, workdir))
    os.environ.update(env)  # forwarded by name only, below
    info = await asyncio.wait_for(fetch_tools(server["command"][0], server["command"][1:], list(env)), timeout)
    tools = []
    for t in info.tools:
        entry = {"name": t.name, "description": t.description, "inputSchema": t.input_schema}
        if t.annotations:
            entry["annotations"] = t.annotations
        if t.title:
            entry["title"] = t.title
        tools.append(entry)
    return {"server": info.name, "version": info.version, "command": server["command"], "tools": tools}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", action="append", help="capture only this server (repeatable)")
    parser.add_argument("--workdir", default=None, help="folder the servers run in (default: a new temp folder)")
    parser.add_argument("--timeout", type=float, default=240.0)
    args = parser.parse_args()

    with open(os.path.join(HOLDOUT, "servers.json"), encoding="utf-8") as f:
        servers = json.load(f)["servers"]
    workdir = args.workdir or tempfile.mkdtemp(prefix="mcp-holdout-")
    os.makedirs(os.path.join(HOLDOUT, "tools"), exist_ok=True)
    os.chdir(workdir)
    failed = 0
    for server in servers:
        if args.only and server["name"] not in args.only:
            continue
        try:
            data = asyncio.run(capture(server, workdir, args.timeout))
        except BaseException as exc:  # noqa: BLE001 - report and move on to the next server
            if isinstance(exc, KeyboardInterrupt):
                raise
            failed += 1
            print(f"{server['name']}: FAILED {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
            continue
        path = os.path.join(HOLDOUT, "tools", f"{server['name']}.json")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=1, sort_keys=True, ensure_ascii=False)
            f.write("\n")
        print(f"{server['name']}: {len(data['tools'])} tools -> {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
