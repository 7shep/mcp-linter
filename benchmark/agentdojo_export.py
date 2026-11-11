"""Export AgentDojo's tool suites as saved tools/list files, plus each task's tool route.

Run it with the Python that has AgentDojo installed, not mcp-lint's:

    <agentdojo-venv>/python -I benchmark/agentdojo_export.py [--out DIR] [--version v1.2]

It writes, under DIR (default benchmark/results/agentdojo):

- tools/<suite>.json: the suite's tools in the shape of survey/tools/*.json
  (name, description, inputSchema), so mcp-lint's tagger can read them.
- cases.json: for each user task, the tools whose results carry an injection
  placeholder when the task is done correctly (found with AgentDojo's own
  canary method), and for each injection task, the tool calls its ground truth
  makes, in order.

Only tool names, task ids and placeholder ids are written. No task prompt,
goal or attack text leaves AgentDojo. No model is called.
"""

from __future__ import annotations

import argparse
import json
import os

from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import get_text_content_as_str

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(HERE, "results", "agentdojo")


def tool_list(suite, version: str) -> dict:
    tools = [
        {
            "name": f.name,
            "description": f.description,
            "inputSchema": f.parameters.model_json_schema(),
        }
        for f in sorted(suite.tools, key=lambda f: f.name)
    ]
    return {"server": f"agentdojo-{suite.name}", "version": version, "command": [], "tools": tools}


def source_tools(suite, user_task) -> dict:
    """Same method as AgentDojo's BaseAttack.get_injection_candidates, keeping the tool names."""
    canaries = {inj: f"<CANARY---{inj}--->" for inj in suite.get_injection_vector_defaults()}
    env = suite.load_and_inject_default_environment(canaries)
    runtime = FunctionsRuntime(suite.tools)
    _, _, _, messages, _ = GroundTruthPipeline(user_task).query(user_task.PROMPT, runtime, env)
    tools: set[str] = set()
    vectors: set[str] = set()
    for message in messages:
        if message["role"] != "tool" or message["content"] is None:
            continue
        text = get_text_content_as_str(message["content"])
        hits = {inj for inj, canary in canaries.items() if canary in text}
        if hits:
            tools.add(message["tool_call"].function)
            vectors |= hits
    return {"source_tools": sorted(tools), "vectors": sorted(vectors)}


def injection_calls(suite, injection_task) -> dict:
    env = suite.load_and_inject_default_environment(suite.get_injection_vector_defaults())
    return {"calls": [call.function for call in injection_task.ground_truth(env)]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--version", default="v1.2")
    args = parser.parse_args()

    os.makedirs(os.path.join(args.out, "tools"), exist_ok=True)
    cases: dict = {"benchmark_version": args.version, "suites": {}}
    for name, suite in sorted(get_suites(args.version).items()):
        with open(os.path.join(args.out, "tools", f"{name}.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(tool_list(suite, args.version), f, indent=1, sort_keys=True)
            f.write("\n")
        cases["suites"][name] = {
            "user_tasks": {tid: source_tools(suite, t) for tid, t in suite.user_tasks.items()},
            "injection_tasks": {tid: injection_calls(suite, t) for tid, t in suite.injection_tasks.items()},
        }
    with open(os.path.join(args.out, "cases.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(cases, f, indent=1, sort_keys=True)
        f.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
