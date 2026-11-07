# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

mcp-lint lints MCP servers against Anthropic's "Writing effective tools for agents" guidance. It reads a server's tool definitions (and optionally calls the tools) and reports findings, a token-weighted score, and can serve the server back through a fixing proxy. Python 3.10+, one runtime dependency (`mcp>=2.1`), built with hatchling.

## Commands

```bash
python -m venv .venv
.venv/Scripts/pip install -e .          # Linux/macOS: .venv/bin/pip

python -m unittest discover -s tests                        # full suite (what CI runs)
python -m unittest discover -s tests -p test_cli.py         # one file
python -m unittest tests.test_cli.CheckCommandTests         # one class
python -m unittest tests.test_cli -k fails_on_error         # by name substring

python -m build                                              # sdist + wheel into dist/
mcp-lint check tests/fixtures/sample_tools.json              # lint a saved tools/list offline
mcp-lint run -- python tests/fixtures/demo_server.py         # lint a live stdio server
```

- Tests use stdlib `unittest`, not pytest. `tests/` has no `__init__.py`, so don't pass `-t .` to discover.
- The package must be installed (`pip install -e .`) for tests to import `mcp_lint`.
- `mcp-lint check`/`run` exit 1 whenever a finding is at or above `--fail-on` (default `error`), so exit 1 on a sample file is normal. Exit 2 is a usage or connection error.
- Some tests start `tests/fixtures/demo_server.py` as a real MCP server through `sys.executable`. The server's tracebacks in test output (e.g. `UnexpectedToolError: Error executing tool search_contacts`) are expected, not failures.
- No linter or formatter is configured.
- CI (`.github/workflows/ci.yml`) runs the suite on Ubuntu with Python 3.10–3.13 and Windows with 3.13, and builds and installs the wheel.

## Architecture

Pipeline for `run`/`check` (`cli.py:main`): get `ToolDef`s → `rules.run_static` → (`run` with `--probe`/`--error-probes`) `client.fetch_and_probe` + `rules.probe.run_probe_rules` → `report.render_*` / `to_json` → `score.score_server` → exit code.

- **`models.py`**: `ToolDef`, `Finding`, `Severity`. Rules work on these, never on MCP SDK objects, so rules are testable without a server. `ToolDef.read_only` is true only for an explicit `readOnlyHint: true`. That is the probe safety gate; `destructiveHint: false` does not count.
- **Rules** are plain functions returning `list[Finding]`, registered in lists that the runners iterate:
  - `rules/static.py`: `STATIC_RULES` (per tool: S1–S3) and `TOOLSET_RULES` (whole tool list: S4–S7).
  - `rules/security.py`: `SECURITY_RULES` (S8 hidden text). S8 is not scored.
  - `rules/probe.py`: `PROBE_RULES` (P1–P5), each taking `(tools_by_name, probe_results)`.
  - A new rule needs adding to its list, and to `score.FIXED_COSTS` (or `score.MEASURED`) if it should affect the score. The README's rule tables document every rule ID and threshold; keep them in sync.
- **`client.py`**: stdio connection via the MCP SDK, paginated `tools/list`, probe calls on one session. Servers get only the SDK's minimal default environment plus names passed with `--pass-env`. Never forward the full environment: keeping API keys away from linted servers is a stated guarantee. `safe_exec.py` applies the same minimal environment when the eval launches servers directly.
- **`fixtures.py` / `probe.py`**: the fixtures file format, argument and safety checks before any call (non-read-only tools need `"allow_destructive": true`), generated bad-argument probes for P4 (read-only tools only), and `ProbeResult` capture.
- **`score.py`**: turns findings into estimated wasted tokens per session; scores halve every `HALF_LIFE` tokens. All cost constants live here.
- **`text.py`**: token estimation (4 chars per token of compact JSON; always labelled as an estimate), name splitting and naming-style detection.
- **`proxy.py`** (`mcp-lint proxy`): an MCP server that wraps an upstream one and applies the fixes (paging with `offset`/`limit`, description replacement from `eval/fixes/*.json`, `isError` on error-as-success). Its pure functions (`rewrite_tool`, `page_text`, `fix_result`) are unit-tested without a server.
- **`lock.py`** (`mcp-lint lock`, `lock --check`): the rug-pull lockfile. `canonical()` normalises a `ToolDef` (every MCP `Tool` field) so equal schemas hash equal; `diff_lock()` classifies changes as `Finding(rule="LOCK", kind=...)`. The rule it enforces: any change to text the model or user reads, or that makes a schema accept or ask for more, is an error; anything else that changes the hash is at least a warning (fail closed). New change classes need a row in the README's Lockfile table. The lock never stores the raw launch command, only its hash.
- **`eval.py` / `evaltasks.py`** (`mcp-lint eval`): before/after experiment that runs headless `claude -p` against each server directly (`baseline`) and behind the proxy (`fixed`, plus single-fix ablations). Results append to `eval/results/results.jsonl` and the runner is resumable. `--run` makes real Claude Code calls; don't start it unless asked.

## Data directories

- `tests/fixtures/`: demo MCP servers and tool lists used by tests (`poisoned_tools.json` holds S8 attack strings on purpose).
- `survey/tools/`: saved `tools/list` results from 18 real servers. `tests/test_survey_tools.py` fails if S8 raises a warning or error on any of them, so S8 changes must stay quiet on this benign corpus. `survey/fixtures/` and `make_sandbox.py` reproduce the probe numbers in `RESULTS.md`.
- `eval/`: tasks, hand-written description fixes, recorded results, and `REPORT.md`. Results files are experiment records, not generated scratch; don't rewrite them.
