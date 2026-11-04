# mcp-linter

A linter for [MCP](https://modelcontextprotocol.io) servers. It connects to a server, reads its tool definitions, and flags the things that make tools hard for agents to use, based on Anthropic's [Writing effective tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents).

> Work in progress: the static rules S1–S7 are done; probe rules and eval mode are next. See the [roadmap](#roadmap).

## Install

Needs Python 3.10+.

```bash
git clone https://github.com/7shep/mcp-linter.git
cd mcp-linter
python -m venv .venv
.venv/bin/pip install -e .        # Windows: .venv\Scripts\pip install -e .
```

## Usage

Lint a live server over stdio (put the server command after `--`):

```bash
mcp-lint run -- npx -y @modelcontextprotocol/server-everything
```

Lint a saved `tools/list` result:

```bash
mcp-lint check tools.json --json report.json
```

Example output:

```
mcp-lint 0.1.0  server: demo-server
2 tools checked, definitions ~165 tokens (estimated)

(server)
  i S5 Tool names have no shared service prefix.
      -> Prefix names by service (e.g. 'github_create_issue') so they stay distinct when an agent has many servers loaded. Some clients add a namespace for you.

get
  ! S1 Description is only 2 words (aim for 15+).
      -> Add when to use this tool, what it returns, and any limits.
  ! S2 [id] Parameter 'id' has a vague name and no description.
      -> Use a specific name (e.g. 'user_id' not 'user') or describe what value is expected.
  i S3 [id] Parameter 'id' has no description.
      -> Say what the value means and give an example format.

0 errors, 2 warnings, 2 info; 1/2 tools clean
```

Options:

| Flag | Meaning |
|---|---|
| `--json PATH` | Also write a machine-readable report |
| `--min-severity info\|warning\|error` | Hide terminal findings below this level |
| `--fail-on info\|warning\|error\|never` | Exit 1 if any finding is at or above this level (default `error`) |
| `--probe FIXTURES` | (`run` only) Also call the tools listed in a fixtures file; see [Probing](#probing) |
| `--probe-timeout SECONDS` | Per-call timeout for probes (default 30) |

## Probing

By default mcp-lint only reads tool definitions. With `--probe` it also **calls** tools and records what comes back: status, size in estimated tokens, content types, and latency. The probe rules (planned, see [roadmap](#roadmap)) will check these results.

Only tools listed in a fixtures file are ever called. Generate a starter file, then edit it:

```bash
mcp-lint init-fixtures fixtures.json -- npx -y @modelcontextprotocol/server-filesystem ./sandbox
```

```json
{
  "version": 1,
  "probes": [
    {"tool": "read_text_file", "label": "big", "args": {"path": "${FIXTURES_DIR}/sandbox/big.txt"}},
    {"tool": "read_text_file", "label": "missing file", "args": {"path": "${FIXTURES_DIR}/sandbox/nope.txt"}, "expect_error": true},
    {"tool": "write_file", "args": {"path": "...", "content": "x"}, "allow_destructive": true},
    {"tool": "move_file", "args": {}, "skip": true}
  ]
}
```

- Generated probes start with `"skip": true`. Fill in the args and delete `skip` to run them.
- **Safety:** a tool that isn't annotated `readOnlyHint: true` (or `destructiveHint: false`) is treated as one that may change data, as the MCP spec says. mcp-lint won't call it unless the probe sets `"allow_destructive": true`. Only do that against a sandbox.
- Probes with missing required args, wrong-typed args, or unknown tool names are blocked before any call.
- `"expect_error": true` marks a probe that's meant to fail, such as bad arguments for testing error messages. Argument checks are skipped for it, but the safety check isn't.
- `${FIXTURES_DIR}` expands to the fixtures file's folder, and `${NAME}` to an environment variable, so fixtures can point at a local sandbox and keep secrets out of the file.

```bash
mcp-lint run --probe fixtures.json -- npx -y @modelcontextprotocol/server-filesystem ./sandbox
```

```
Probes
  read_text_file (small)          ok                            ~3 tok  4 ms
  read_text_file (big)            ok                       ~87,224 tok  7 ms
  read_text_file (missing file)   tool_error (expected)        ~43 tok  2 ms
  directory_tree                  ok                        ~5,419 tok  7 ms
  write_file (should be blocked)  blocked
      tool is not marked read-only, so it may change data; add "allow_destructive": true to run it (sandbox only)
```

Reading a 20,000-line file through server-filesystem returns about 87k tokens in one response, over three times Claude Code's default 25k cap on tool output.

## Rules

| ID | Severity | Checks |
|---|---|---|
| S1 | error / warning | Description missing, or shorter than 15 words |
| S2 | warning | Vague parameter name (`id`, `user`, `data`, `q`, ...) with no description |
| S3 | warning / info | Parameter with no type or enum / no description |
| S4 | warning | Two tools that overlap: similar name + description (TF-IDF ≥ 0.5) **and** at least half their parameters shared |
| S5 | warning / info | A tool missing the service prefix most tools use; no shared prefix at all; mixed naming styles |
| S6 | warning / error | All tool definitions together over ~10k / ~25k tokens |
| S7 | warning | `list_*` / `get_all_*` tool with no limit, paging, or filter parameter |

All rules run offline with no API key. Token counts are **estimates** (4 characters per token of compact JSON) and are labelled as such. Findings with no tool (S5 prefix/style notes, S6) appear under `(server)` in the terminal and in `server_findings` in the JSON report.

S4's thresholds were tuned on 8 official reference servers (105 tools). Similar text alone flagged unrelated tools with templated descriptions ("Create a new X in a repository"), so a pair must also share parameters. It still flags pairs like `get_pull_request` / `get_pull_request_files`. The post suggests consolidating those, but you may decide they're fine as separate tools.

### Sample results

| Server | Tools | Definition tokens (est.) | S4 overlaps | S7 unbounded lists |
|---|---|---|---|---|
| server-filesystem | 14 | ~2,000 | `read_file`/`read_text_file`, `list_directory`/`list_directory_with_sizes` | 2 |
| server-github | 26 | ~4,000 | `get_pull_request` vs its `_files`/`_comments`/`_reviews` variants, `get_issue`/`get_pull_request` | 0 |
| mcp-server-git | 12 | ~1,200 | `git_diff_staged`/`git_diff_unstaged` | 0 |
| @playwright/mcp | 25 | ~4,600 | none | 0 |

## Roadmap

- **Probe rules** (on `--probe` results): P1 response size, P2 opaque-ID share, P3 missing pagination, P4 error-message quality, P5 `response_format` support.
- **Per-tool score**, weighted by how much each problem costs an agent: tokens spent and context wasted, not a flat count of warnings.
- **Eval mode:** generate multi-step agent tasks, run them before and after a fixing proxy rewrites the tools, and report the change in success rate and tokens.

## Development

```bash
python -m unittest discover -s tests
```

## License

MIT
