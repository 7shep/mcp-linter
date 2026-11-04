# mcp-linter

A linter for [MCP](https://modelcontextprotocol.io) servers. It connects to a server, reads its tool definitions, and flags the things that make tools hard for agents to use, based on Anthropic's [Writing effective tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents).

> Work in progress: static rules S1–S7 and probe rules P1, P4 and P5 are done; P2, P3, scoring and eval mode are next. See the [roadmap](#roadmap).

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
| `--error-probes` | (`run` only) Send generated bad arguments to read-only tools and check the errors (P4). Works without a fixtures file |
| `--probe-timeout SECONDS` | Per-call timeout for probes (default 30) |

## Probing

By default mcp-lint only reads tool definitions. With `--probe` it also **calls** tools and records what comes back: status, size in estimated tokens, content types, and latency. Probe rules (P1, P4, P5; see [Rules](#rules)) check these results.

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
- **Safety:** only tools annotated `readOnlyHint: true` run without opting in. Every other tool needs `"allow_destructive": true` in its probe, so only do that against a sandbox. That includes tools with no annotations, and tools marked `destructiveHint: false`: that hint means "only adds, never deletes" (like `git_commit`), which still changes state.
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

### Probe results on reference servers

| Server | Probe | Response (est.) | Findings |
|---|---|---|---|
| server-filesystem | `read_text_file` on a 20k-line file | ~87,000 tokens | P1 error, P5 warning |
| server-filesystem | `directory_tree` on a small sandbox | ~5,400 tokens | P1 warning, P5 warning |
| mcp-server-git | `git_log` with `max_count: 400` | ~15,000 tokens | P1 warning, P5 warning |
| mcp-server-git | `git_diff_staged` with a 5k-line file | ~7,300 tokens | P1 warning, P5 warning |
| mcp-server-git | `git_log` default (10 commits) | ~380 tokens | none |
| mcp-server-fetch | `fetch` default (truncates at 5,000 chars) | ~1,300 tokens | none |
| mcp-server-fetch | `fetch` with `max_length: 999999` | ~21,000 tokens | P1 warning, P5 warning |

mcp-server-fetch is a good example of the post's advice: it truncates by default and tells the agent how to get the next chunk.

**Error quality:** `--error-probes` sent 83 bad calls to six reference servers (filesystem, git, fetch, time, memory, everything) and P4 found nothing. Every error named the bad argument and what was expected, for example `Invalid timezone: 'No time zone found with key …'` or `path outside allowed directories: … not in …`. These are the MCP team's reference implementations, so a clean result is fair. Third-party servers are next.

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

Probe rules (only with `--probe`; they read what tools actually returned):

| ID | Severity | Checks |
|---|---|---|
| P1 | warning / error | A response over ~5k tokens, or over ~25k (Claude Code's default cap on tool output, so the agent sees it cut off) |
| P4 | warning / info | Error responses to bad input that won't help an agent fix its call: a leaked stack trace, an empty or opaque message ("Error executing tool X", "Internal error"), no mention of the bad input or what's expected, or invalid arguments accepted without an error |
| P5 | info / warning | A tool returned over ~1k / ~5k tokens but has no way to ask for less: no `response_format`, `verbosity`, `fields`-style parameter, or concise/detailed enum |

P4 checks every probe marked `expect_error`. Add `--error-probes` to generate them: for each **read-only** tool, mcp-lint sends a missing required argument, a wrong type, an invalid enum value, and an *unknown value* (well-formed but pointing at nothing, like `/mcp-lint/does/not/exist.txt` or `https://mcp-lint.invalid/...`). The first three test schema validation, which frameworks like zod and pydantic usually handle well. The unknown value gets past validation and tests the tool's **own** error handling, which is where opaque messages come from. A success on an unknown-value probe isn't flagged, since a search for something missing can rightly return nothing.

One trap P4 catches: in the MCP Python SDK 2.x, a tool that raises anything other than `ToolError` (a plain `ValueError`, say) has its message hidden. The agent only sees `Error executing tool <name>`.

P5 only fires when a probe showed a big response. A tool that always returns 20 tokens doesn't need a concise mode. Probes measure what the fixtures ask for, so a probe that requests 400 log entries shows what an agent *could* pull in one call.

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

- **More probe rules:** P2 opaque-ID share, P3 missing pagination.
- **Per-tool score**, weighted by how much each problem costs an agent: tokens spent and context wasted, not a flat count of warnings.
- **Eval mode:** generate multi-step agent tasks, run them before and after a fixing proxy rewrites the tools, and report the change in success rate and tokens.

## Development

```bash
python -m unittest discover -s tests
```

## License

MIT
