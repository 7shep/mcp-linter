# mcp-linter

A linter for [MCP](https://modelcontextprotocol.io) servers. It connects to a server, reads its tool definitions, and flags the things that make tools hard for agents to use, based on Anthropic's [Writing effective tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents).

> Static rules S1–S7, probe rules P1–P5, a token-weighted score, a fixing proxy and an eval mode are done. See [Eval](#eval) for whether the findings matter.

## Findings

From running it on 18 servers, 8 official and 10 popular third-party ones. Full tables are in [RESULTS.md](RESULTS.md), and the setup to reproduce them is in [`survey/`](survey/).

- **Two servers return whole documents with no limit.** Microsoft's markitdown-mcp turned a 20,000-line file into one ~87,000-token response, and the official server-filesystem did the same. That's over three times Claude Code's 25,000-token cap on tool output.
- **Desktop Commander gets it right:** it reads the same file 1,000 lines at a time (~4,000 tokens) and tells the agent how many lines remain.
- **Notion, Firecrawl and Desktop Commander each spend over 10,000 tokens** just describing their tools, on every request. Notion's 24 descriptions are mostly under 15 words; the tokens go into parameter schemas.
- **4 of 10 third-party servers annotate none of their tools**, so clients can't tell which are read-only.
- **Error messages are mostly good** across 137 bad calls. One server (duckduckgo-mcp-server) returns errors as successful results.

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
mcp-lint 1.0.0  server: demo-server
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
| `--fail-under SCORE` | Also exit 1 if the server score (0-100) is below this; see [Score](#score) |
| `--probe FIXTURES` | (`run` only) Also call the tools listed in a fixtures file; see [Probing](#probing) |
| `--error-probes` | (`run` only) Send generated bad arguments to read-only tools and check the errors (P4). Works without a fixtures file |
| `--include-responses` | (`run` only) Keep full probe response text in the `--json` report instead of a 400-character preview |
| `--probe-timeout SECONDS` | Per-call timeout for probes (default 30) |
| `--pass-env NAME` | (`run`, `init-fixtures`) Forward an environment variable to the server; repeatable. Servers otherwise get only a minimal safe set (PATH, TEMP, home folder...), so your API keys and tokens never reach a server you didn't hand them to |

## Probing

By default mcp-lint only reads tool definitions. With `--probe` it also **calls** tools and records what comes back: status, size in estimated tokens, content types, and latency. Probe rules (P1–P5; see [Rules](#rules)) check these results.

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
| P2 | info / warning | Opaque IDs (UUIDs, long hex like git SHAs, random 20+ char tokens) taking up over 10% / 25% of a response **without readable labels** next to them. A response passes when most records that hold an ID (lines, blank-line-separated blocks, or JSON objects) also hold readable words such as a name or title |
| P3 | warning / info | A response over ~5k tokens with no paging cursor or note about what's left (checked in its first and last 600 characters). A warning if the tool has no paging or limit parameters; info if it does, since the agent asked for that much |
| P4 | warning / info | Error responses to bad input that won't help an agent fix its call: a leaked stack trace, an empty or opaque message ("Error executing tool X", "Internal error"), no mention of the bad input or what's expected, an error returned as a successful result (no `isError`), or invalid arguments accepted without an error |
| P5 | info / warning | A tool returned over ~1k / ~5k tokens but has no way to ask for less: no `response_format`, `verbosity`, `fields`-style parameter, or concise/detailed enum |

P4 checks every probe marked `expect_error`. Add `--error-probes` to generate them: for each **read-only** tool, mcp-lint sends a missing required argument, a wrong type, an invalid enum value, and an *unknown value* (well-formed but pointing at nothing, like `/mcp-lint/does/not/exist.txt` or `https://mcp-lint.invalid/...`). The first three test schema validation, which frameworks like zod and pydantic usually handle well. The unknown value gets past validation and tests the tool's **own** error handling, which is where opaque messages come from. A success on an unknown-value probe isn't flagged, since a search for something missing can rightly return nothing.

One trap P4 catches: in the MCP Python SDK 2.x, a tool that raises anything other than `ToolError` (a plain `ValueError`, say) has its message hidden. The agent only sees `Error executing tool <name>`.

P5 only fires when a probe showed a big response. A tool that always returns 20 tokens doesn't need a concise mode. Probes measure what the fixtures ask for, so a probe that requests 400 log entries shows what an agent *could* pull in one call.

All rules run offline with no API key. Token counts are **estimates** (4 characters per token of compact JSON) and are labelled as such. Findings with no tool (S5 prefix/style notes, S6) appear under `(server)` in the terminal and in `server_findings` in the JSON report.

S4's thresholds were tuned on 8 official reference servers (105 tools) and checked on 10 third-party ones. Similar text alone flagged unrelated tools with templated descriptions ("Create a new X in a repository"), so a pair must also share parameters. Pairs whose names use different action verbs (`retrieve-a-block` / `delete-a-block`) are skipped. It still flags pairs like `get_pull_request` / `get_pull_request_files`. The post suggests consolidating those, but you may decide they're fine as separate tools.

## Score

Every run ends with a score: each tool's, and the server's, out of 100. It's weighted by **how many tokens each problem costs an agent**, not by counting warnings. One 87k-token response matters far more than a dozen short descriptions.

```
Score: 25/100 (D)  ~20,066 tokens wasted per session (estimated; static checks + probes)
    0 F  read_text_file   87,224-token response: ~85,224, P5 no concise mode: ~300, S3 undescribed param [path]: ~100
   51 C  directory_tree   5,419-token response: ~3,419, P3 no paging hint: ~1,000, P5 no concise mode: ~300
   86 B  read_file        S1 short description: ~500, S4 overlaps another tool: ~500, S3 undescribed param [path]: ~100
   ...
```

That's server-filesystem: one tool that dumps whole files sinks the server.

Each finding becomes an estimate of tokens wasted per session:

- **Measured from probes:**
  - response tokens over a 2,000-token budget (P1)
  - characters spent on unlabelled IDs (P2)

  Responses the probe *asked* to be big (it set `max_length`, `max_count` and so on) aren't charged. Neither are responses that say what's left ("19000 remaining"): the agent controls those.
- **Measured from definitions:** tokens over 300 per tool, counted twice per session. Definitions are resent every turn but usually prompt-cached, so this assumes about 20 turns at about 10% cost.
- **Estimated, for problems that cause retries or wrong picks:**

| Finding | Estimated waste (tokens per session) |
|---|---|
| No description (S1) | 2,000 |
| Unbounded list, if not measured (S7) | 2,000 |
| Opaque or empty error, leaked stack trace (P4) | 1,500 |
| Big response, no paging hint, no paging params (P3) | 1,000 |
| Error with no guidance (P4) | 700 |
| Short description (S1), overlapping tool (S4), error as success / accepted bad input (P4) | 500 |
| Vague or untyped parameter (S2, S3) | 300 |

A **tool's score** halves for every 5,000 wasted tokens. The **server's waste** adds up all definition overhead, since that's paid every session whichever tools are used. To that it adds the average per-tool usage waste, times 3 tools used per session. The server score halves for every 10,000.

The constants are rough guesses, kept in one place ([`score.py`](src/mcp_lint/score.py)) so they can be argued with. Treat the ordering as the result, not the exact numbers. Without `--probe` the score covers only static checks, and the report says so. `--fail-under SCORE` exits 1 when the server scores below a threshold.

## Eval

Do mcp-lint's findings matter to a real agent? [`eval/REPORT.md`](eval/REPORT.md) has the before/after experiment: Claude Code (headless, `--model haiku`) answers checkable questions with one MCP server connected, once with the server as it ships and once behind `mcp-lint proxy`, which fixes what mcp-lint flags.

**Result:** on 15 held-out tasks across server-filesystem, markitdown-mcp and mcp-server-git (90 runs), success rose from 53% to 98%. Nearly all of that came from paging long responses, and the worst-scored server (markitdown, 0/100) gained the most. Tokens per task did **not** go down: paging turns quick give-ups into long successes. See the report for the full numbers and caveats.

![Task success with and without mcp-lint fixes: all tasks 53% to 98%, markitdown-mcp 0% to 100%, server-filesystem 80% to 100%, mcp-server-git 80% to 93%](eval/chart/success.png)

```bash
mcp-lint proxy --descriptions eval/fixes/mcp-server-git.json -- uvx mcp-server-git   # serve fixed tools over stdio
mcp-lint eval --setup                                   # build the sandbox + repo, write eval/tasks/
mcp-lint eval --run --split test --runs 3               # runs `claude -p`; resumable
mcp-lint eval --report                                  # tables from eval/results/results.jsonl
```

The proxy's fixes are each switchable (`--no-paging`, `--no-errors`, `--descriptions FILE`):

- **Paging:** responses over ~2,000 tokens are cut to a page, every tool gains `offset`/`limit` (in lines), and a note says `[showing lines 1-112 of 8000; pass offset=112 for more]`.
- **Descriptions:** S1-flagged descriptions are replaced from a hand-written file in [`eval/fixes/`](eval/fixes/).
- **Errors:** error text returned as a success gets `isError` set.

## Development

```bash
python -m unittest discover -s tests
```

## License

MIT
