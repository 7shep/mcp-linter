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

- **Probe rules (real calls):** response size, opaque-ID share, missing pagination, error-message quality, `response_format` support, plus a per-tool score.
- **Eval mode:** generate multi-step agent tasks, run them before and after a fixing proxy rewrites the tools, and report the change in success rate and tokens.

## Development

```bash
python -m unittest discover -s tests
```

## License

MIT
