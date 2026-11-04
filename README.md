# mcp-linter

A linter for [MCP](https://modelcontextprotocol.io) servers. It connects to a server, reads its tool definitions, and flags the things that make tools hard for agents to use, based on Anthropic's [Writing effective tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents).

> Early work in progress: rules S1–S3 are implemented. See the [roadmap](#roadmap).

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
2 tools checked

get
  ! S1 Description is only 2 words (aim for 15+).
      -> Add when to use this tool, what it returns, and any limits.
  ! S2 [id] Parameter 'id' has a vague name and no description.
      -> Use a specific name (e.g. 'user_id' not 'user') or describe what value is expected.
  i S3 [id] Parameter 'id' has no description.
      -> Say what the value means and give an example format.

0 errors, 2 warnings, 1 info; 1/2 tools clean
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

## Roadmap

- **Static rules:** S4 near-duplicate tools, S5 name prefixes, S6 total definition tokens, S7 `list_*` tools without limits or filters.
- **Probe rules (real calls):** response size, opaque-ID share, missing pagination, error-message quality, `response_format` support, plus a per-tool score.
- **Eval mode:** generate multi-step agent tasks, run them before and after a fixing proxy rewrites the tools, and report the change in success rate and tokens.

## Development

```bash
python -m unittest discover -s tests
```

## License

MIT
