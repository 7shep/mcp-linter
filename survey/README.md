# Survey

The fixtures and sandbox used for [RESULTS.md](../RESULTS.md), so the numbers can be reproduced.

## Saved tool lists

`tools/` holds the `tools/list` results of the 18 surveyed servers (230 tools): 8 official reference servers and 10 popular third-party ones, captured on 2026-11-04. Most were run at `@latest`, so a server's current tools may differ; `version` and `command` record what was run where they're known. Lint any of them offline:

```bash
mcp-lint check survey/tools/notion.json
```

They're also a benign corpus for checking false positives. `tests/test_survey_tools.py` fails if the security rule S8 raises a warning or error on any of them.

## Reproducing the probes

```bash
python survey/make_sandbox.py
```

Then run each server from a scratch folder. Servers only get a minimal environment, so none of them see your API keys:

```bash
mcp-lint run --error-probes --probe survey/fixtures/markitdown.json --json markitdown.json -- uvx markitdown-mcp
mcp-lint run --error-probes --probe survey/fixtures/desktop-commander.json -- npx -y @wonderwhy-er/desktop-commander@latest
mcp-lint run --error-probes --probe survey/fixtures/context7.json -- npx -y @upstash/context7-mcp@latest
mcp-lint run --error-probes --probe survey/fixtures/chrome-devtools.json -- npx -y chrome-devtools-mcp@latest --headless --isolated
mcp-lint run --error-probes --probe survey/fixtures/aws-docs.json -- uvx awslabs.aws-documentation-mcp-server@latest
mcp-lint run --error-probes --probe survey/fixtures/duckduckgo.json -- uvx duckduckgo-mcp-server
mcp-lint run --error-probes --probe survey/fixtures/filesystem.json -- npx -y @modelcontextprotocol/server-filesystem survey/sandbox
```

Notes:

- `--error-probes` only sends bad arguments to tools annotated read-only.
- aws-docs, duckduckgo and markitdown annotate none of their tools, so their fixtures opt in with `"allow_destructive": true`. Their tools only fetch or read; check that for yourself before copying the pattern.
- Network servers (aws-docs, duckduckgo, context7, markitdown's web probe) make real requests, so results change as the pages and APIs do.
