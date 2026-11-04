# Results

mcp-lint run on 18 MCP servers (8 official reference servers and 10 popular third-party ones), 2026-11-04. Token counts are **estimates** (4 characters per token). Fixtures and sandbox are in [`survey/`](survey/).

## Headlines

1. **Two servers return whole documents with no limit.** Microsoft's markitdown-mcp converted a 20,000-line file into one ~87,000-token response, and one Python docs page into ~29,000. The official server-filesystem returned the same ~87,000 tokens for the same file. Both are over Claude Code's default 25,000-token cap on tool output, so the agent sees a cut-off result. Neither tool can return less: markitdown's only parameter is `uri`.
2. **A community server does this better than the official one.** Desktop Commander reads the same file 1,000 lines at a time (~4,000 tokens) and starts with `[Reading 1000 lines from start (total: 20000 lines, 19000 remaining)]`, so the agent knows there's more and how much. This is the pattern the post recommends.
3. **Three servers spend over 10,000 tokens just describing their tools**, on every request, before any tool is called: Notion (~18,700, 24 tools), Firecrawl (~13,200, 26 tools) and Desktop Commander (~12,500, 25 tools). The largest official server, Playwright, is ~4,600 for 25 tools.
4. **Notion's tools are named and described like an API reference, not for an agent.** 22 of its 24 descriptions are under 15 words (e.g. `API-retrieve-a-block`: "Retrieve a block"). Its definitions are still the heaviest in the survey: the tokens go into large parameter schemas, not into telling the agent when to use each tool.
5. **4 of 10 third-party servers annotate none of their tools** (aws-docs, duckduckgo, markitdown, tavily). Clients can't tell which tools are read-only, so they have to ask before every call or trust blindly.
6. **Error messages are mostly good.** 137 bad calls (83 to official servers, 54 to third-party ones) found no stack traces and no opaque errors. Context7 stands out: `Invalid library ID format: "…". Expected format: /owner/repo or /owner/repo/version`. The issues found:
   - duckduckgo-mcp-server returns errors (`Error: Refusing to fetch …`) as **successful** results, without setting `isError`.
   - Desktop Commander's `get_config` accepted an invalid `origin` value without complaint.
   - Desktop Commander passes raw validation output to the agent (`Error: [ { "code": "invalid_type", … } ]`). It names the bad argument, so P4 doesn't flag it, but it's noisy.

## Third-party servers

| Server | Version | Downloads/mo | Tools | Definition tokens | Annotated read-only | Static findings (warnings) |
|---|---|---|---|---|---|---|
| chrome-devtools-mcp (Google) | 1.12.0 | 7.7M npm | 32 | ~6,900 | 8 | S1 ×16, S7 ×1 |
| @upstash/context7-mcp | 4.5.0 | 2.5M npm | 2 | ~1,200 | 2 | none |
| @wonderwhy-er/desktop-commander | 0.3.1 | 1.7M npm | 25 | ~12,500 | 13 | **S6**, S7 ×4, S2 ×2, S3 ×1 |
| @notionhq/notion-mcp-server | 1.0.0 | 810k npm | 24 | ~18,700 | 12 | **S6**, S1 ×22 |
| firecrawl-mcp | 3.36.1 | 510k npm | 26 | ~13,200 | 17 | **S6**, S2 ×10 |
| exa-mcp-server | 3.4.3 | 110k npm | 2 | ~500 | 2 | none |
| tavily-mcp | 0.2.22 | 78k npm | 5 | ~1,900 | 0 (no annotations) | S1 ×1 |
| duckduckgo-mcp-server | not reported | 72k PyPI | 3 | ~1,000 | 0 (no annotations) | none |
| markitdown-mcp (Microsoft) | not reported | n/a | 1 | ~70 | 0 (no annotations) | S1 ×1 |
| awslabs.aws-documentation-mcp-server | not reported | n/a | 5 | ~3,700 | 0 (no annotations) | none |

@brave/brave-search-mcp-server wouldn't start without an API key. Notion, Firecrawl, Exa and Tavily need keys to call tools, so they were only checked statically.

### Probes

| Server | Probe | Response | Findings |
|---|---|---|---|
| markitdown | `convert_to_markdown` on a 20k-line file | ~87,200 tokens | P1 error, P5 |
| markitdown | `convert_to_markdown` on a Python docs page | ~29,000 tokens | P1 error |
| desktop-commander | `read_file` on the same 20k-line file | ~4,000 tokens (first 1,000 lines + how many remain) | P5 info |
| desktop-commander | `list_directory` on 300 files | ~1,500 tokens | P5 info |
| duckduckgo | `fetch_content` default | ~2,000 tokens | none |
| duckduckgo | `fetch_content` with `max_length: 999999` | ~20,100 tokens | P1, P5 |
| aws-docs | `read_documentation` default | ~1,300 tokens | none |
| aws-docs | `read_documentation` with `max_length: 999999` | ~13,100 tokens | P1, P5 |
| context7 | `resolve-library-id` / `query-docs` | ≤ ~460 tokens | none |
| chrome-devtools | `list_pages` + 16 error probes | small | none |

The pattern: tools that truncate by default and take a `max_length` (duckduckgo, aws-docs, mcp-server-fetch) only go big when asked. Tools with no limit (markitdown, server-filesystem's `read_text_file` without `head`/`tail`) go big on ordinary input.

## Official reference servers

| Server | Tools | Definition tokens | Notable |
|---|---|---|---|
| server-filesystem | 14 | ~2,000 | S4: `read_file`/`read_text_file`, `list_directory`/`list_directory_with_sizes`. `read_text_file` on a 20k-line file: ~87,000 tokens (P1 error) |
| server-github | 26 | ~4,000 | S4: `get_pull_request` and its `_files`/`_comments`/`_reviews` variants |
| mcp-server-git | 12 | ~1,200 | S4: `git_diff_staged`/`git_diff_unstaged`. `git_log` with 400 commits: ~15,000 tokens (default 10: ~380) |
| @playwright/mcp | 25 | ~4,600 | none |
| server-everything | 16 | ~1,800 | S1 ×8 |
| server-memory | 9 | ~1,100 | none |
| mcp-server-fetch | 1 | ~260 | truncates at 5,000 chars by default and says how to get more |
| mcp-server-time | 2 | ~290 | none |

## What the survey changed in mcp-lint

- **S4** flagged Notion's `retrieve-a-block` / `delete-a-block` and Chrome's `screencast_start` / `screencast_stop`. They share parameters and wording but do opposite things. Pairs whose names use different action verbs are now skipped.
- **P4** labelled duckduckgo's error-as-success responses "accepted invalid arguments". It now reports them as their own kind.
- **Before running third-party code**, mcp-lint stopped passing the user's full environment (API keys included) to servers. They now get only a minimal safe set, plus anything named with `--pass-env`.
