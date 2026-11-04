# Does fixing what mcp-lint flags help an agent?

**Summary (paste-ready):**

1. On 15 held-out tasks across 3 local MCP servers, with Claude Code (Haiku) as the agent, putting the servers behind a proxy that fixes what mcp-lint flags raised success from **53% to 98%** (paired difference +44 points, 95% CI +18 to +71; 90 runs).
2. The gain comes almost entirely from **paging** (better descriptions alone: +7 points, within noise): unpaged tools returned whole files, Claude Code capped them at ~25k tokens, and the agent gave up. markitdown-mcp (mcp-lint's worst score, 0/100) went from 0/15 to 15/15. mcp-server-git (its best of the three, 87/100) gained least, +13 points, within noise.
3. Fixing did **not** save tokens overall: +93k per task on average (CI −1k to +222k). Failed baseline runs quit early and cheap, and scanning a large result in 2,000-token pages costs many turns. On tasks both conditions always solved, tokens were about the same (−5%).

## Setup

**Agent.** Claude Code 2.1.318 run headless on a Claude subscription: `claude -p --output-format stream-json --verbose --model haiku --max-turns 25`. There was no API key, so the agent is the real product rather than a hand-written loop. That makes the results about what a Claude Code user would see, with Claude Code's own system prompt, tool handling and output cap. Every run used `claude-haiku-5-5` (from the reported `modelUsage`).

Each run gets only the server under test:

- `--mcp-config <temp file> --strict-mcp-config`: no other MCP servers.
- `--tools ""`: no built-in tools (Read, Bash, Grep...), so the agent must use MCP tools.
- `--allowedTools` lists only that server's **read-only** tools. Write tools (`write_file`, `git_commit`...) stay in the tool list but are denied: `--permission-mode dontAsk --permission-prompts none`.
- `--setting-sources project` from a cwd with no settings, `--disable-slash-commands`, `--no-session-persistence`: the user's global settings, plugins and skills stay out, and nothing is changed globally.

**Conditions.** The MCP server key is `srv` in both, so tool names are identical.

| Condition | MCP server command |
|---|---|
| baseline | the server directly, through `python -m mcp_lint.safe_exec`, which gives it a minimal environment. Claude Code would otherwise pass its whole environment, API keys included |
| fixed | `mcp-lint proxy --descriptions eval/fixes/<server>.json -- <server>` with paging, descriptions and errors on |
| descriptions_only (ablation) | the proxy with `--no-paging --no-errors` |

**The proxy** (`src/mcp_lint/proxy.py`, `mcp-lint proxy`) connects to the upstream server over stdio and re-exposes its tools. Nothing upstream is forked or patched.

- *Paging:* text responses over ~2,000 tokens (estimated, 4 chars/token) are cut to a page. Every tool gains `offset`/`limit` parameters (in lines). Explicit limits are capped at 5 pages. The first line says `[showing lines 1-112 of 8000; pass offset=112 for more]`.
- *Descriptions:* tools that mcp-lint flags S1 (under 15 words) get a hand-written description from [`eval/fixes/`](fixes/): 1 tool in server-filesystem, 1 in markitdown, 11 in mcp-server-git.
- *Errors:* sets `isError` on "successful" results whose text starts like an error. **It never fired:** none of these three servers returns errors as successes (0 flagged across all runs). So "fixed" is effectively paging + descriptions, and an errors-only ablation would have measured nothing.

mcp-lint's own score for each server, before and behind the proxy, with probes from [`eval/lint-fixtures/`](lint-fixtures/) (estimated tokens; JSON reports in `eval/results/lint/`):

| Server | Baseline score | Behind proxy |
|---|---|---|
| markitdown-mcp 0.0.1a7 | 0 F (one ~142k-token response) | 99 A |
| server-filesystem 2.1.0 | 12 F | 96 A |
| mcp-server-git 2026.10.28 | 87 B | 94 A |

So if the score predicts anything, markitdown should gain most and git least.

## Tasks

`mcp-lint eval --setup` builds, from a fixed seed, a sandbox in the temp folder:

- `log.txt`: 8,000 log lines with random request IDs, ~142k tokens.
- `inventory.csv`: 3,000 rows with random SKUs.
- `report.html`: 400 sections with random titles.
- `sub/`: 300 empty files.
- A scratch git repo: 900 commits made with `git fast-import`, with fixed authors and timestamps so the SHAs are reproducible. Each message carries a unique ticket number, and each commit changes `counter.txt` and adds a note to `notes.md`.

Content is random rather than "line number N", so answers can't be guessed from a pattern. That's why this sandbox replaces the survey's `survey/sandbox`, whose `big.txt` is guessable.

There are 45 tasks, 15 per server, in [`eval/tasks/`](tasks/). Every answer is computed in Python from the generated data. Examples:

- "In log.txt, what is the request ID on line 7,082?"
- "How many files in sub/ start with file_25?"
- "Which commit's message mentions TCK-3993? Give its author."
- "How many commits on main were authored by Emil Novak?"

The agent must end with `ANSWER: ...`, which is checked exactly:

- Text answers are matched case- and quote-insensitively.
- Integers are parsed, so `8,000` counts as `8000`.
- Commit SHAs must be at least 7 hex characters and a prefix of the real SHA.

Each server's tasks were split by a seeded shuffle into 10 dev and 5 held-out. Dev tasks were used only for the pilot. **All numbers below are held-out**, and no task was changed after the pilot.

## Results (held-out, 3 runs per task per condition)

Tokens, turns and cost are **Claude Code-reported** (`usage`, `num_turns`, `total_cost_usd` from the final result event). Tokens per task = input + cache creation + cache read + output. On a subscription the cost figure is Claude Code's API-price estimate, not money spent.

"SD over reps" is the spread of the success rate across the 3 repetitions. Baseline shows ± 0 because each baseline task either always or never succeeded. `descriptions_only` is the ablation, with 1 run per task.

| Server | Condition | Runs | Success (± SD over reps) | Tokens / task, mean ± SD (median) | Turns, mean ± SD | Cost / task | Errors |
|---|---|---|---|---|---|---|---|
| filesystem | baseline | 15 | 80% ± 0 | 52,498 ± 35,121 (35,100) | 4.1 ± 2.5 | $0.004 | 0 |
| filesystem | fixed | 15 | 100% ± 0 | 33,993 ± 18,696 (26,500) | 2.5 ± 0.7 | $0.002 | 0 |
| filesystem | descriptions_only | 5 | 80% | 55,208 ± 36,139 (34,958) | 4.4 ± 2.2 | $0.005 | 0 |
| markitdown | baseline | 15 | 0% ± 0 | 28,988 ± 18,539 (23,030) | 3.5 ± 1.9 | $0.002 | 0 |
| markitdown | fixed | 15 | 100% ± 0 | 218,317 ± 396,993 (35,246) | 8.9 ± 9.7 | $0.015 | 0 |
| markitdown | descriptions_only | 5 | 0% | 22,083 ± 11,919 (14,962) | 2.8 ± 1.3 | $0.002 | 0 |
| git | baseline | 15 | 80% ± 0 | 290,801 ± 161,623 (285,237) | 12.3 ± 5.4 | $0.025 | 0 |
| git | fixed | 15 | 93% ± 12 | 398,444 ± 340,954 (242,151) | 14.1 ± 5.7 | $0.023 | 0 |
| git | descriptions_only | 5 | 100% | 408,699 ± 205,722 (294,453) | 14.8 ± 11.1 | $0.019 | 0 |
| **all** | baseline | 45 | 53% ± 0 | 124,096 ± 152,048 (45,835) | 6.6 ± 5.4 | $0.010 | 0 |
| **all** | fixed | 45 | 98% ± 4 | 216,918 ± 331,494 (77,743) | 8.5 ± 7.9 | $0.014 | 0 |
| **all** | descriptions_only | 15 | 60% | 161,997 ± 212,852 (42,369) | 7.3 ± 8.2 | $0.008 | 0 |

Paired per-task differences vs baseline (mean of per-task means; 95% bootstrap CI over tasks):

| Server | Condition | Tasks | Success Δ (pts) | Tokens Δ | Turns Δ | Cost Δ |
|---|---|---|---|---|---|---|
| filesystem | fixed | 5 | +20 [+0, +60] | -18,505 [-41,810, +1,252] | -1.6 [-3.5, +0.0] | -0.002 [-0.004, -0.000] |
| filesystem | descriptions_only | 5 | +0 [+0, +0] | +2,710 [-8,362, +13,439] | +0.3 [-0.6, +1.0] | +0.001 [+0.000, +0.002] |
| markitdown | fixed | 5 | +100 [+100, +100] | +189,329 [-2,326, +514,375] | +5.4 [-1.0, +13.1] | +0.014 [+0.001, +0.034] |
| markitdown | descriptions_only | 5 | +0 [+0, +0] | -6,905 [-25,614, +7,650] | -0.7 [-2.7, +0.8] | +0.000 [-0.000, +0.001] |
| git | fixed | 5 | +13 [-20, +60] | +107,643 [-13,756, +285,667] | +1.7 [-4.0, +6.3] | -0.002 [-0.004, -0.000] |
| git | descriptions_only | 5 | +20 [+0, +60] | +117,898 [-35,759, +250,234] | +2.5 [-4.8, +11.3] | -0.006 [-0.022, +0.004] |
| **all** | fixed | 15 | +44 [+18, +71] | +92,822 [-717, +221,849] | +1.8 [-1.4, +5.3] | +0.003 [-0.002, +0.011] |
| **all** | descriptions_only | 15 | +7 [+0, +20] | +37,901 [-11,907, +98,480] | +0.7 [-1.6, +3.8] | -0.002 [-0.007, +0.002] |

| Task | Kind | baseline ok | fixed ok | descriptions_only ok | baseline tokens | fixed tokens | descriptions_only tokens |
|---|---|---|---|---|---|---|---|
| filesystem-01 | log_line | 3/3 | 3/3 | 1/1 | 35,242 | 27,309 | 34,958 |
| filesystem-02 | log_line | 0/3 | 3/3 | 0/1 | 82,948 | 22,583 | 105,041 |
| filesystem-08 | sub_count | 3/3 | 3/3 | 1/1 | 23,232 | 26,601 | 29,750 |
| filesystem-10 | sub_count | 3/3 | 3/3 | 1/1 | 23,014 | 26,740 | 24,213 |
| filesystem-15 | html_section | 3/3 | 3/3 | 1/1 | 98,055 | 66,729 | 82,079 |
| git-06 | commit_author | 3/3 | 2/3 | 1/1 | 381,560 | 487,990 | 627,538 |
| git-09 | counter_at | 3/3 | 3/3 | 1/1 | 404,751 | 441,563 | 256,070 |
| git-12 | note_added | 3/3 | 3/3 | 1/1 | 206,637 | 175,251 | 227,906 |
| git-14 | first_commit | 3/3 | 3/3 | 1/1 | 111,823 | 90,412 | 294,453 |
| git-15 | author_count | 0/3 | 3/3 | 1/1 | 349,233 | 797,005 | 637,526 |
| markitdown-02 | log_line | 0/3 | 3/3 | 0/1 | 56,839 | 26,002 | 14,962 |
| markitdown-06 | csv_qty | 0/3 | 3/3 | 0/1 | 23,702 | 854,032 | 42,369 |
| markitdown-11 | html_section | 0/3 | 3/3 | 0/1 | 26,103 | 34,567 | 23,367 |
| markitdown-12 | html_section | 0/3 | 3/3 | 0/1 | 14,536 | 41,502 | 14,831 |
| markitdown-15 | html_count | 0/3 | 3/3 | 0/1 | 23,762 | 135,483 | 14,886 |

### What happened

**Baseline failures were Claude Code's output cap, almost every time.** A capped result makes Claude Code reply `Error: result (132,275 characters) exceeds maximum allowed tokens. Output has been saved to <file>`. With no file tools, the agent can't read that file. Counts of baseline runs with at least one capped result, and of baseline failures:

| Server | Runs with a capped result | Failures | What the agent did |
|---|---|---|---|
| markitdown | 15/15 | 15/15 | `convert_to_markdown` has no way to ask for less, so it said "Unable to determine" |
| server-filesystem | 9/15 | 3/15 | `head`/`tail` can reach lines near either end, but not line 7,082 of 8,000 without exceeding the cap (filesystem-02, 0/3) |
| mcp-server-git | 14/15 | 3/15 | Recovered by choosing smaller `max_count` windows or date ranges |

The agent was honest about failing: 18 of the 21 baseline failures said they couldn't find the answer. The other 3, all on git-15, were a **confident wrong answer**: "how many commits by Emil Novak". The agent tallied 141 by hand over monthly `git_log` windows; the right answer is 146. Behind the proxy, the same task was right 3/3.

**Why fixed costs more tokens.** Paging turns a capped failure into a long success:

- markitdown-06 asks for one SKU's quantity in a 3,000-row CSV. With no search tool, the agent read the table page by page: 20 pages in each of the 3 runs, all correct. The reported tokens were 188k, 1.19M and 1.19M for the same 20 calls, So the same agent behaviour can be reported at very different totals. The output doesn't say why; one guess is how much of the context was re-sent rather than cached. Token means here are noisy.
- On git, the agent scanned `git_log` in 2,000-token pages instead of picking its own ~22k-character chunks (`max_count: 150`). That meant more turns, and every turn re-reads the growing context, so cache-read tokens grow much faster than the number of calls. Pages also split commit records in the middle.

The proxy cut 11.1M tokens of upstream output down to 0.63M actually returned. The agent still paid for re-reading its context on every turn.

**Like for like.** The 7 tasks that both conditions solved in every run:

| | Tokens / task (mean, median) | Turns | Cost / task |
|---|---|---|---|
| baseline | 128,965 (92,960) | 6.7 | $0.0074 |
| fixed | 122,087 (77,743) | 6.4 | $0.0066 |

That's 5% fewer tokens with the fix, within noise. server-filesystem saved more (44.9k → 36.8k, 3.3 → 2.6 turns). Git was flat (241k → 236k).

**The one fixed failure** was git-06, run 3. The agent asked for `max_count: 500` of 900 commits, paged to the end of those 500, and concluded the ticket didn't exist. The proxy's "end of response" note was accurate for the response, but the agent read it as the end of the history.

**Does mcp-lint's ranking predict the gain?** Yes, in order. markitdown (0/100) gained +100 points, server-filesystem (12/100) +20, mcp-server-git (87/100) +13, and only markitdown's gain is clearly outside noise with 5 tasks per server. Three servers is too few to call this a correlation.

### Ablation: descriptions only

With paging off and only the S1 descriptions replaced (1 run per held-out task, 15 runs), success was 60% vs baseline 53%: +7 points [+0, +20].

- server-filesystem and markitdown didn't change at all, as expected. A better description can't get a 142k-token response past a 25k cap.
- The only change was git-15, the author count: right in its one descriptions-only run, wrong in all 3 baseline runs. The new `git_log` description says what `max_count` and the timestamp filters do, which may have helped. With one run this is an anecdote.

So nearly all of the "fixed" gain is the paging fix, and the descriptions fix shows no measurable effect at this sample size. The errors fix never triggered (see Setup). It wasn't ablated, and these servers can't measure it.

## Runs and reported cost

The cap was 150 `claude -p` runs. **About 141 were launched**: 135 are recorded, and up to 6 more were killed in flight (see below). Every run used Haiku, and none hit a usage or rate limit. Claude Code-reported cost across all 135 recorded runs: **$1.44** (19.5M tokens, mostly cache reads).

| Part | Runs | Notes |
|---|---|---|
| Pilot (dev tasks) | 6 | 4 with a setup bug (below), 2 after the fix. Kept in `results/pilot-roots-bug.jsonl` and `results/pilot.jsonl` |
| Main: baseline + fixed, 15 held-out × 3 | 90 valid | |
| Wasted during the main run | 24 recorded + up to 6 unrecorded | Two runners ran at once on the same results file (19 duplicates). 5 more ran while a live edit had left a syntax error in the code the proxy imports. All are in `results/excluded.jsonl` with the reason. The runner now takes a lock file and re-runs proxy start failures |
| Ablation: descriptions_only, 15 × 1 | 15 | |

What was cut to fit:

- Dev tasks were never run beyond the pilot, so results cover 15 of the 45 tasks.
- The ablations are one run per task, and paging_only and errors_only weren't run. paging_only would be near-identical to fixed, since errors never fired, and errors_only can't fire on these servers.
- No second model.

**Setup bug found by the pilot.** In the first pilot, baseline server-filesystem said "Access denied". Claude Code sends MCP *roots* (its cwd), and server-filesystem replaces its allowed directories with them, so each run's scratch cwd locked the agent out of the sandbox. The proxy's upstream client sends no roots, so only baseline was affected. Now every run's cwd is the eval base folder, and server-filesystem is started on that same folder, so both conditions have identical access.

## Limitations

- **Small sample.** 5 held-out tasks per server, 3 runs each. The per-server CIs are wide, and only the markitdown result and the all-servers success difference are clearly outside noise.
- **Task design favours paging.** The tasks were written to need specific data out of large files, the situation the post warns about and mcp-lint flags. They say nothing about servers whose responses are small. Tasks were generated once and not tuned, but they were chosen knowing what mcp-lint checks.
- **No search tools.** With Bash or Grep the baseline agent could have read the saved overflow file. These results are for an agent limited to the MCP server under test.
- **Claude Code's cap is part of the result.** Claude Code caps MCP tool output at about 25,000 tokens and saves the rest to a file, so baseline runs face real truncation. Another client, with a bigger cap or none, would give different baseline numbers. Some of the "fix" is avoiding this specific client's cap.
- **One page size.** A 2,000-token page suits lookups but makes scans expensive. A larger page, or a search/grep parameter (the post's other advice), would probably cut the token cost. This wasn't tested.
- **One model.** All runs are Haiku. A stronger model might recover from capped output differently.
- **Descriptions are confounded with paging in "fixed".** The ablation separates them for one run per task only.
- **Usage numbers are Claude Code's own report.** Cache-read tokens dominate, and the cost is an API-price estimate, not subscription usage.
- **Side effect on disk.** Claude Code saved capped tool outputs under `~/.claude/projects/C--Users-alex-AppData-Local-Temp-mcp-lint-eval*` (a few MB). That's Claude Code's own data folder, not written by an MCP tool. It's safe to delete.

## Reproduce

```bash
mcp-lint eval --setup                                       # sandbox + repo in %TEMP%/mcp-lint-eval, tasks in eval/tasks/
mcp-lint eval --run --split test --runs 3 --workers 3      # baseline + fixed; resumable, one runner per results file
mcp-lint eval --run --split test --runs 1 --conditions descriptions_only
mcp-lint eval --report --out eval/results/tables.md
```

The raw results are in [`results/`](results/):

- `results.jsonl`: one line per run: task, condition, model, success, answer, turns, token counts, cost, duration, tool calls with result sizes, and proxy stats.
- `excluded.jsonl`: runs dropped and why.
- `pilot*.jsonl`: the pilot runs.
