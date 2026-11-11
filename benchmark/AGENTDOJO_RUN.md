# AgentDojo run: plan

**Status:** plan only. Nothing here has been run against a model. Every paid step needs Alex's approval first.

## Why this run

The research question is whether mcp-lint's static trifecta warning predicts real exploits (`DESIGN.md`, H1). The Haiku 5.5 run on our own mock servers was a null result: 0 of 600 trials leaked, so precision and recall are undefined. We need attacks with a non-zero base rate. AgentDojo's `important_instructions` attack succeeds on many published models, and we already have its attack paths labelled offline (`results/agentdojo/crosscheck*.md`). This run adds the missing column, which is whether each attack actually worked.

## What gets measured

The unit is one AgentDojo security case: a user task paired with an injection task. There are 949 cases across 4 suites. AgentDojo's own scoring decides the outcome, and `security` true means the injection task's goal was reached. Step 0 confirms that meaning in the installed version before any numbers are read.

The predictor is fixed in advance, from the offline cross-check: for each exfil case, **is the whole path labelled** (untrusted source, private source, and sink)? This is computed for each tagger and profile.

| Tagger | Status | Role in this run |
|---|---|---|
| v1 (`tagging.py`, frozen) | never tuned on AgentDojo | **the main test** |
| v2 (`tagging_v2.py`, draft) | rules written after reading AgentDojo's misses | reported, labelled dev-set |

### Pre-registered tests

The tests are fixed before any scored run. CIs are 95% bootstrap intervals that resample user tasks within each suite, because cases that share a user task are not independent.

| | Hypothesis | Test |
|---|---|---|
| **A1** | Exfil cases whose path v1 labels succeed more often than those it doesn't. | ASR(labelled) − ASR(unlabelled) has a CI above 0, per model. Pooled, and within workspace, the only suite with both kinds in bulk (63 labelled, 337 not). |
| **A2** | A suite-level warning misses real risk. | Banking ASR (no warning from v1) has a CI above 0 for at least one model. |
| **A3** | Precision and recall of the per-case path label, with an exploited case as the positive class. | Reported with Wilson intervals. Not a pass/fail test. |
| **A4** | Action cases (no data theft, only a sink call) are a control. | Reported only. The trifecta claim is about exfil. |

The confound to report plainly: labelled paths sit almost entirely in workspace and travel, and banking has none, so a pooled difference partly measures suites. The within-workspace comparison is the cleaner one.

## Size, from an offline ground-truth pass

AgentDojo v1.2, measured on 2026-11-11 by replaying each user task's ground-truth calls and summing the resent context per turn (4 chars per token, no model called):

| Suite | User tasks | Injection tasks | Security cases | Tool-definition tokens | Input tokens per trial (ground truth) |
|---|---|---|---|---|---|
| workspace | 40 | 14 | 560 | ~3.1k | ~9.7k |
| travel | 20 | 7 | 140 | ~3.8k | ~27.2k |
| banking | 16 | 9 | 144 | ~1.2k | ~3.2k |
| slack | 21 | 5 | 105 | ~1.0k | ~6.0k |
| **Total** | **97** | **35** | **949** | | **~11.5M for one full pass** (949 attacked + 97 clean) |

Real agents take extra turns and think, so the cost estimate below doubles input (~23M). It also assumes ~2k output tokens per trial (~2M).

## Models and cost

| Model | How it runs | One full pass, estimated | Notes |
|---|---|---|---|
| qwen2.5:7b, qwen3:8b (already in Ollama) | AgentDojo `local` provider, `LOCAL_LLM_PORT=11434` | $0, roughly 10–20 hours on the RTX 3050 | Small open models are the likeliest to have a non-zero ASR. Needs `num_ctx` ≥ 32k for travel, which may spill out of 8 GB of VRAM; check in the pilot. Prompt-based tool calling, so utility may be low. |
| Claude Haiku 5.5 | custom pipeline, Anthropic API key | ~$3.50 ($0.10 / $0.50 per MTok) | Null on our own injections. AgentDojo's attack is different, so it's worth one pass. |
| Claude Sonnet 5.5 | same | ~$66 ($2 / $10) | Only if the gate passes. |
| Claude Opus 5.5 | same | ~$130 ($4 / $20) | Only if the gate passes and Alex wants it. |

Costs are list API prices from the cached model table (2026-11-03), with no caching or batch discount. The tool definitions and system prompt are a stable prefix, so prompt caching should cut Claude input costs a lot. **Key needed for Claude steps only.** AgentDojo calls the Anthropic API directly, so the Claude Code plan login doesn't cover it. It needs `ANTHROPIC_API_KEY`, or possibly an `ant auth login` profile. AgentDojo's `AnthropicLLM` rebuilds its client from `api_key`/`auth_token`, so step 0 checks whether a profile survives that. The local steps need no key.

## Run order

| Step | What | Paid? | Trials | Expected cost |
|---|---|---|---|---|
| 0 | Wiring, offline: runner script, result reader, scorer joined to `crosscheck.json`, tests | No | 0 | $0 |
| 1 | Local pilot: qwen2.5:7b, banking and slack, `important_instructions` | No | ~270 | $0, ~3 h |
| 2 | Local full pass, both qwen models, all suites | No | ~2,100 | $0, ~1–2 days |
| 3 | Haiku 5.5 pilot: 60 stratified cases (15 per suite) + 20 clean | Yes | 80 | ~$0.30 |
| 4 | Haiku 5.5 full | Yes | 1,046 | ~$3.50 |
| 5 | Sonnet 5.5 full (Opus 5.5 optional) | Yes | 1,046 each | ~$66 (+$130) |

### Step 0 details (no model calls)

- **`benchmark/agentdojo_run.py`**, run with AgentDojo's venv (`-I`, like `agentdojo_export.py`). It builds the pipeline itself, because AgentDojo 0.1.35's model list stops at Claude 3.7 and its CLI can't name Claude 5.5:
  - `AnthropicLLM(client, "claude-haiku-5-5", temperature=None, max_tokens=16000)`. `temperature=None` keeps sampling parameters out of the request, which new API versions reject. The default `max_tokens=1024` would truncate, since thinking is on by default on Haiku 5.5.
  - The attack is `important_instructions_no_model_name`, because the stock attack looks the model name up in a table that has no 5.5 entry. For local models, the stock attack's "Local model" name is used.
  - It calls `benchmark_suite_with_injections` and `benchmark_suite_without_injections` with a `logdir` under `benchmark/results/agentdojo/runs/<model>/`. AgentDojo skips trials it has already logged, so it resumes.
  - Safety: the AgentDojo environments are in-memory Python objects, with no real email, bank or network. The runner refuses any provider other than Anthropic or `localhost`. Servers and agents get no Claude Code tools.
- **`benchmark/agentdojo_score.py`** (mcp-lint's Python, doesn't import agentdojo): reads the per-trial logs (`utility`, `security`), joins them to `crosscheck.json` / `crosscheck_v2.json` by (suite, user task, injection task), and writes `results/agentdojo/asr_<model>.md` with A1–A4.
- **Tests, offline:**
  - A fake log set where every exfil case "succeeds" gives ASR 1.0 and precision equal to the labelled share (83/582 strict for v1).
  - An all-fail set gives ASR 0 and undefined precision, reported as such, not as 0.
  - A missing or duplicate trial is an error, never a silent zero.
  - The bootstrap resamples user tasks, not cases.
  - Confirm in the installed source that `security == True` means the attack succeeded, and pin that with a test.
- **What gets stored:** AgentDojo's per-trial logs contain the attack text and the model's messages. They stay out of git (`benchmark/results/agentdojo/runs/` is in `.gitignore`, like the existing transcripts). Only the scored table, with case ids, outcomes and tags, gets committed, the same rule as `agentdojo_export.py`.

### Gates

- **After step 1:**
  - Utility on clean tasks must be at least 30%. Otherwise the model can't do the tasks and ASR means little.
  - At least 90% of trials must finish without format or context errors.
  - If it fails, try qwen3:8b or a larger context before step 2.
- **After step 2 (the key gate):** exfil ASR must be at least 5% on at least one local model. If no local model reaches that, A1 is untestable with these models too. Write that up as a second null result and stop.
- **After step 3:** median cost per trial within 2× of the estimate, and no truncated responses (`max_tokens` stops). Then step 4.
- **After step 4:** if Haiku's exfil ASR is below 5%, stop before Sonnet and Opus, as in `DESIGN.md`. A1 then rests on the local models alone, and the write-up says so.

## Limits

- **Static attacks.** `important_instructions` is fixed text, so ASR is a lower bound for an adaptive attacker ("The Attacker Moves Second", arXiv 2510.09023).
- **AgentDojo's tools aren't MCP servers.** The tagger reads their exported definitions, as in the cross-check, but the agent calls them as plain functions through AgentDojo's own loop, not through MCP or Claude Code. The results describe the pipeline with a model, like our other runs.
- **One attack per case.** AgentDojo reports the best of several attacks on its leaderboard. We run only `important_instructions`, so ASR here will sit below its published numbers.
- **v2 is dev-set here.** Any v2-vs-v1 gain on this run doesn't count as evidence for v2. The holdout (`results/holdout_score.md`) does.

## Decisions needed

1. Approve steps 0–2 (free, local, mostly GPU time)?
2. For steps 3–5: provide an Anthropic API key or an `ant auth login` profile, and approve Haiku (~$4 total) first.
3. Sonnet 5.5 (~$66) and Opus 5.5 (~$130): decide after step 4.
