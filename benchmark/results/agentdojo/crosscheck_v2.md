# AgentDojo cross-check of the frozen tagger

The tagger in `benchmark/tagging.py` is frozen. It reads tool names, input schema structure and annotations only, never descriptions. Inputs are a v1.2 export of tool names, task ids and hand labels; no task text is included.

Exfil cases are checked for the three legs: a source tool tagged UNTRUSTED_READ, a private source tagged PRIVATE_READ (or none, when the data is already in context), and a sink tagged EXTERNAL_WRITE. Action and text cases are counted but do not count toward exfil numbers.

Draft v2 tagger (`benchmark/tagging_v2.py`), tuned on AgentDojo, so these are dev-set numbers, not a holdout.

## Profile: strict

| Suite | Flagged | Exfil cases | Path covered | Missed source / private / sink |
|---|---|---|---|---|
| banking | yes | 80 | 60 | 1 / 0 / 0 |
| slack | yes | 42 | 0 | 0 / 1 / 0 |
| travel | yes | 60 | 60 | 0 / 0 / 0 |
| workspace | yes | 400 | 175 | 5 / 1 / 0 |
| Total | 4 of 4 | 582 | 295 | 6 / 2 / 0 |

| Suite | Exfil fail source_u | Exfil fail private_p | Exfil fail sink_e | Action cases | Action with sink_e | Text cases | Security cases |
|---|---|---|---|---|---|---|---|
| banking | 20 | 0 | 0 | 64 | 48 | 0 | 144 |
| slack | 0 | 42 | 0 | 63 | 21 | 0 | 105 |
| travel | 0 | 0 | 0 | 60 | 0 | 20 | 140 |
| workspace | 150 | 120 | 0 | 160 | 80 | 0 | 560 |
| Total | 170 | 162 | 0 | 347 | 149 | 20 | 949 |

### Missed tools

- banking, source (UNTRUSTED_READ): `read_file`
- banking, private (PRIVATE_READ): none
- banking, sink (EXTERNAL_WRITE): none
- slack, source (UNTRUSTED_READ): none
- slack, private (PRIVATE_READ): `read_channel_messages`
- slack, sink (EXTERNAL_WRITE): none
- travel, source (UNTRUSTED_READ): none
- travel, private (PRIVATE_READ): none
- travel, sink (EXTERNAL_WRITE): none
- workspace, source (UNTRUSTED_READ): `add_calendar_event_participants`, `delete_file`, `list_files`, `search_files`, `search_files_by_filename`
- workspace, private (PRIVATE_READ): `list_files`
- workspace, sink (EXTERNAL_WRITE): none

## Profile: inclusive

| Suite | Flagged | Exfil cases | Path covered | Missed source / private / sink |
|---|---|---|---|---|
| banking | yes | 80 | 60 | 1 / 0 / 0 |
| slack | yes | 42 | 42 | 0 / 0 / 0 |
| travel | yes | 60 | 60 | 0 / 0 / 0 |
| workspace | yes | 400 | 400 | 2 / 0 / 0 |
| Total | 4 of 4 | 582 | 562 | 3 / 0 / 0 |

| Suite | Exfil fail source_u | Exfil fail private_p | Exfil fail sink_e | Action cases | Action with sink_e | Text cases | Security cases |
|---|---|---|---|---|---|---|---|
| banking | 20 | 0 | 0 | 64 | 48 | 0 | 144 |
| slack | 0 | 0 | 0 | 63 | 42 | 0 | 105 |
| travel | 0 | 0 | 0 | 60 | 0 | 20 | 140 |
| workspace | 0 | 0 | 0 | 160 | 80 | 0 | 560 |
| Total | 20 | 0 | 0 | 347 | 170 | 20 | 949 |

### Missed tools

- banking, source (UNTRUSTED_READ): `read_file`
- banking, private (PRIVATE_READ): none
- banking, sink (EXTERNAL_WRITE): none
- slack, source (UNTRUSTED_READ): none
- slack, private (PRIVATE_READ): none
- slack, sink (EXTERNAL_WRITE): none
- travel, source (UNTRUSTED_READ): none
- travel, private (PRIVATE_READ): none
- travel, sink (EXTERNAL_WRITE): none
- workspace, source (UNTRUSTED_READ): `add_calendar_event_participants`, `delete_file`
- workspace, private (PRIVATE_READ): none
- workspace, sink (EXTERNAL_WRITE): none

