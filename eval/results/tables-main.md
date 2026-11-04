| Server | Condition | Runs | Success (± SD over reps) | Tokens / task, mean ± SD (median) | Turns, mean ± SD | Cost / task | Errors |
|---|---|---|---|---|---|---|---|
| filesystem | baseline | 15 | 80% ± 0 | 52,498 ± 35,121 (35,100) | 4.1 ± 2.5 | $0.004 | 0 |
| filesystem | fixed | 15 | 100% ± 0 | 33,993 ± 18,696 (26,500) | 2.5 ± 0.7 | $0.002 | 0 |
| markitdown | baseline | 15 | 0% ± 0 | 28,988 ± 18,539 (23,030) | 3.5 ± 1.9 | $0.002 | 0 |
| markitdown | fixed | 15 | 100% ± 0 | 218,317 ± 396,993 (35,246) | 8.9 ± 9.7 | $0.015 | 0 |
| git | baseline | 15 | 80% ± 0 | 290,801 ± 161,623 (285,237) | 12.3 ± 5.4 | $0.025 | 0 |
| git | fixed | 15 | 93% ± 12 | 398,444 ± 340,954 (242,151) | 14.1 ± 5.7 | $0.023 | 0 |
| **all** | baseline | 45 | 53% ± 0 | 124,096 ± 152,048 (45,835) | 6.6 ± 5.4 | $0.010 | 0 |
| **all** | fixed | 45 | 98% ± 4 | 216,918 ± 331,494 (77,743) | 8.5 ± 7.9 | $0.014 | 0 |

Paired per-task differences vs baseline (mean of per-task means; 95% bootstrap CI over tasks):

| Server | Condition | Tasks | Success Δ (pts) | Tokens Δ | Turns Δ | Cost Δ |
|---|---|---|---|---|---|---|
| filesystem | fixed | 5 | +20 [+0, +60] | -18,505 [-41,810, +1,252] | -1.6 [-3.5, +0.0] | -0.002 [-0.004, -0.000] |
| markitdown | fixed | 5 | +100 [+100, +100] | +189,329 [-2,326, +514,375] | +5.4 [-1.0, +13.1] | +0.014 [+0.001, +0.034] |
| git | fixed | 5 | +13 [-20, +60] | +107,643 [-13,756, +285,667] | +1.7 [-4.0, +6.3] | -0.002 [-0.004, -0.000] |
| **all** | fixed | 15 | +44 [+18, +71] | +92,822 [-717, +221,849] | +1.8 [-1.4, +5.3] | +0.003 [-0.002, +0.011] |

| Task | Kind | baseline ok | fixed ok | baseline tokens | fixed tokens |
|---|---|---|---|---|---|
| filesystem-01 | log_line | 3/3 | 3/3 | 35,242 | 27,309 |
| filesystem-02 | log_line | 0/3 | 3/3 | 82,948 | 22,583 |
| filesystem-08 | sub_count | 3/3 | 3/3 | 23,232 | 26,601 |
| filesystem-10 | sub_count | 3/3 | 3/3 | 23,014 | 26,740 |
| filesystem-15 | html_section | 3/3 | 3/3 | 98,055 | 66,729 |
| git-06 | commit_author | 3/3 | 2/3 | 381,560 | 487,990 |
| git-09 | counter_at | 3/3 | 3/3 | 404,751 | 441,563 |
| git-12 | note_added | 3/3 | 3/3 | 206,637 | 175,251 |
| git-14 | first_commit | 3/3 | 3/3 | 111,823 | 90,412 |
| git-15 | author_count | 0/3 | 3/3 | 349,233 | 797,005 |
| markitdown-02 | log_line | 0/3 | 3/3 | 56,839 | 26,002 |
| markitdown-06 | csv_qty | 0/3 | 3/3 | 23,702 | 854,032 |
| markitdown-11 | html_section | 0/3 | 3/3 | 26,103 | 34,567 |
| markitdown-12 | html_section | 0/3 | 3/3 | 14,536 | 41,502 |
| markitdown-15 | html_count | 0/3 | 3/3 | 23,762 | 135,483 |
