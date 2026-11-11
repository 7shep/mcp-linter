# Holdout score: v1 vs draft v2 tagger

Blind labels were committed before either tagger ran on these servers. Tool counts: atlassian 96, discord 22, google-calendar 13, ms-365 375, paypal 28, square 3.

## Pooled per-tool recall and precision

| Tagger/profile | Leg | Recall | Precision | TP | FP | FN | Macro recall over servers |
|---|---|---|---|---|---|---|---|
| v1/strict | P | 18% (48/263) | 100% (48/48) | 48 | 0 | 215 | 0.0664 |
| v1/strict | U | 34% (36/106) | 78% (36/46) | 36 | 10 | 70 | 0.2877 |
| v1/strict | E | 48% (39/82) | 72% (39/54) | 39 | 15 | 43 | 0.3754 |
| v1/inclusive | P | 27% (71/263) | 93% (71/76) | 71 | 5 | 192 | 0.1156 |
| v1/inclusive | U | 75% (79/106) | 39% (79/203) | 79 | 124 | 27 | 0.4344 |
| v1/inclusive | E | 71% (58/82) | 28% (58/207) | 58 | 149 | 24 | 0.4507 |
| v2/strict | P | 19% (50/263) | 100% (50/50) | 50 | 0 | 213 | 0.0778 |
| v2/strict | U | 51% (54/106) | 71% (54/76) | 54 | 22 | 52 | 0.4489 |
| v2/strict | E | 48% (39/82) | 72% (39/54) | 39 | 15 | 43 | 0.3754 |
| v2/inclusive | P | 37% (98/263) | 94% (98/104) | 98 | 6 | 165 | 0.202 |
| v2/inclusive | U | 77% (82/106) | 39% (82/210) | 82 | 128 | 24 | 0.5236 |
| v2/inclusive | E | 71% (58/82) | 28% (58/207) | 58 | 149 | 24 | 0.4507 |

## Server trifecta flag

| Server | Labelled trifecta | v1/strict | v1/inclusive | v2/strict | v2/inclusive |
|---|---|---|---|---|---|
| atlassian | yes | yes | yes | yes | yes |
| discord | yes | no | no | no | yes |
| google-calendar | yes | no | no | no | no |
| ms-365 | yes | yes | yes | yes | yes |
| paypal | yes | no | no | yes | yes |
| square | yes | no | no | no | no |
