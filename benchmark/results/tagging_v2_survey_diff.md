# Draft v2 tagger against v1: survey diff

Draft v2 (`benchmark/tagging_v2.py`) is v1 plus new evidence, so no tag is lost. The rules were tuned on AgentDojo; these 18 survey lists are a check, not a holdout, and v1 was already tuned on them.

## Totals

Servers: 18. Tools: 230.

| Profile | Tools changed | Tags gained | Tags lost | Servers with trifecta (v1 -> v2) | Trifecta flag changed |
|---|---|---|---|---|---|
| strict | 0 | 0 | 0 | 3 -> 3 | none |
| inclusive | 1 | 1 | 0 | 8 -> 8 | none |

## Per server

| Server | Split | Tools | Tools changed strict | Tools changed inclusive | Trifecta strict (v1 -> v2) | Trifecta inclusive (v1 -> v2) |
|---|---|---|---|---|---|---|
| aws-docs | holdout | 5 | 0 | 0 | no -> no | yes -> yes |
| chrome-devtools | holdout | 32 | 0 | 0 | no -> no | yes -> yes |
| context7 | holdout | 2 | 0 | 0 | no -> no | no -> no |
| desktop-commander | dev | 25 | 0 | 0 | yes -> yes | yes -> yes |
| duckduckgo | holdout | 3 | 0 | 0 | no -> no | no -> no |
| everything | dev | 16 | 0 | 1 | no -> no | yes -> yes |
| exa | holdout | 2 | 0 | 0 | no -> no | no -> no |
| fetch | dev | 1 | 0 | 0 | no -> no | no -> no |
| filesystem | dev | 14 | 0 | 0 | no -> no | no -> no |
| firecrawl | holdout | 26 | 0 | 0 | no -> no | yes -> yes |
| git | dev | 12 | 0 | 0 | no -> no | no -> no |
| github | dev | 26 | 0 | 0 | yes -> yes | yes -> yes |
| markitdown | holdout | 1 | 0 | 0 | no -> no | no -> no |
| memory | dev | 9 | 0 | 0 | no -> no | no -> no |
| notion | dev | 24 | 0 | 0 | yes -> yes | yes -> yes |
| playwright | holdout | 25 | 0 | 0 | no -> no | yes -> yes |
| tavily | holdout | 5 | 0 | 0 | no -> no | no -> no |
| time | dev | 2 | 0 | 0 | no -> no | no -> no |

## Changed tools

| Server | Tool | Profile | v1 tags | v2 tags | New rules |
|---|---|---|---|---|---|
| everything | get-annotated-message | inclusive | UNTRUSTED_READ | PRIVATE_READ, UNTRUSTED_READ | P-MESSAGE |

