# Tagging survey: 18 saved MCP tool lists

Rules were tuned while reading the dev lists and frozen before the holdout lists were tagged.

## Per server

| Server | Split | Tools | Tagged strict | Tagged inclusive | P/U/E strict | P/U/E inclusive | Trifecta strict | Trifecta inclusive |
|---|---|---|---|---|---|---|---|---|
| aws-docs | holdout | 5 | 3 | 4 | 1/3/0 | 1/4/4 | no | yes |
| chrome-devtools | holdout | 32 | 5 | 8 | 0/3/2 | 2/6/4 | no | yes |
| context7 | holdout | 2 | 0 | 2 | 0/0/0 | 0/2/0 | no | no |
| desktop-commander | dev | 25 | 3 | 10 | 2/1/1 | 9/2/3 | yes | yes |
| duckduckgo | holdout | 3 | 1 | 2 | 0/1/0 | 0/2/1 | no | no |
| everything | dev | 16 | 2 | 3 | 1/1/0 | 1/2/1 | no | yes |
| exa | holdout | 2 | 2 | 2 | 0/2/0 | 0/2/1 | no | no |
| fetch | dev | 1 | 1 | 1 | 0/1/0 | 0/1/1 | no | no |
| filesystem | dev | 14 | 4 | 9 | 4/0/0 | 9/0/0 | no | no |
| firecrawl | holdout | 26 | 6 | 17 | 0/4/4 | 4/13/11 | no | yes |
| git | dev | 12 | 5 | 7 | 5/0/0 | 7/0/0 | no | no |
| github | dev | 26 | 17 | 21 | 2/9/7 | 11/13/7 | yes | yes |
| markitdown | holdout | 1 | 1 | 1 | 0/1/0 | 0/1/1 | no | no |
| memory | dev | 9 | 1 | 3 | 1/0/0 | 3/0/0 | no | no |
| notion | dev | 24 | 3 | 14 | 1/1/1 | 11/2/1 | yes | yes |
| playwright | holdout | 25 | 6 | 25 | 0/4/2 | 3/25/4 | no | yes |
| tavily | holdout | 5 | 3 | 4 | 0/3/0 | 0/4/3 | no | no |
| time | dev | 2 | 0 | 0 | 0/0/0 | 0/0/0 | no | no |

P/U/E = PRIVATE_READ / UNTRUSTED_READ / EXTERNAL_WRITE tool counts.

## Totals

| Split | Profile | Tools | Tools tagged | PRIVATE_READ | UNTRUSTED_READ | EXTERNAL_WRITE | Servers with trifecta |
|---|---|---|---|---|---|---|---|
| dev | strict | 129 | 36 | 16 | 13 | 9 | 3 |
| dev | inclusive | 129 | 68 | 51 | 20 | 13 | 4 |
| holdout | strict | 101 | 27 | 1 | 21 | 8 | 0 |
| holdout | inclusive | 101 | 65 | 10 | 59 | 29 | 4 |
| all | strict | 230 | 63 | 17 | 34 | 17 | 3 |
| all | inclusive | 230 | 133 | 61 | 79 | 42 | 8 |

## Rule hits

| Rule | Tag | Confidence | Tools |
|---|---|---|---|
| E-EXEC | EXTERNAL_WRITE | high | 8 |
| E-FORGE-WRITE | EXTERNAL_WRITE | high | 2 |
| E-OPEN-WRITE | EXTERNAL_WRITE | medium | 10 |
| E-RECIPIENT | EXTERNAL_WRITE | high | 1 |
| E-SEND | EXTERNAL_WRITE | high | 1 |
| E-SHARED-OBJECT | EXTERNAL_WRITE | high | 6 |
| E-URL-EGRESS | EXTERNAL_WRITE | medium | 23 |
| P-CALL-HISTORY | PRIVATE_READ | medium | 1 |
| P-EXEC | PRIVATE_READ | medium | 8 |
| P-FILE-META | PRIVATE_READ | medium | 9 |
| P-FILE-READ | PRIVATE_READ | high | 6 |
| P-FORGE-CONTENT | PRIVATE_READ | high | 2 |
| P-FORGE-READ | PRIVATE_READ | medium | 8 |
| P-NOUN | PRIVATE_READ | high | 4 |
| P-NOUN-AMBIGUOUS | PRIVATE_READ | medium | 15 |
| P-PROCESS-OUTPUT | PRIVATE_READ | medium | 1 |
| P-VCS-META | PRIVATE_READ | medium | 2 |
| P-VCS-READ | PRIVATE_READ | high | 5 |
| U-BROWSER | UNTRUSTED_READ | high | 4 |
| U-BROWSER | UNTRUSTED_READ | medium | 25 |
| U-EXEC | UNTRUSTED_READ | medium | 8 |
| U-FORGE-READ | UNTRUSTED_READ | medium | 2 |
| U-OPEN-READ | UNTRUSTED_READ | medium | 13 |
| U-SEARCH | UNTRUSTED_READ | medium | 7 |
| U-THIRD-PARTY | UNTRUSTED_READ | high | 13 |
| U-URL-READ | UNTRUSTED_READ | high | 17 |
| U-URL-READ | UNTRUSTED_READ | medium | 6 |
| U-WEB | UNTRUSTED_READ | high | 2 |

## False positives

| Profile | Split | Tag | Assigned | Apparent FP | Rate |
|---|---|---|---|---|---|
| strict | dev | (all) | 38 | 2 | 5.3% |
| strict | dev | PRIVATE_READ | 16 | 0 | 0.0% |
| strict | dev | UNTRUSTED_READ | 13 | 1 | 7.7% |
| strict | dev | EXTERNAL_WRITE | 9 | 1 | 11.1% |
| strict | holdout | (all) | 30 | 4 | 13.3% |
| strict | holdout | PRIVATE_READ | 1 | 1 | 100.0% |
| strict | holdout | UNTRUSTED_READ | 21 | 3 | 14.3% |
| strict | holdout | EXTERNAL_WRITE | 8 | 0 | 0.0% |
| strict | all | (all) | 68 | 6 | 8.8% |
| strict | all | PRIVATE_READ | 17 | 1 | 5.9% |
| strict | all | UNTRUSTED_READ | 34 | 4 | 11.8% |
| strict | all | EXTERNAL_WRITE | 17 | 1 | 5.9% |
| inclusive | dev | (all) | 84 | 6 | 7.1% |
| inclusive | dev | PRIVATE_READ | 51 | 1 | 2.0% |
| inclusive | dev | UNTRUSTED_READ | 20 | 3 | 15.0% |
| inclusive | dev | EXTERNAL_WRITE | 13 | 2 | 15.4% |
| inclusive | holdout | (all) | 98 | 18 | 18.4% |
| inclusive | holdout | PRIVATE_READ | 10 | 5 | 50.0% |
| inclusive | holdout | UNTRUSTED_READ | 59 | 7 | 11.9% |
| inclusive | holdout | EXTERNAL_WRITE | 29 | 6 | 20.7% |
| inclusive | all | (all) | 182 | 24 | 13.2% |
| inclusive | all | PRIVATE_READ | 61 | 6 | 9.8% |
| inclusive | all | UNTRUSTED_READ | 79 | 10 | 12.7% |
| inclusive | all | EXTERNAL_WRITE | 42 | 8 | 19.1% |

## False-positive entries

| Server | Tool | Tag | Split | In strict | Reason |
|---|---|---|---|---|---|
| everything | get-annotated-message | UNTRUSTED_READ | dev | yes | Demo tool returning fixed text. Tagged only for the noun 'message'. |
| everything | trigger-resource-update | UNTRUSTED_READ | dev | no | The URI names a resource for a notification. No content comes back. |
| everything | trigger-resource-update | EXTERNAL_WRITE | dev | no | The URI names a resource for a notification. Nothing is sent to that address. |
| github | search_users | PRIVATE_READ | dev | no | Returns public GitHub profiles. |
| notion | API-post-search | UNTRUSTED_READ | dev | no | Searches page titles inside the connected workspace, with no outside corpus. |
| notion | API-create-a-comment | EXTERNAL_WRITE | dev | yes | A comment is visible only to people with access to the page, so it leaves the boundary only on a publicly shared page. This one call decides Notion's whole trifecta. |
| aws-docs | read_documentation | UNTRUSTED_READ | holdout | yes | Description limits URLs to docs.aws.amazon.com, so the content is AWS-authored. |
| aws-docs | read_documentation | EXTERNAL_WRITE | holdout | no | Description limits URLs to docs.aws.amazon.com, so an attacker host cannot receive a request. |
| aws-docs | read_sections | UNTRUSTED_READ | holdout | yes | AWS documentation pages only, as for read_documentation. |
| aws-docs | read_sections | EXTERNAL_WRITE | holdout | no | AWS documentation pages only, as for read_documentation. |
| aws-docs | search_table | PRIVATE_READ | holdout | yes | 'table' here is a table in a public documentation page. |
| aws-docs | search_table | UNTRUSTED_READ | holdout | yes | Description limits URLs to docs.aws.amazon.com. |
| aws-docs | search_table | EXTERNAL_WRITE | holdout | no | Description limits URLs to docs.aws.amazon.com. |
| aws-docs | recommend | UNTRUSTED_READ | holdout | no | Takes an AWS documentation page URL and returns related AWS pages. |
| aws-docs | recommend | EXTERNAL_WRITE | holdout | no | Takes an AWS documentation page URL and returns related AWS pages. |
| firecrawl | firecrawl_scrape | PRIVATE_READ | holdout | no | The nested 'script' is a page action in Firecrawl's own browser, which has no access to the user's local data. |
| firecrawl | firecrawl_search | PRIVATE_READ | holdout | no | The nested 'script' is a page action in Firecrawl's own browser, which has no access to the user's local data. |
| firecrawl | firecrawl_crawl | PRIVATE_READ | holdout | no | The nested 'script' is a page action in Firecrawl's own browser, which has no access to the user's local data. |
| firecrawl | firecrawl_interact | PRIVATE_READ | holdout | no | The code runs in Firecrawl's own browser session, which has no access to the user's local data. |
| firecrawl | firecrawl_monitor_delete | EXTERNAL_WRITE | holdout | no | Takes only a monitor id. openWorldHint is true, but no chosen data can leave. |
| firecrawl | firecrawl_monitor_run | EXTERNAL_WRITE | holdout | no | Takes only a monitor id. openWorldHint is true, but no chosen data can leave. |
| playwright | browser_close | UNTRUSTED_READ | holdout | no | Closes the page. Tagged only for the 'browser' prefix. |
| playwright | browser_resize | UNTRUSTED_READ | holdout | no | Resizes the window. Tagged only for the 'browser' prefix. |
| playwright | browser_emulate_media | UNTRUSTED_READ | holdout | no | Sets CSS media features. Tagged only for the 'browser' prefix. |

## False-negative entries

| Server | Tool | Tag | Split | Reason |
|---|---|---|---|---|
| markitdown | convert_to_markdown | PRIVATE_READ | holdout | Accepts file: URIs, so it reads local files. The rules treat a URI parameter as web only. |
| firecrawl | firecrawl_parse | PRIVATE_READ | holdout | Reads a local file through 'filePath'. The camelCase name misses PATH_PARAMS. |
| tavily | tavily_research | UNTRUSTED_READ | holdout | Returns web research. Its 'input' parameter is not in QUERY_PARAMS. |
| chrome-devtools | get_network_request | UNTRUSTED_READ | holdout | Returns response bodies from visited sites. 'network' is not a browser noun. |
| chrome-devtools | fill_form | EXTERNAL_WRITE | holdout | Form fields are sent to whatever page is open. |
| playwright | browser_file_upload | EXTERNAL_WRITE | holdout | Sends a local file to the open page. The verb is third in the name, past the two-word verb window. |
| playwright | browser_fill_form | EXTERNAL_WRITE | holdout | Form fields are sent to whatever page is open. |

## Minimal sets before review

### strict

Smallest size: 1 server(s). 3 set(s) in total; first 3 shown.

- desktop-commander
- github
- notion

### inclusive

Smallest size: 1 server(s). 8 set(s) in total; first 8 shown.

- aws-docs
- chrome-devtools
- desktop-commander
- everything
- firecrawl
- github
- notion
- playwright

## Minimal sets after review

Servers with a trifecta after review (strict): desktop-commander, github

### strict

Smallest size: 1 server(s). 2 set(s) in total; first 2 shown.

- desktop-commander
- github

Leaving out servers that hold all three alone:

### strict

Smallest size: 2 server(s). 15 set(s) in total; first 15 shown.

- chrome-devtools + everything
- chrome-devtools + filesystem
- chrome-devtools + git
- chrome-devtools + memory
- chrome-devtools + notion
- everything + firecrawl
- everything + playwright
- filesystem + firecrawl
- filesystem + playwright
- firecrawl + git
- firecrawl + memory
- firecrawl + notion
- git + playwright
- memory + playwright
- notion + playwright

Servers with a trifecta after review (inclusive): chrome-devtools, desktop-commander, github, playwright

### inclusive

Smallest size: 1 server(s). 4 set(s) in total; first 4 shown.

- chrome-devtools
- desktop-commander
- github
- playwright

Leaving out servers that hold all three alone:

### inclusive

Smallest size: 2 server(s). 30 set(s) in total; first 25 shown.

- duckduckgo + everything
- duckduckgo + filesystem
- duckduckgo + git
- duckduckgo + memory
- duckduckgo + notion
- everything + exa
- everything + fetch
- everything + firecrawl
- everything + markitdown
- everything + tavily
- exa + filesystem
- exa + git
- exa + memory
- exa + notion
- fetch + filesystem
- fetch + git
- fetch + memory
- fetch + notion
- filesystem + firecrawl
- filesystem + markitdown
- filesystem + tavily
- firecrawl + git
- firecrawl + memory
- firecrawl + notion
- git + markitdown

