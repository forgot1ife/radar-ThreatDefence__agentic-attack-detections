# cyber-harness Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **cyber-harness** ([chainreactors/cyber-harness](https://github.com/chainreactors/cyber-harness), formerly AIScan, reviewed at `02ac8ecf`, November 25, 2026, two commits after `v1.0.0-rc10`), a Go agent harness from the chainreactors group. Its `cyber-scan` agent drives the group's own scanners (gogo, spray, zombie, neutron), a headless browser, a curl clone and shell commands against the targets it is given, with no approval step; `cyber-audit` audits code and binaries; `cyber-harness` is a Web Hub that scan and audit nodes connect to. No vendor or CERT report of cyber-harness in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds cyber-harness testing you, running on a host, and its Hub exposed or in use.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, exposure searches |
| Docs | [What cyber-harness leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax, Suricata rules against test flows, YARA against synthetic samples built from its strings. Baseline every rule on your own data before alerting |

## What cyber-harness leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Basic-auth probe | `User-Agent: cyber` exactly (`aiscan` before September 2026) on a `GET` to a URL that just answered `401`; zombie then guesses Basic-auth passwords there | `tools/scan/http_auth.go:49` |
| fetch tool | `User-Agent: Mozilla/5.0 (compatible; cyber/1.0; +https://github.com/chainreactors/cyber-harness)` | `tools/search/fetch.go:28` |
| curl tool | Chrome 133 on Linux user agent with `Sec-Ch-Ua: "Chromium";v="133", "Google Chrome";v="133", "Not(A:Brand";v="24"`, sent by Go | `tools/curl/client.go:37-54` |
| MCP client | `clientInfo` `cyber-harness` / `mcp-ext`, request ids `cyber-mcp-<n>` | `tools/mcp/connection.go:133,146` |
| Host | Binaries `cyber-scan`, `cyber-harness`, `cyber-audit` (`aiscan`, `aiscan-full` up to `v1.0.0-rc9`); `--server-url http://<key>@<hub>:8080 --node-name`; `<temp>/cyber-agent.pid`; `.cyber/mitm/`, `.cyber/output/`, `~/.cyber/arsenal/bin/`; `cyber-harness.db` | `cmd/cyber-scan/pidlock.go:16`, `tools/proxy/config.go:47` |
| Web Hub | Plain HTTP on `127.0.0.1:8080` (`--addr 0.0.0.0:8080` in the docs), title `Cyber` (`AIScan` before), inline `localStorage.getItem('cyber-theme')`, no icon file, a fixed ConnectRPC CORS header set on every response, `401` `{"error":"invalid or missing access key"}`, cookie `cyber_session` | `web/frontend/index.html:7-11`, `pkg/web/handler.go:56-66` |
| Hub traffic | Node WebSocket `/api/aop/node/ws`, browser WebSocket `/api/aop/application/ws`, ConnectRPC `/cyber.rpc.<pkg>.<Service>/` | `pkg/web/service.go:12-13` |

## Exposed Hubs

The Hub needs a single access key on its `/api/` and ConnectRPC paths; without `--token` the key is random and printed to the log. The README and Web guide examples start it with `--token replace-me`, and a key in hand lets anyone run commands on every connected node. The searches are in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `cyber-harness`: the page title `Cyber` with the theme key `cyber-theme` (3 hosts in a scout search, not re-checked), the theme key without the title, the CORS header set, and the older `AIScan` page. There is no favicon hash: the icon is an inline SVG and `/favicon.ico` returns the page.

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: cyber-harness on a host, the watchlist sweep, and its user agents and Hub traffic in web and proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: its user agents in web and proxy logs |
| [`sigma/`](sigma) | 4 Sigma rules: user agents in web logs, Hub traffic and release downloads in proxy logs, its processes, its files |
| [`suricata/`](suricata) | Rules for its user agents and curl header set, its MCP client, the Hub page, headers, login and API, and node and browser traffic to a Hub |
| [`yara/`](yara) | Rules for its binaries and source, the Hub page and the Hub database |

Model traffic from servers, scanners started by an agent, password guessing and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `cyber-harness`.

## Limits

- Most of its scanning comes from the chainreactors scanner libraries and from shell tools the model starts. Their request shapes are set outside this repository and are not covered here.
- The exact user agents appear on two paths only: the scan pipeline's Basic-auth check after a `401`, and the `fetch` tool.
- Binary names change with a rename; the AIScan strings cover builds from before September 15, 2026.
- A match means cyber-harness, not an attacker: it is published for authorized testing and benchmarks. Check who ran it and whether the test was agreed.
