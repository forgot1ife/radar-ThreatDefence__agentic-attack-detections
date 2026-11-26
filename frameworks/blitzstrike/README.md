# Blitz Strike Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Blitz Strike** ([shinthink/blitzstrike](https://github.com/shinthink/blitzstrike), npm package `blitzstrike`, reviewed at `9d7a6ecb`, package version 2.4.200), a TypeScript MCP server that an AI coding client such as Claude Code, Cursor, Codex or OpenCode starts over stdio. One tool call, `run_engagement(<url>)`, runs recon and a fixed set of live injection and misconfiguration checks against a website; other tools verify findings, write proof of concept requests, run nuclei and install any of 130 security tools. Its server instructions tell the model to start with that call, and its scope check records the scope without blocking anything. No vendor or CERT report of Blitz Strike in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds Blitz Strike testing you and Blitz Strike running on a host. It has no web console to find on the internet.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What Blitz Strike leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax, Suricata rules against test flows, Sigma rules against test events, YARA against the Blitz Strike source. Baseline every rule on your own data before alerting |

## What Blitz Strike leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| User agents | `blitzstrike/1.0` on the 27 requests of the default reflection sweep, `blitzstrike/2`, `Mozilla/5.0 (compatible; BlitzStrike/2.4)`, `Mozilla/5.0 (blitzstrike oracle probe)` and four more `Mozilla/5.0 (blitzstrike ...)` strings, `Mozilla/5.0 (recon-agent)`. Its other requests carry the runtime's default (`node` under Node.js) | `src/strike.ts:42`, `src/sibling-scan.ts:111`, `src/auth-session.ts:57`, `src/blind-oracle.ts:142` |
| Sweep marker | `?q=BS<base36 time><random>` and the same in `search`, `query`, `s`, `id`, `url`, `redirect`, `name`, `page` | `src/strike.ts:57-58`, `src/orchestrator.ts:491` |
| Default checks | `https://evil-blitz.example.com` in 11 redirect parameters and as `Origin`; `http://httpbin.org/anything/blitzstrike-ssrf-canary` in 23 URL parameters; `%0d%0aX-BlitzStrike%3A%20injected` in 8 parameters; `Host: bs-marker.example.com` | `src/orchestrator.ts:513,632,644,646` |
| Single-tool markers | `/bs-nonexistent-<id>` (file read control), `blitzstrike_pollution_canary_9f3a` (prototype pollution), `window.__blitz_xss__` (browser XSS check), `zzblitz` (proof of concept requests the model is given to send) | `src/strike.ts:288`, `src/proto-pollution.ts:8`, `src/browser.ts:91`, `src/auto-poc.ts:47` |
| Callbacks | `interactsh-client -json` when installed; otherwise its own listener on `0.0.0.0:<random port>` that answers every request with `oob-ok`. The path after the callback host is chosen by the model | `src/oob.ts:134,157-187` |
| Host | `blitzstrike serve --mcp` under `npx`, `bunx`, a global npm install or `bun run src/index.ts`, child of the AI client; children `nuclei ... -jsonl -silent -no-color -timeout 10`, `interactsh-client -json`, `chrome-devtools-mcp`, `sh -c go install / pip install / apt-get install -y`; files under `~/.blitzstrike/`; a `blitzstrike` entry in every AI client's MCP settings and four OpenCode personas | `src/cli.ts:136-328`, `src/audit.ts:14-15` |
| Console | None. The MCP server speaks stdio only | `src/server.ts:4070-4074` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Blitz Strike on a host, the watchlist sweep, and its user agents and markers in web and proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: Blitz Strike's user agents or default markers reached a web server or proxy |
| [`sigma/`](sigma) | 5 Sigma rules: markers in web logs, the SSRF canary or user agent in proxy logs, the MCP server, the tools it starts, and its files |
| [`suricata/`](suricata) | Rules for its user agents, the markers of its checks, an SSRF canary fetched by your server, and the answer of its callback listener |
| [`yara/`](yara) | A rule for the source, npm bundle or binary, and one for its reports, SARIF files and audit log |

Out-of-band lookups, nuclei and other attack tools, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `blitzstrike`.

## Limits

- The user agent and markers come from Blitz Strike's own HTTP code. Traffic from tools it starts (nuclei, interactsh, Chromium, catalog tools) and commands the driving model runs itself through its shell look like those tools, not like Blitz Strike.
- The `zzblitz` requests are written by `auto_poc` for the model to send; the model can change or skip them.
- A match means Blitz Strike, not an attacker: it is promoted for bug bounty and security testing. Check who ran it and whether the test was agreed.
