# OpenHack Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **OpenHack** ([openhackai/OpenHack](https://github.com/openhackai/OpenHack)), which has shipped two programs under one name. **v2** (the current `main`, reviewed at `f94e153c`, release `v2.0.0`) is a Bun/TypeScript source-code scanner with a dashboard on `127.0.0.1:6969`: it reads a local project, sends excerpts to OpenAI, Anthropic or a reused Codex or Claude Code login, and sends nothing to any target. **v0.x** (the Python package `openhack` on PyPI, latest `0.2.4`, reviewed at tag `v0.2.4`) is a terminal pentest agent that runs nmap, sqlmap, nuclei and shell commands, writes canary rows into a target's database and makes targets call back to the vendor's out-of-band collector `oob.openhack.com`. Public reports of either in an intrusion were not searched for this draft, so this folder is built from the source code alone: it finds the v0.x agent testing you, and either version on a host.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What OpenHack leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax and conversion, Suricata rules against test flows, Sigma rules against test events, YARA against synthetic samples. Baseline every rule on your own data before alerting |

## What OpenHack leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Out-of-band callbacks (v0.2.4) | A target that ran a blind payload resolves `oob.openhack.com` (or `<data>.oob.openhack.com`) and calls `https://oob.openhack.com/<label>-<12 hex>/...` | v0.2.4 `openhack/tools/oob.py:29,41-46`, `openhack/prompts/specialists/blind.py:17-18` |
| Canary rows (v0.2.4) | `__openhack_test_probe`, `__openhack_test_probe_updated`, `__openhack_test_@example.com` written to, read from and deleted from a target's tables, for example `GET /rest/v1/<table>?name=eq.__openhack_test_probe` | v0.2.4 `openhack/prompts/hunter.py:176-189`, `openhack/prompts/validator.py:53-93` |
| User agents (v0.2.4) | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36` on web fetches; exactly `openhack` on calls to `api.openhack.com`, `oob.openhack.com`, `auth.openai.com` and `models.dev` | v0.2.4 `openhack/tools/web.py:34-37`, `openhack/agents/llm.py:92`, `openhack/tools/oob.py:75` |
| Vendor hosts | `api.openhack.com` (v0.2.4 default model gateway and update check), `app.openhack.com` (v0.2.4 login), `install.openhack.com` (v2 installer) | v0.2.4 `openhack/config.py:84-85`, `openhack/updates.py:73`; v2 `deploy/installer/wrangler.toml:8` |
| Subscription CLI children (v2) | `claude --safe-mode --restricted --setting-sources "" --settings {"disableAllHooks":true,"apiKeyHelper":"","forceLoginMethod":"claudeai"} --system-prompt "... You are a source-review worker inside OpenHack. ..."` and `codex --no-daemon exec ... --config model_instructions_file="<tmp>/openhack-subscription-<random>/instructions.txt" -` | v2 `src/providers/subscription.ts:15,84,152-154,164` |
| Host (both) | `~/.openhack/` (v2: `credentials.json`, `projects/<hash>/scans/<id>.json`, `dashboard-6969.log`; v0.2.4: `config`, `auth.json`, `scans/<id>.events.jsonl`), the detached `openhack dashboard --port 6969 --home <home> --no-open`, v0.2.4's `nmap -sV -Pn -T4`, `sqlmap -u <url> --batch --disable-coloring` and compose projects `openhack-sandbox-<time>` | v2 `README.md:147-158`, `src/cli/dashboard.ts:199`; v0.2.4 `openhack/tools/recon.py:105,186`, `openhack/sandbox/orchestrator.py:66` |
| Dashboard (v2) | `127.0.0.1:6969` only; any other `Host` gets 403 `{"error":"This dashboard only accepts requests addressed to localhost."}`. Title `OpenHack · Local`, no favicon | v2 `src/server/index.ts:80,85`, `src/server/security.ts:9`, `web/index.html:7` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: OpenHack on a host, its markers and hosts in web, proxy and DNS logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: one of your hosts contacting the OpenHack out-of-band collector |
| [`sigma/`](sigma) | 8 Sigma rules: the CLI, its subscription CLI children, the scanners v0.2.4 starts, its files, collector lookups, collector and canary markers in web logs, and its hosts and user agent in proxy logs |
| [`suricata/`](suricata) | Rules for collector lookups and callbacks, canary rows, its user agents, its vendor hosts and a forwarded v2 dashboard |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the v2 executable or source, the v0.2.4 package, and v2 scan reports |

Out-of-band lookups to public services, attack tools started by an agent, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `openhack`.

## Limits

- v2 sends nothing to targets. On a network it shows only as calls to the model provider (or, in subscription mode, the provider CLI's own traffic) and a one-time download from `install.openhack.com` and GitHub.
- The canary rows and the out-of-band payload shapes come from v0.2.4's prompts; the model decides whether to follow them. `OOB_URL` moves the collector to any host.
- v0.2.4's scanning goes through nmap, sqlmap, nuclei, httpx and curl with their own default user agents, which these strings do not cover.
- Nothing listens beyond loopback, so there is no exposed console to search for.
- A match means OpenHack, not an attacker: both versions are published as tools for testing code and systems you own. Check who ran it and whether the test was agreed.
