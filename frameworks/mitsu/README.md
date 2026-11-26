# Mitsu Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**Mitsu** ([ARCANGEL0/Mitsu](https://github.com/ARCANGEL0/Mitsu), reviewed at `a4844932`, November 20, 2026; PyPI package `mitsu` 1.5.2). Terminal (TUI) AI pentest agent in Python. It connects a model from about 20 providers, or the Codex or Claude Code CLI, to its own MCP server, which offers a shell tool, a web reader and a catalog of 165 offensive tools (nmap, nuclei, sqlmap, hydra, netexec, Metasploit and others) that it can install on request. It keeps a per-session "Intel" record of targets, services, findings and credentials, and writes HTML and PDF assessment reports. It has three modes: Recon (passive), Guided (operator approves each action) and AutoPwn (no per-command approval).

Mitsu has no web console and no API server: its only listeners, a per-turn MCP server and an optional SearXNG container, are bound to 127.0.0.1, so there is nothing to find on the internet. On a target it shows up as one fixed user agent on the pages it reads, followed by stock scanner traffic. The strongest signals are on the host that runs it. No vendor or CERT report of Mitsu in a real intrusion was found on November 26, 2026.

| | |
|---|---|
| Tool | [ARCANGEL0/Mitsu](https://github.com/ARCANGEL0/Mitsu), reviewed at `a4844932`. PyPI `mitsu`; no Docker image |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA |
| Docs | [What Mitsu leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the source code, not from captured runs. Baseline every rule on your own data before alerting |

## What Mitsu leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Page fetch user agent | `Mitsu/0.1 (terminal assistant; public search)` on every page its web_search tool opens, and on its search-engine scraping. The prompt tells the model to open operator-supplied URLs this way first | `search/engines.py:77,114-125`, `tui/session.py:5626` |
| Codex provider | `codex exec ... --config mcp_servers.mitsu.url="http://127.0.0.1:<port>/<token>/mcp" --config developer_instructions="You are Mitsu: the operator’s ..."` in `/tmp/mitsu-codex-sessions/<id>` | `providers/codex_cli.py:119-151,334` |
| Claude Code provider | `claude -p ... --mcp-config {"mcpServers":{"mitsu":...}} --permission-mode dontAsk --allowedTools mcp__mitsu__...` in `/tmp/mitsu-claude-sessions/<id>` | `providers/claude_code.py:376-407` |
| Shell tool | `/bin/bash -o pipefail -c <command>` (or `sudo -S -p "" -- /bin/bash -o pipefail -c`) under the Mitsu Python process; Armory scanners start directly under it | `tools/agent_host.py:1557-1572`, `tools/armory_mcp.py:337-346` |
| SearXNG | Container `mitsu-searxng-<port>` and volume `mitsu-searxng-config` on 127.0.0.1 | `services/searxng.py:209,237-249` |
| Files | `~/.local/share/mitsu/sessions/<32 hex>.json` (conversation, targets, findings, credentials), reports `vulnerability-assessment-<stamp>.html/.pdf`, `~/.config/mitsu/credentials.json` | `config/storage.py:57,223`, `workspace/assessment_report.py:1065` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Mitsu on a host, its user agents in web and proxy logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: the Codex or Claude Code CLI started by Mitsu, or its SearXNG container |
| [`sigma/`](sigma) | 7 Sigma rules for process, file, proxy and web server logs |
| [`suricata/`](suricata) | 5 rules: the two user agents, and the prompt and tool names in decrypted model traffic |
| [`yara/`](yara) | Rules for the Mitsu source, its session files, and its reports and attack-surface map |

Mitsu's scans come from stock tools, so the cross-framework rules in [`behaviors/`](../../behaviors) carry most of the target-side detection: model API calls from servers, coding-agent CLIs started with MCP servers, and scanner traffic against your sites.

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `mitsu`.

## Limits

- Only the page fetch user agent reaches a target, and only for pages the model opens with `web_search`. Everything else a target sees is a stock tool's traffic.
- The user agent, prompt, folder and container names are easy to change in a fork; the rules catch Mitsu as published.
- Model-traffic rules need TLS inspection or an AI gateway. Most targets and search engines are HTTPS, so the user-agent rules see them only in web server logs or behind a TLS-inspecting proxy.
- A match means Mitsu, not an attacker: it is published for CTFs, labs and authorized tests. Check who runs it and against what.
