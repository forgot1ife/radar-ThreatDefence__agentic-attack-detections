# NyxStrike Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **NyxStrike** ([CommonHuman-Lab/nyxstrike](https://github.com/CommonHuman-Lab/nyxstrike), reviewed at `3ac7449`, release 1.9.0), a derivative of [HexStrike](../hexstrike) that was published as "HexStrike AI - Community Edition" until April 2026. It exposes about 200 offensive tools to any MCP client, or to its own LLM agents, through a Flask server on port 8888 that also serves a React dashboard, and it runs every tool through a shell. No vendor or CERT report of NyxStrike in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds NyxStrike testing you, NyxStrike running on a host, and its server exposed.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What NyxStrike leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax and conversion, Suricata rules against test flows, YARA against the NyxStrike source, its CommonHuman-Lab scanner packages and the HexStrike source. Baseline every rule on your own data before alerting |

## What NyxStrike leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| User agents | `NyxStrike/1.0` (decision engine HEAD of the target), `Security-HTTP-Framework/1.0 (Advanced Security Testing)`, `Security-BrowserAgent/1.0 (Security Testing)`, `commonhuman-core/openapi-discover` | `backend/server_core/intelligence/intelligent_decision_engine.py:192`, `backend/server_api/web_framework/` |
| Probes | `<xssTest123>` in GET forms; StingXSS and BreachSQL markers `StingXSS_<6>`, `BreachSQL_<6>`, `stingxss_redir_marker`, `X-StingXSS-Crlf`, `Origin: https://evil.stingxss-probe.example.com` | `browser_agent.py:238`, stingxss, breachsql |
| Host | `nyxstrike-env/bin/python3 nyxstrike_server.py` as the parent of `/bin/sh -c <tool>`, `nyxstrike_mcp.py --server http://...:8888`, a burst of about 150 `which` processes, `.nyxstrike_data/`, `nyxstrike.log` | `nyxstrike.sh`, `enhanced_command_executor.py:251-253` |
| Server | Port 8888, `/health` says `NyxStrike Tools API Server is operational`, `/ping` says `Pong! NyxStrike Tools API Server is responsive`; with a token set, every path answers `401` with `Unexpected authorization header format` | `monitoring.py:35`, `system_monitoring.py:215`, `nyxstrike_server.py:66` |
| Console | Title `NyxStrike`, icon `/assets/favicon-CBc3_nbG.ico` with Shodan hash `-1255721562` | `frontend/dashboard/index.html` |

## Shared with HexStrike

NyxStrike keeps HexStrike's `/api/tools/<tool>` API on 8888 and its exploit generator user agent `Mozilla/5.0 (Compatible Exploit)`, so HexStrike Suricata 3803003 and 3803011, its proxy rule and YARA `HexStrike_Generated_Exploit` fire on NyxStrike too. The rules here match only what NyxStrike renamed or added; the HexStrike user agent, probe and health rules do not fire on NyxStrike 1.4.0 or later. The full comparison is in [source-code-signals.md](source-code-signals.md#what-it-shares-with-hexstrike-and-what-changed).

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: NyxStrike on a host, the watchlist sweep, and its user agents, markers and server paths in web and proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: NyxStrike user agent or browser agent probe |
| [`sigma/`](sigma) | 4 Sigma rules: web logs, processes, files and proxy |
| [`suricata/`](suricata) | Rules for its user agents and probe markers, and for its server's health, ping, dashboard and 401 responses |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for its source and dashboard bundle, MCP client configurations that use it, and the StingXSS and BreachSQL packages it installs |

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `nyxstrike`.

## Limits

- Most of its scanning is stock tools (nmap, nuclei, sqlmap, ffuf) with their own user agents; the strings here cover NyxStrike's own modules and its CommonHuman-Lab scanners.
- StingXSS and BreachSQL are published on their own as well, so their markers mean those scanners, not necessarily NyxStrike.
- A match means NyxStrike, not an attacker: it is promoted for authorized testing, bug bounty and CTF work. Check who ran it and whether the test was agreed.
