# DarkMoon Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **DarkMoon**, an open-source autonomous AI penetration testing stack from ASC IT. A branded OpenCode fork runs an orchestrator and about 50 specialist sub-agents (web, CMS, cloud, Active Directory, Kubernetes, CI/CD, email, firmware, LLM endpoints), and every command they run goes through the DarkMoon MCP server into a root toolbox container with the host's Docker socket. It works with cloud models, on-prem Anthropic-compatible endpoints, and local Ollama or llama.cpp. No public report of DarkMoon used in an intrusion was found.

| | |
|---|---|
| Tool | [ASCIT31/Dark-Moon](https://github.com/ASCIT31/Dark-Moon) (Docker Hub `ascit/darkmoon`, `ascit/opencode-darkmoon`), reviewed at `bb1b70ce` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Status | Experimental. Written from the source code; Suricata cases are crafted from the agent prompts. Baseline every rule on your own data before alerting |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: DarkMoon on a host, watchlist sweep, DarkMoon markers in web and proxy logs, and the `/tmp/.dm_proof` file on your servers |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: the DarkMoon stack running on a host |
| [`sigma/`](sigma) | 4 Sigma rules for process, file and web server logs |
| [`suricata/`](suricata) | Rules for the probes the agent prompts write out (user agent `dm-edge`, the `dm-poison.invalid` cache test, SMTP `dm-test.local`, registry and SCIM proofs), the placeholder model key `darkmoon-local`, and the MCP server's own answers |
| [`yara/`](yara) | Rules for the DarkMoon source and images, its reports and its `.opencode.env` file |
| Docs | [What DarkMoon leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |

The open-source edition has no web console: the only service it runs is its MCP server on `127.0.0.1:8181` inside a container, so internet exposure is rare and only shows when an operator publishes that port. DarkMoon sends no telemetry. What it does to a target looks mostly like its stock tools (naabu, httpx, nuclei, katana, ffuf, sqlmap), so the cross-framework rules in [`behaviors/`](../../behaviors) carry much of the target-side detection: an AI agent in auto-approve mode driving attack tools (hunt 01; DarkMoon allows every tool call), model API calls from servers (hunt 02) and NetExec fan-out across Windows hosts (hunt 06).

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `darkmoon`.
