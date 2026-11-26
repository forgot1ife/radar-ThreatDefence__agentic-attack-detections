# CHYing-agent Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **CHYing-agent**, an open-source contest agent from the Tencent Cloud hackathon's intelligent penetration challenge. An orchestrator on the Claude Agent SDK, with permissions bypassed, hands work to sub-agents that run commands in a privileged Kali container, drive a headless Chrome, decompile binaries through a Ghidra MCP server and, when enabled, run Metasploit post-exploitation in tmux. It works with any Anthropic-compatible model endpoint; the author ran it on GLM-5. No public report of CHYing-agent used in an intrusion was found.

| | |
|---|---|
| Tool | [yhy0/CHYing-agent](https://github.com/yhy0/CHYing-agent) (MIT, no published package or image), reviewed at `0d2ee81f` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What CHYing-agent leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Written from the source code; Suricata cases are crafted from it. Baseline every rule on your own data before alerting |

## What CHYing-agent leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Web terminal markers | When it takes over a target's web terminal (ttyd, wetty, GoTTY, Kubernetes exec) it types `echo __WSS_PROBE_7b3e__`, and wraps every command with `; __chy_rc=$?; printf '\n__WSS_EXIT_c1a4__%s\n' "$__chy_rc"; echo __WSS_CMD_END_9f7a__` | `chying_agent/claude_sdk/wss_terminal_client.py` |
| Dashboard | FastAPI and Vue on `0.0.0.0:8080`, no login, title `CHYing Agent Dashboard`, OpenAPI description `Web Dashboard API for CHYing Agent`, stock Vite icon `/vite.svg` | `main.py`, `chying_agent/web/app.py`, `web-ui/index.html` |
| Tools container | `chying-agent-docker` from the locally built image `chying-agent-docker-tools:latest`, privileged, publishing an unauthenticated GhidraMCP REST server on 8089 and MCP bridge on 8766 | `docker/docker-compose.yml`, `docker/entrypoint.sh` |
| Python tool calls | `/bin/bash -c "echo <base64> \| base64 -d \| python3"` in the container; the base64 starts `IyA9PT0g6Ieq5Yqo5rOo5YWl77ya` (the agent's work-directory header) | `chying_agent/executor/docker_native.py`, `chying_agent/claude_sdk/mcp_tools.py` |
| Files | `agent-work/ctf/<Category>/<challenge>/` with `findings.log`, `attack_timeline.md`, `dumps/commands.log`, `poc_scripts/`; `data/chying.db`; `logs/chying_agent_<time>.log` | `chying_agent/challenge_solver.py`, `chying_agent/db/session.py`, `chying_agent/common.py` |
| Model traffic | System prompt `You are CHYing Orchestrator - an autonomous security automation system ...` and tools named `mcp__chying__exec`, `mcp__chying__record_key_finding` | `chying_agent/prompts/orchestrator_identity.md`, `chying_agent/claude_sdk/mcp_tools.py` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: CHYing-agent on a host, the watchlist sweep, and dashboard use and web terminal markers in proxy, firewall and target logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: CHYing-agent running on a host |
| [`sigma/`](sigma) | 3 Sigma rules: the launch, container and Ghidra services; Python tool calls in its container; its files |
| [`suricata/`](suricata) | Rules for the web terminal markers in terminal output, an exposed dashboard, and its model requests (TLS inspection) |
| [`yara/`](yara) | Rules for its source, the command wrapper left in a target's shell history, and its work files |
| Docs | [What CHYing-agent leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |

CHYing-agent has no user agent or canary of its own in HTTP traffic: what reaches a web target is its Kali tools with their defaults, so the cross-framework rules in [`behaviors/`](../../behaviors) carry most of the target-side detection (an AI agent driving attack tools with permissions bypassed, model API calls from servers, out-of-band lookups). It sends no telemetry.

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `chying-agent`.

## Limits

- The web terminal markers only reach the wire in cleartext `ws://` or decrypted `wss://`, and only in the terminal's output: the client's frames are masked, and GoTTY base64-encodes its output.
- The dashboard title needs the Vue build (`start-web.sh`); without it only the API, `/docs` and `/openapi.json` answer.
- A match means CHYing-agent, not an attacker: it is a contest tool. Check who ran it and whether the test was agreed.
