# Cybermes Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**Cybermes** ([Zyrexnn/Cybermes](https://github.com/Zyrexnn/Cybermes), reviewed at `149b9a66`, November 16, 2026; v3.5.1; npm package `cybermes-mcp`; image `ghcr.io/zyrexnn/cybermes`) is an autonomous offensive security and bug bounty framework built on [Hermes Agent](../hermes). It ships a Hermes persona and configuration with approvals switched off and a system prompt that treats every target the operator names as authorized, about 220 attack skills, a Docker image that runs the Hermes Telegram gateway, and a Go MCP server (`cybermes-mcp`) that gives AI clients crawl, probe, fuzz, nmap, nuclei and reporting tools.

Cybermes has no listener of its own, so there is nothing Cybermes-specific to find on the internet; the Hermes dashboard rules apply if an operator starts it. On a target, Cybermes shows up through fixed user agents when its own HTTP engines and audit scripts run, and otherwise as stock scanner traffic. On a host, its launcher, MCP server and files are distinctive. No vendor or CERT report of Cybermes in a real intrusion was found on November 26, 2026.

| | |
|---|---|
| Tool | [Zyrexnn/Cybermes](https://github.com/Zyrexnn/Cybermes), reviewed at `149b9a66` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA |
| Docs | [What Cybermes leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the source code, not from captured runs. Baseline every rule on your own data before alerting |

## What Cybermes leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Engine user agents | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Cybermes/2.1 (Recon Crawler)`, `... Cybermes/2.1 (Security Assessment)`, `... Cybermes/3.2 (API Fuzzer)`, `... Cybermes/3.2 (Subdomain Recon)` (to crt.sh), when katana, httpx, ffuf or subfinder are not installed | `pkg/crawl/crawler.go:84`, `pkg/probe/probe.go:82`, `pkg/fuzz/fuzzer.go:382`, `pkg/subdomain/subdomain.go:183` |
| Audit scripts | `Cybermes-AIGateway-Auditor/1.0` with `Origin: https://audit-canary.example.com`; `Cybermes-ExamAuditor/1.0`; `Cybermes-Security-Auditor/1.0` in model-written PoCs | `scripts/audit_ai_gateway_config.py:28,59`, `scripts/audit_exam_state_machine.py:109`, `.cursorrules:8` |
| Hermes set up for attack | `HERMES_YOLO_MODE=1`, `approvals.mode: 'off'`, persona "You are Cybermes, an ...", auto-loaded skill `autonomous-godmode-hunter`; container `cybermes-agent` running `/opt/hermes-venv/bin/hermes gateway run` | `.env.example:45`, `.hermes/config.yaml.example:11-13,54-57,74-76`, `docker-compose.yml:7,21` |
| MCP server | `cybermes-mcp` via `npx -y cybermes-mcp@latest`, cached as `~/.cybermes/bin/cybermes-mcp-v<version>-<os>-<arch>`; scanners started with its fixed argument order | `npm/src/adapters/clients.js:42`, `npm/src/utils/binary.js:44,130`, `pkg/nmap/nmap.go:282-296` |
| Files | `recon/<slug>/katana.txt`, `reports/<slug>/{findings,pocs,evidence}/`, `report.html` ("Cybermes Security Assessment"), `REPORT_<slug>.pdf`, `~/.cybermes/` | `pkg/report/aggregator.go`, `pkg/report/html_template.go:328` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Cybermes on a host, its user agents in web and proxy logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: the Cybermes launcher, MCP server or its files on a host |
| [`sigma/`](sigma) | 5 Sigma rules for process, file, proxy and web server logs |
| [`suricata/`](suricata) | 12 rules: the user agents and audit canary, npm and release downloads, and the persona and MCP tool names in decrypted model traffic |
| [`yara/`](yara) | Rules for the Cybermes persona and config, its source and MCP binary, and its reports |

## Hermes rules that apply

Cybermes runs Hermes, so the [Hermes rules](../hermes) apply on a host that runs it:

- Hermes hunt 01 fires on the attack tools (nmap, nuclei, httpx, katana, sqlmap) that Hermes starts in Cybermes runs.
- The Hermes Sigma process rule and the Hermes analytics rule fire only when `--yolo` or `HERMES_YOLO_MODE` is on the command line. Cybermes sets `HERMES_YOLO_MODE=1` in `.env` and `approvals.mode: 'off'` in `config.yaml`, neither of which reaches the command line, so they usually stay quiet; the Cybermes rules here cover that gap.
- The Hermes file rule and godmode YARA rule do not fire: `autonomous-godmode-hunter` is not the Hermes `godmode` jailbreak skill, and Cybermes writes no `prefill.json`.
- The Hermes dashboard and WebUI rules (Suricata 3806010, 3806011, 3806013; `http.title:"Hermes Agent" port:9119`) fire only if the operator starts `cybermes dashboard` or a Hermes WebUI.

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `cybermes`.

## Limits

- The engine user agents appear only when katana, httpx, ffuf or subfinder are missing, which `setup.sh` tries to prevent by downloading them; a custom `User-Agent` header in a tool call also replaces them. With the tools installed, a target sees stock tool traffic, covered by [`behaviors/`](../../behaviors).
- The prompt, folder, file and container names are easy to change in a fork; the rules catch Cybermes as published.
- Model-traffic rules need TLS inspection or an AI gateway. Most targets are HTTPS, so the user-agent rules usually see them only in web server logs.
- A match means Cybermes, not an attacker: it is published for bug bounty and authorized testing. Check who runs it and against what.
