# KaliGPT Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**KaliGPT**, also called **HackerX** ([SudoHopeX/KaliGPT](https://github.com/SudoHopeX/KaliGPT), reviewed at `b15b8d48`, November 25, 2026, branch `hackerx`, KaliGPT v1.3). Command-line AI agent in Python for Kali and other Debian, Arch and Termux systems. It connects a Gemini (default), OpenAI, OpenRouter, Ollama or LiteLLM model to seven tools: a shell tool that runs any command the model chooses without approval, two HTTP tools that probe a URL with their own user agents, and web search through a companion helper, OpenSearchAPI, that it starts on 127.0.0.1:5000. Its system prompt tells the model to hunt web vulnerabilities autonomously and in a loop.

KaliGPT has no web console. On a target it shows up as the fixed user agent of its HTTP tools, followed by stock tool traffic (curl, nmap, gau). On the host it is easy to see: a fixed install folder, `/opt/KaliGPT`, a launcher in `/usr/local/bin`, and fixed process command lines. No vendor or CERT report of KaliGPT in a real intrusion was found on November 26, 2026.

| | |
|---|---|
| Tool | [SudoHopeX/KaliGPT](https://github.com/SudoHopeX/KaliGPT), reviewed at `b15b8d48`; installed from a `curl \| bash` script, no package or image. Companion [SudoHopeX/OpenSearchAPI](https://github.com/SudoHopeX/OpenSearchAPI) at `02108aba` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA |
| Docs | [What KaliGPT leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the source code, not from captured runs. Baseline every rule on your own data before alerting |

## What KaliGPT leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| HTTP tool user agents | `HackerX WebRequestFramework/1.0` (web_request_analysis, get_raw_response) and `LocalScraper/1.0` (get_local_server_content) on requests to targets | `agents/utils/tools/web_request_framework.py:63,276`, `agents/utils/tools/locals.py:35` |
| Processes | `python /opt/KaliGPT/OpenSearchAPI/app.py` (search helper on 127.0.0.1:5000), `python3 -m agents.gemini` and the other providers in `/opt/KaliGPT`, `/bin/bash /usr/local/bin/kaligpt ...` | `installers/installer.deb.sh:141-306` |
| Shell tool | The model's command split on spaces and started directly (no shell) under the provider process, in `/opt/KaliGPT` | `agents/utils/tools/locals.py:68-95` |
| Files | `/opt/KaliGPT/`, `/usr/local/bin/kaligpt`, `/usr/local/bin/opensearchapi`, `kaligptinstaller.sh`; API keys in `/opt/KaliGPT/agents/utils/api.config.json`, mode 666 | `install.sh:77`, `installers/installer.deb.sh:72-315` |
| Web launcher | `chromium https://chatgpt.com/g/g-xouSQobsE-kaligpt/?prompt=<prompt>` | `agents/utils/web_launcher.json:15`, `agents/web_launcher.py:184` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: KaliGPT on a host, its user agents and URLs in web and proxy logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: KaliGPT's search helper, launcher or provider module on a host |
| [`sigma/`](sigma) | 7 Sigma rules for process, file, proxy and web server logs |
| [`suricata/`](suricata) | 3 rules: the two tool user agents, and the OpenSearchAPI helper page |
| [`yara/`](yara) | Rules for the KaliGPT source, its launcher and installer, and its provider key file |

KaliGPT's scans come from stock tools, so the cross-framework rules in [`behaviors/`](../../behaviors) carry most of the target-side detection: model API calls from servers and scanner traffic against your sites.

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `kaligpt`.

## Limits

- Only the two HTTP tools carry a KaliGPT user agent, and the model can replace the first one through the tool's `headers` argument. Everything else a target sees is a stock tool's traffic.
- Install paths, the launcher name and the user agents are easy to change in a fork or a manual install; the rules catch KaliGPT as published.
- HTTPS targets show the user agent only in web server logs or behind a TLS-inspecting proxy.
- The search helper rule (Suricata 3813223, Shodan query) also matches OpenSearchAPI run on its own, without KaliGPT.
- A match means KaliGPT, not an attacker: it is published for learning and authorized testing. Check who runs it and against what.
