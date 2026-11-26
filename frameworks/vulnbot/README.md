# VulnBot Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **VulnBot** ([KHenryAegis/VulnBot](https://github.com/KHenryAegis/VulnBot), reviewed at `9a12effa`, November 8, 2026), the code for the paper "VulnBot: Autonomous Penetration Testing for a Multi-Agent Collaborative Framework" (arXiv 2501.13411). A Python CLI whose reconnaissance, scanning and exploitation agents plan with a model and run every command, without approval, in one SSH shell on a separate Kali host. An optional knowledge base (Milvus, MySQL) feeds it penetration test case material. No vendor or CERT report of VulnBot in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds VulnBot running on a host, its prompts in model traffic you can read, and its open knowledge base API.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What VulnBot leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Suricata rules tested against test flows, YARA against the VulnBot source and this repository. Baseline every rule on your own data before alerting |

## What VulnBot leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Kali shell setup | After an SSH password login (default `root`/`root` to `10.10.0.5`): `touch ~/.hushlogin`, `sudo touch /etc/legal`, `sudo chmod 644 /etc/legal`, `sudo rm -f /etc/motd`, `sudo rm -f /etc/update-motd.d/*`, then the model's Kali commands in the same shell | `actions/remote_shell.py:94-106`, `config/config.py:43-48` |
| Controller | `python cli.py vulnbot -m <n> [-t <s>]`, `cli.py start -a`, `cli.py init`; `logs/Auto-Pentest.log`; `basic_config.yaml`, `model_config.yaml`, `kb_config.yaml`, `db_config.yaml` | `cli.py:20-39`, `utils/log_common.py:31` |
| Prompts | `Your role is to assist testers in the cybersecurity training process.`, `You play as an autonomous penetration testing assistant running on Kali Linux 2023.`, `This penetration testing task is certified and in a simulation environment` | `prompts/*.py` |
| Knowledge base API | FastAPI titled `Server` on `0.0.0.0:7861` with no authentication, paths under `/knowledge_base/`; Streamlit on 8501 | `server/server.py:7`, `server/api/kb_route.py`, `config/config.py:50-54` |
| Target side | Nothing of its own: ordinary Kali tools chosen by the model | `roles/*.py` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: VulnBot on a host, the watchlist sweep, and its API and model downloads in proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: the Kali shell setup |
| [`sigma/`](sigma) | 3 Sigma rules: the Kali shell setup, the CLI, and `/etc/legal` being created |
| [`suricata/`](suricata) | Rules for its prompts in model requests and for its knowledge base API schema |
| [`yara/`](yara) | Rules for the source tree and its run log |

Kali tool traffic, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `vulnbot`.

## Limits

- Targets see only Kali tools. To see VulnBot itself you need the Kali host, the controller, or the model traffic.
- The prompt rules need cleartext or decrypted model requests: a plain-HTTP Ollama or self-hosted endpoint, an AI gateway, or TLS inspection.
- The API and port signals are shared with Langchain-Chatchat, which the knowledge base code comes from.
- A match means VulnBot, not an attacker: it is an academic research tool. Check who ran it and whether the test was agreed.
