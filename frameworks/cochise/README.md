# Cochise Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**Cochise** ([andreashappe/cochise](https://github.com/andreashappe/cochise), reviewed at `4db4fded`, October 24, 2026). Research prototype by Andreas Happe for autonomous assumed-breach testing of Microsoft Active Directory networks, published with the ACM TOSEM paper *Can LLMs Hack Enterprise Networks?* (arXiv 2502.04227). A Planner model keeps an attack plan and hands one task at a time to a short-lived Executor model, which runs shell commands over SSH on a Kali Linux VM inside the target network and reports back. Models are reached through litellm; the README and every shipped run log use OpenRouter.

Cochise is about 630 lines of Python with no web interface, no API server and no listening port, so there is nothing to find on the internet. It sends no fixed user agent, marker or callback to a target: the lab sees stock Kali tools (`nxc`, impacket, `certipy-ad`, `nmap`) chosen by the model. The useful signals are its scenario prompt, which tells the model to spray from `/osint_users.txt` and to run `ntpdate <dc-ip>` before Kerberos attacks, its asyncssh client on the Kali VM, and the JSON run log it writes. No vendor or CERT report of Cochise in a real intrusion was found on November 26, 2026.

| | |
|---|---|
| Tool | [andreashappe/cochise](https://github.com/andreashappe/cochise), reviewed at `4db4fded`. Not on PyPI or Docker Hub |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA |
| Docs | [What Cochise leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the source code and the run logs the repository ships, not from captured traffic. Baseline every rule on your own data before alerting |

## What Cochise leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| User list path | Spraying and AS-REP commands that read `/osint_users.txt`, a file at the root of the Kali VM that the scenario prompt names (39 of the 59 shipped runs) | `templates/scenario.md:31` |
| Run log | `logs/run-<YYYYmmdd-HHMMSS>.json` in the working directory, JSON lines starting with `"event": "starting test-run"`, holding every command, its output and every credential found | `logger.py:33-52` |
| SSH client | `SSH-2.0-AsyncSSH_2.24.0` from the Cochise host to the Kali VM, password login, one session for the whole run, every command an exec channel with no PTY | `ssh_connection.py:19,27` |
| Launcher | `uv run cochise`, `<venv>/bin/cochise`, older `python src/cochise.py`; `cochise-replay logs/run-<ts>.json` | `pyproject.toml:21-25` |
| Prompts | `You MUST call the perform_task tool to delegate work to the executor.` and the scenario text, in model traffic and in the run log | `planner.py:205`, `templates/scenario.md` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Cochise on a host (launcher, run log, the Kali VM side), its network and SSH shape, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: AD attack commands that read `/osint_users.txt` |
| [`sigma/`](sigma) | 3 Sigma rules for process and file events |
| [`suricata/`](suricata) | 1 rule for the asyncssh client banner |
| [`yara/`](yara) | Rules for the source, the scenario prompt and the run log |

What Cochise does to a lab looks like the stock tools it runs and like any agent, so the cross-framework rules in [`behaviors/`](../../behaviors) carry most of the network detection: model API calls from servers and AD attack tools in bursts.

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `cochise`.

## Limits

- Cochise is built for lab networks (GOAD). The scenario hard-codes `192.168.122.0/24`; an operator edits it for another range.
- `/osint_users.txt`, the log name and the launcher are easy to change; the rules catch someone running the repository as published.
- The asyncssh banner belongs to a library, not to Cochise. On its own it says only that a Python asyncssh client logged in.
- A match means Cochise, not an attacker: it is research code. Check who runs it and against what.
