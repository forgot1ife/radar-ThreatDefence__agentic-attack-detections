# hackingBuddyGPT Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**hackingBuddyGPT** ([ipa-lab/hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT), reviewed at `e23d9185`, October 24, 2026). Open-source Python framework for LLM-driven security testing, from the paper "Getting pwn'd by AI: Penetration Testing with Large Language Models" (arXiv 2308.00121), with over 1,300 stars. Each experiment is a sub-command of its `wintermute` CLI: Linux privilege escalation over SSH, Windows privilege escalation over psexec, web and REST API testing over HTTP, and an Active Directory planner/executor that drives a Kali host. The model's commands run with no approval step.

hackingBuddyGPT has no web interface, API server or listening port, so there is nothing to find on the internet. Its HTTP requests carry Python requests' default user agent. What identifies it is the way it frames commands in a target's shell, a few fixed values in its web-API discovery code, and its CLI and files on the host that runs it. No vendor or CERT report of hackingBuddyGPT in a real intrusion was found on November 26, 2026.

| | |
|---|---|
| Tool | [ipa-lab/hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT), reviewed at `e23d9185`. PyPI package `hackingBuddyGPT`, container image `ghcr.io/ipa-lab/hackingbuddygpt` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA |
| Docs | [What hackingBuddyGPT leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the source code, not from captured runs. Suricata rules tested against flows written from the source, YARA against the source tree and synthetic logs and history files. Baseline every rule on your own data before alerting |

## What hackingBuddyGPT leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Shell framing on Linux targets | Each command typed into one interactive bash over SSH between `echo __CMDSTART_<8 hex>__` and `echo "__CMDEND_<8 hex>__:$?:$(id -u):$(id -un)"`: in `~/.bash_history`, and as an `id -u` and `id -un` process after every command | `utils/connectors/ssh_interactive_connection.py:112-143` |
| Web-API discovery | Query values set by the code: `api_key=YourAPIKeyHere`, `access_token=YourAccessToken`, `callback=myFunction` and others; the joined path `/products/1/users/profile` | `usecases/web_api/detection_response_handler.py:45-76,400-428` |
| Web-API test prompts | OTP guesses for `adam007@example.com` with `Az123###` (the crAPI victim account), `{"email": "' or 1=1--", "password": "a", "x": <n>}`, `<script>alert("XSS2")</script>` | `utils/prompt_generation/information/_pentesting_auth.py:535`, `_pentesting_injection.py:181,314` |
| lse.sh on the target | `wget -q '.../linux-smart-enumeration/releases/latest/download/lse.sh' -O lse.sh;chmod 700 lse.sh; ./lse.sh -c -i -l 0` | `usecases/call_usecase_from_usecase.py:36` |
| Operator host | `wintermute <UseCase>`, `python -m hackingBuddyGPT.cli.wintermute`, `benchmark_privesc.py`; tmux `send-keys` with `echo 'CMDSTART<hex>'` in local shell mode; `logs/log-<timestamp>.jsonl` with `hackingbuddygpt.run.*` keys | `pyproject.toml:82-86`, `utils/connectors/local_shell.py:169-183`, `utils/log_storage.py:41-51,113-131` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: hackingBuddyGPT on a host, its shell framing on a Linux target, its discovery values in web and proxy logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: the hackingBuddyGPT CLI on a host |
| [`sigma/`](sigma) | 5 Sigma rules: the CLI, the tmux markers, lse.sh on a target, its output files, its discovery values in web logs |
| [`suricata/`](suricata) | 7 rules: discovery values and test payloads against your sites, and SSH logins from asyncssh |
| [`yara/`](yara) | Rules for the source, its run logs, and its markers in shell history |

The model traffic, the tools the model picks on a Kali host and SSH logins with a weak password look like any agent or tester; the cross-framework rules in [`behaviors/`](../../behaviors) cover them.

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `hackingbuddygpt`.

## Limits

- Most signals depend on the use-case. The shell framing comes from the Linux privilege-escalation use-cases, the query values from `WebAPITesting`, lse.sh from `ExPrivEscLinuxLSE`. The web use-cases send whatever the model writes.
- The test payloads are instructions to the model, which can reword them. The crAPI account values are also in public crAPI walkthroughs.
- The asyncssh client banner is a library default, used by other tools too.
- A match means hackingBuddyGPT, not an attacker: it is research code, popular with students and security teams. Check who ran it and whether the test was agreed.
