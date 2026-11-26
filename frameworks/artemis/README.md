# ARTEMIS Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**ARTEMIS** ([Stanford-Trinity/ARTEMIS](https://github.com/Stanford-Trinity/ARTEMIS), reviewed at `f309242d`, December 31, 2025). "Automated Red Teaming Engine with Multi-agent Intelligent Supervision", a research agent from the Stanford Trinity project for finding vulnerabilities on its own. A Python supervisor plans the work, starts one sub-agent per task and reports findings to Slack. Each sub-agent is a fork of OpenAI's Codex CLI, started with sandboxing and approvals switched off and a red-team specialist prompt (web, web enumeration, client-side web, enumeration, Linux or Windows privilege escalation, Active Directory, shelling). An optional triage step re-runs each finding to reproduce it and rate it before it is posted.

ARTEMIS has no web interface, no API server and no listening port, so there is nothing to find on the internet. It sends no fixed user agent, marker or callback to a target: the target sees stock Kali tools chosen by the model. The strong signals are on the host that runs it, where the Codex fork carries command-line options no other Codex build has. No vendor or CERT report of ARTEMIS in a real intrusion was found on November 26, 2026.

| | |
|---|---|
| Tool | [Stanford-Trinity/ARTEMIS](https://github.com/Stanford-Trinity/ARTEMIS), reviewed at `f309242d`. No PyPI, npm or Docker Hub package is named in the repository; the README builds a local image tagged `artemis` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA |
| Docs | [What ARTEMIS leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the source code, not from captured runs. Baseline every rule on your own data before alerting |

## What ARTEMIS leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Sub-agent | `codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check --log-session-dir <dir> --instance-id <id> --wait-for-followup -C <dir> --mode <specialist> <task>`; `--wait-for-followup` and `--instance-id` exist only in the ARTEMIS fork | `supervisor/orchestration/instance_manager.py:77-105`, `codex-rs/exec/src/cli.rs:66-80` |
| Supervisor | `python -m supervisor.supervisor --config-file <task>.yaml [--benchmark-mode] [--skip-todos] [--use-prompt-generation]`, or `codex-supervisor`; older driver `codex autonomous -f <config>.yaml` | `supervisor/supervisor.py:51-72`, `codex-rs/cli/src/main.rs:144-187` |
| Session folder | `logs/supervisor_session_<unix time>/` with `supervisor_heartbeat.json`, `supervisor_todo.json`, `vulnerabilities_found.log`, and `workspaces/<id>/realtime_context.txt`, `status.json`, `followup_input.json`, `final_result.json` | `supervisor/supervisor.py:87-89`, `codex-rs/exec/src/realtime_logger.rs:39,496` |
| Slack report | `curl -X POST -H "Content-Type: application/json" --data '{"title": ..., "vuln_type": ..., "repro_steps": ..., "cleanup": ...}' <webhook>` | `supervisor/submissions/vulnerability.py:72-80` |
| Prompts | `You are Codex, a deployed cybersecurity red-teaming agent operating inside a fully-equipped Kali Linux container`, embedded in the compiled `codex` binary | `codex-rs/core/web.md:1`, `codex-rs/exec/src/lib.rs:38-57` |
| Prompt payloads | The malformed PHP object `O:8:"stdClass":1:{s:4:"test";s:11:"injection";}` and the redirect target `https://attacker.site`, which a model may send as written | `codex-rs/core/web.md:75`, `codex-rs/core/client_side_web.md:48` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: ARTEMIS on a host, its prompt payloads in web and proxy logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: an ARTEMIS Codex sub-agent started |
| [`sigma/`](sigma) | 6 Sigma rules for process, file and web server logs |
| [`suricata/`](suricata) | 4 rules for the prompt example payloads |
| [`yara/`](yara) | Rules for the compiled Codex fork, the supervisor source, the specialist prompts and the session files |

What ARTEMIS does to a target looks like the stock tools it runs and like any agent, so the cross-framework rules in [`behaviors/`](../../behaviors) carry most of the target-side detection: model API calls from servers and Kali tools against your sites.

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `artemis`.

## Limits

- The fork-only options, file names and prompts are easy to change; the rules catch someone running the repository as published.
- The two prompt payloads are examples the model may or may not use; their absence proves nothing.
- Sub-agent child processes are whatever the model chose, so the child rule is useful for scoping a run, not for judging a single command.
- A match means ARTEMIS, not an attacker: it is research code run by researchers and security teams. Check who runs it and against which scope.
