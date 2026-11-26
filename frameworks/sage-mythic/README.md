# Sage (Mythic) Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Sage** ([MythicAgents/sage](https://github.com/MythicAgents/sage), reviewed at `cbff42f0`, November 23, 2026, version 0.4.0), an AI operator that installs into a Mythic C2 server as a chat container. It reads the operation's callbacks, tasks, credentials and files and a BloodHound CE graph, and proposes each next step as a Mythic task; in supervised mode a task runs after the operator accepts it, and an experimental auto mode runs without per-action approval. Everything that reaches a target is executed by a Mythic payload callback (the project has qualified Apollo only). No vendor or CERT report of Sage in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds the commands and files Sage's tasks leave on Windows hosts, Sage running on a Mythic server, its model and Mythic API traffic, and its embedded Phoenix trace UI exposed.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What Sage leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Written from the source code; Suricata rules have test flows and Sigma rules have test events. Baseline every rule on your own data before alerting |

## What Sage leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Proof markers | Default markers `SAGE_REMOTE_EXEC_PROOF_<host>_<callback>`, `SAGE_EP_ADJUST_PROOF_`, `SAGE_CA_EXPORT_PROOF_`, `SAGE_CERT_ENROLL_PROOF_`, `SAGE_CERT_AUTH_PROOF_` in the commands and PowerShell its tasks run | `ai/langgraph/capabilities.py`, `mythic_capability_adapter.py` |
| Files on targets | `C:\Windows\Temp\sage_remote_exec_<host>_<cb>.txt`, `sage_ep_adjust_`, `sage_ca_export_<slug>.pfx` and `_backup\`, `sage_ca_dpapi_`, `sage_forged_cert_`, `sage_ca_signing_`; `C:\Users\Public\sage_gpo_<slug>_whoami.txt`; `%TEMP%\sage_cert_enroll_<slug>\request.inf` | same |
| Commands on targets | `schtasks.exe /Create ... /TN "SageExec_..."`; `certutil.exe -f -p SagePfx-v1-... -backupKey ...\sage_ca_export_..._backup`; `New-PSDrive -Name SAGEPROOF` / `SAGEEP` / `SAGECA`; `Set-MpPreference -DisableRealtimeMonitoring $true` with `Add-MpPreference -ExclusionPath C:\Windows\Temp` | same |
| Mythic host | Container `sage`, image `ghcr.io/mythicagents/sage`, `python3 /usr/local/bin/sage-entrypoint`, `uv --directory /opt/bloodhound_mcp run --no-sync main.py`, `InstalledServices/sage/sage.db` and `.phoenix/phoenix.db`, banner `Sage build_commit=... source_fp=... version=...` | `Dockerfile`, `main.py`, `_version.py` |
| Network | GraphQL to Mythic named `sageWhoamiScopes`, `SageReconcileTasks`...; prompts `you drive all Mythic C2 operations and in-memory offensive tradecraft`; Slack text `Sage findings changed. Open Mythic to review.`; SharpHound 2.13.0 fetched by python-requests | `mythic_tools.py`, `prompts/`, `sage_chat/findings_slack.py` |
| Exposure | Embedded Arize Phoenix on 6006 (OTLP 4317), no login by default, title `Phoenix`; its API returns Sage's `sage.kernel.*` spans with full prompts and tool results. Sage has no web console of its own | `main.py:114` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: Sage on a Mythic host, Sage's tasks on your Windows hosts, Phoenix and model traffic in web and proxy logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: a Sage proof marker, proof file or `SageExec_` task in a process command line |
| [`sigma/`](sigma) | 7 Sigma rules: proof commands, the `SageExec_` task, the encoded marker script, proof files on Windows, the Sage container processes and state files on Linux, and the SharpHound fetch |
| [`suricata/`](suricata) | Rules for the Phoenix UI and Sage traces, Sage's Mythic GraphQL queries, prompts and tool names in model requests, the Slack notice and the SharpHound fetch |
| [`yara/`](yara) | Rules for the Sage source and prompts, proof files on targets, and a Phoenix database holding Sage traces |

Out-of-band lookups, attack tools started by an agent, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `sage-mythic`.

## Limits

- Sage is a red-team tool for the Mythic C2 framework. A match means Sage, not an attacker: check who runs the Mythic server and whether the engagement was agreed.
- The markers and file names are defaults the code fills in. The model or the operator can pass another marker, path, task name or command, and the stock tools Sage tasks (Mimikatz, Rubeus, SharpHound, certutil, schtasks, wmic) look the same from any operator.
- The C2 traffic between Mythic and its payloads belongs to the payload type and is not covered. The network rules on GraphQL, prompts and Slack need TLS decryption.
- The Phoenix page and favicon belong to arize-phoenix and match any Phoenix server. Only responses that carry `sage.kernel.` spans are Sage's.
- Mythic, its payload types and the BloodHound MCP server were not read for this review.
