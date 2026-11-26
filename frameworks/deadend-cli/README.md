# Deadend CLI Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Deadend CLI** ([straylabs-ai/deadend-cli](https://github.com/straylabs-ai/deadend-cli), formerly `xoxruns/deadend-cli`, reviewed at `34e83717`, August 7, 2026, and at its last tag `v0.1.15`, April 11, 2026), an autonomous web application penetration testing agent. A Bun terminal UI (`deadend`) drives a Python JSON-RPC backend over stdin and stdout. The backend sends model-written raw HTTP requests through Playwright, runs shell commands in a Kali container (`xoxruns/sandboxed_kali`) and runs Python payloads in a separate sandbox. Its default execution mode is `yolo`: no step waits for approval. It has no listener and no web console. No vendor or CERT report of Deadend CLI in a real intrusion was found on November 26, 2026, so this folder is built from the source code and from the project's own published benchmark logs: it finds Deadend CLI testing you and Deadend CLI running on a host.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What Deadend CLI leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Suricata rules checked for syntax and written with a case and a near miss each; YARA strings checked against the source files at `34e83717` and run against this repository (no matches). Baseline every rule on your own data before alerting |

## What Deadend CLI leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Reflection marker | `deadend7x7probe` in a parameter (the project's logs show `GET /page?test=deadend7x7probe`) | `deadend_prompts/_shared/_vulnerability_playbooks.jinja2:450` |
| Test account | Login and sign-up requests with `deadendtester` / `deadendpassword123!` / `hacker@straylabs.ai` (the wallet's real values, swapped in for the dummy `deadenduser` / `deadendpassword` / `deadenduser@straylabs.ai` before sending). Requests sent with curl or Python keep the dummy values | `data/reusable_credentials.json:4-10`, `browser_automation/auth_handler.py:23-60` |
| Placeholders (this commit) | At `34e83717` the prompts give the model `<dummy_username>`, `<dummy_password>`, `<dummy_email>`, which the swap does not replace, so they reach the target as written (inferred) | `requester.instructions.jinja2:365,377` |
| Host | `~/.cache/deadend/bin/deadend.sh --log-file ~/.cache/deadend/logs/rpc-server-<ms>.log` (or `uv run python -m deadend_cli.jsonrpc_server`); `~/.deadend/reusable_credentials.json` copied on every start; `requester.jsonl` and `python_interpreter.jsonl` under `~/.cache/deadend/logs/`; Docker image `xoxruns/sandboxed_kali` | `cli/deadend/src/runtime/server-launcher.ts:65-107`, `deadend_agent/constants.py:24-37`, `component_manager.py:773-775` |
| Telemetry | Opt-in Phoenix traces to `https://crunch.straylabs.ai/v1/traces` when `DEADEND_PHOENIX_OTEL_ENABLED=true` and no endpoint is set | `jsonrpc_server.py:235-239,304-322` |
| Console | None. The backend reads JSON-RPC from stdin; the sandbox container publishes no port | `jsonrpc/rpc_server.py:232-240` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Deadend CLI on a host, its markers and setup traffic in web, proxy and DNS logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: the Deadend CLI backend or its credential wallet on a host |
| [`sigma/`](sigma) | 5 Sigma rules: the backend process, its wallet and session files, its image pull, release download and trace collector in proxy logs, its marker in web logs, and the collector lookup |
| [`suricata/`](suricata) | 8 rules: marker, test account, placeholders and example header on targets; trace collector by SNI and DNS |
| [`yara/`](yara) | Rules for the source or package and for the credential wallet |

Out-of-band lookups, attack tools started by an agent, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `deadend-cli`.

## Limits

- The marker and the test account come from prompts and a wallet file. The model may skip the marker, and an operator can edit `~/.deadend/reusable_credentials.json` (it is overwritten from the package on each start, so editing the package is needed to keep a change).
- Its HTTP user agents are ordinary browser strings (`Chrome/131.0.0.0` and `Chrome/120.0.0.0` on Windows 10). Do not use them to find Deadend CLI.
- Shell traffic from the Kali sandbox is nmap, ffuf, nikto, sqlmap and curl, which looks like any scanner.
- A match means Deadend CLI, not an attacker. Check who ran it and whether the test was agreed.
