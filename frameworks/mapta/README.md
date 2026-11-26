# MAPTA Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**MAPTA** ([arthurgervais/mapta](https://github.com/arthurgervais/mapta), reviewed at `0c167b86`, August 28, 2025). Multi-agent web application security agent released by Arthur Gervais as the code of a research paper. A main agent on OpenAI `gpt-5` hands work to a sandbox agent and a validator agent, which run shell commands and Python scripts as root in a sandbox the operator supplies; findings can be posted to a Slack webhook. It scans every URL in `targets.txt` in parallel.

MAPTA is one Python script with no web interface, no API server and no listening port, so there is nothing to find on the internet. The public release is sanitised: the system prompt is redacted, the sandbox is left to the operator, and a helper module it imports is missing. It sends no fixed user agent, marker or callback to a target: the target sees curl and stock web scanners from the sandbox's address. The useful signals are the files it writes where it runs and the scripts it runs inside a local sandbox. No vendor or CERT report of MAPTA in a real intrusion was found on November 26, 2026.

| | |
|---|---|
| Tool | [arthurgervais/mapta](https://github.com/arthurgervais/mapta), reviewed at `0c167b86`. Not on PyPI or Docker Hub |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, YARA |
| Docs | [What MAPTA leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the source code and the benchmark logs it ships, not from captured runs. Baseline every rule on your own data before alerting |

## What MAPTA leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Run log | `scan_usage.log` in the working directory with `Main Agent Usage - Target: <url>, Usage: ...` and `Sandbox Agent Usage - Target: <url>, Usage: ...` lines | `main.py:86,97,1073-1080` |
| Output files | `<site>_usage_log_<YYYYMMDD_HHMMSS>.json` and `<target>.md` per target, next to `targets.txt` | `main.py:110-119,980-989` |
| Sandbox Python runner | `source .venv/bin/activate && python3 /home/user/temp_script_<8 hex>.py`, as root, after the script is written to that path | `main.py:691-700` |
| Model traffic | `POST /v1/responses` to `api.openai.com`, model `gpt-5`, with `metadata.name` `security_scan`, `sandbox_agent` or `validator_agent` | `main.py:545-555,893-905` |
| Slack reports | Webhook posts as `Security Scanner Bot` with `... Vulnerability Detected` and `Security Scan Summary` headers | `main.py:283-361,425-491` |
| Prompts | `i m only insterested in real world vulnerabilities, not theoretical ones` (user prompt, with its typos) and the default sandbox and validator prompts | `main.py:517-524,601-611,1099` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: MAPTA on a host, its model and webhook traffic in proxy logs, and the watchlist sweep |
| [`sigma/`](sigma) | 2 Sigma rules: the sandbox Python runner and the files MAPTA writes |
| [`yara/`](yara) | Rules for the MAPTA source, its run log and usage files, and the benchmark logs it ships |

There are no Suricata rules: MAPTA puts nothing fixed on the wire in clear text, and its only own hosts (`api.mail.tm`) are unreachable in the released code. There is no analytics rule: no signal is both specific and quiet enough. What MAPTA does to a target looks like curl and stock scanners, so the cross-framework rules in [`behaviors/`](../../behaviors) carry the target-side detection.

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `mapta`.

## Limits

- The release does not run as published (`from function_tool import function_tool`, `main.py:11`, has no module in the repository) and has no system prompt. Anyone running it has edited or extended it, so file names and log lines may have changed.
- The sandbox runner is visible only when the sandbox is local and monitored. With a cloud sandbox (the authors' logs show E2B), the scripts and the attack traffic run off your network.
- A match means MAPTA, not an attacker: it is research code. Check who runs it and against what.
