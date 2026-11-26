# What MAPTA leaves behind

MAPTA ([arthurgervais/mapta](https://github.com/arthurgervais/mapta), two commits on August 28, 2025, reviewed at `0c167b86aedeb4f27745a84a8f7324518b0c960a`, "init", August 28, 2025; MIT; Python; 137 stars on November 26, 2026; not archived; no releases or tags; no README) is the open release of a multi-agent web application security agent. The GitHub description reads "We present MAPTA, a multi-agent system for autonomous web application security assessment that combines large language model orchestration with tool-grounded execution and end-to-end exploit validation". The repository holds three things: `main.py` (the agent, 1,105 lines), `analyze_logs.py` (plots and LaTeX tables for a paper) and `ctf-logs/` (104 benchmark runs against the XBOW validation benchmarks, 80 with a flag found, each a `trace.log` and a `metrics.json`, plus `ctf-logs/analysis_output/` with the PNG, PDF, HTML and LaTeX output of `analyze_logs.py`). `analyze_logs.py` reads hard-coded paths under one author's home folder (`analyze_logs.py:546,1030-1031`) and is not part of the agent. File references are to the repository at `0c167b86`. It is not on PyPI, npm or Docker Hub, and there is no hosted service.

The release is sanitised: the system prompt is replaced by `SYSTEM_PROMPT_REDACTED` (`main.py:1082`), the sandbox is left to a user-supplied factory (`main.py:25-27`), and `main.py` imports a `function_tool` module that is not in the repository (`main.py:11`). As published it does not run without that module. The benchmark logs in `ctf-logs/` come from a different, unreleased harness (tool names `e2b_run_command` and `e2b_run_python`, an `agents.result.RunResult` result type, output under `logs/`), not from `main.py`.

**Fragility** says what it takes to remove a signal: *code* means editing `main.py`, *config* means an environment variable, *operator* means a choice made at run time, *code (prompt)* means the model decides, steered by a prompt.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Launcher | `python main.py` with a `targets.txt` file (one URL per line, `#` comments) in the working directory. Without `targets.txt`, or with no valid line in it, the script prints a message and exits without scanning; the "single target mode" it mentions is not in the release | `main.py:1069-1105`, `main.py:837-855` |
| Settings | Environment only: `OPENAI_API_KEY` (read by the OpenAI client), `SANDBOX_FACTORY`, `SYSTEM_PROMPT`, `SANDBOX_SYSTEM_PROMPT`, `VALIDATOR_SYSTEM_PROMPT`, `SLACK_WEBHOOK_URL`, `SLACK_CHANNEL` (default `#security-alerts`). The Slack error text mentions a `.env` file, but nothing loads one | `main.py:17-18,22,27,517,601,1082,376` |
| Model | `AsyncOpenAI()` with no base URL, so `api.openai.com` unless `OPENAI_BASE_URL` is set. Every call is `client.responses.create(model="gpt-5", reasoning={"effort": "high"})` (the Responses API, `POST /v1/responses`) | `main.py:22,545-555,629-639,893-905` |
| Agents | Main agent (tools: `sandbox_agent`, `validator_agent`, the three mail tools, `send_slack_alert`, `send_slack_summary`), a sandbox agent and a validator agent (tools: `sandbox_run_command`, `sandbox_run_python`). Up to 100 rounds each, 50 for the validator. All targets in `targets.txt` are scanned in parallel | `main.py:507-589,591-669,885,1012-1025` |
| Request metadata | Each model request carries `metadata` with `name` set to `security_scan` (main agent, plus `site_name` and `target_url`), `sandbox_agent` or `validator_agent` | `main.py:550-554,634-638,898-904` |
| Sandbox | `SANDBOX_FACTORY="module:function"` must return an object with `.files.write(path, content)`, `.commands.run(cmd, timeout=..., user=...)` and optionally `.set_timeout()` and `.kill()`. Timeout set to 12000. One sandbox per target, killed at the end. Without a factory every tool call returns `Error: No sandbox instance available for this scan`. That interface and the `/home/user` home folder match the E2B sandbox SDK, and the benchmark logs name E2B tools, but the release names no provider | `main.py:25-68,866-871,947-950,960-961` |
| Shell tool | `sbx.commands.run(command, timeout=120, user="root")`: the model's command, as root, in the sandbox | `main.py:728-777` |
| Python tool | Writes the model's code to `/home/user/temp_script_<8 hex>.py` and runs `source .venv/bin/activate && python3 /home/user/temp_script_<8 hex>.py` as root | `main.py:671-725` |
| Mail tools | `GET https://api.mail.tm/messages` and `/messages/<id>` with a stored JWT. Nothing in the release creates a mail.tm account or stores a token (`email_token_store` is never written), so these calls never happen as published | `main.py:146-234` |
| Slack | When `SLACK_WEBHOOK_URL` is set, `send_slack_alert` and `send_slack_summary` post JSON to it with `"username": "Security Scanner Bot"`, `"icon_emoji": ":shield:"`, headers `<emoji> <type> Vulnerability Detected` and `<emoji> Security Scan Summary` | `main.py:237-377,380-504` |
| Web UI, API, telemetry | None. No listening socket, no update check, no tunnel, no MCP | whole repository |

## Signals on the target side

MAPTA has no hard-coded user agent, header, canary string, test account, payload marker or callback domain. The model writes every command, steered by a system prompt that is not published.

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Source address | Traffic comes from the sandbox, not from the operator's host. With a cloud sandbox (the authors used E2B, see `ctf-logs/`) that is the provider's address space | `main.py:728-777`, `ctf-logs/*/metrics.json` | Operator |
| Tools seen in the authors' runs | In the 104 shipped benchmark traces (2,260 shell commands), by first word: `curl` 1,463 (mostly `curl -i` / `curl -s -i`, often with a `cookies.txt` jar), `bash` 612 (`bash -lc` loops), `gobuster` 15, `ffuf` 11, `feroxbuster` 6, `nmap` 2, `dirb` 2, `wpscan` 1; no `sqlmap`. Default user agents. One-off test user agents such as `XSS-Header-Test` appear once and are model-chosen | `ctf-logs/*/trace.log` | Code (prompt) |
| User prompt | `I need you to do a full vulnerability scan of {target_url}, you must critically analyse the code and identify every single vulnerability, ... i m only insterested in real world vulnerabilities, not theoretical ones` (with the typos). Sent to the model, never to the target | `main.py:1099` | Code |

## Signals on a host that runs MAPTA

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Launcher | `python main.py` (or `python3 main.py`) in a folder holding `targets.txt` | `main.py:1069-1102` | Operator |
| Run log | `scan_usage.log` in the working directory, appended on every run, with lines such as `Main Agent Usage - Target: <url>, Usage: ...`, `Sandbox Agent Usage - Target: <url>, Usage: ...`, `Usage data saved to <file>`, and `Sandbox factory not configured; running without a sandbox.`. The `httpx` library also logs its requests here at INFO (`HTTP Request: POST https://api.openai.com/v1/responses ...`): library behavior, not checked on a live run | `main.py:1073-1080,86,97,118,51` | Code |
| Usage file | `<site>_usage_log_<YYYYMMDD_HHMMSS>.json` per target in the working directory, JSON with `scan_duration`, `main_agent_calls`, `sandbox_agent_calls`, `total_calls`, `main_agent_usage`, `sandbox_agent_usage`, entries with `"agent_type": "main_agent"` / `"sandbox_agent"` | `main.py:99-119,988-989` | Code |
| Report file | `<target without scheme, / replaced by _>.md` per target in the working directory (for example `app.example.test.md`) | `main.py:980-985` | Code |
| Inside the sandbox | Root process `python3 /home/user/temp_script_<8 hex>.py` started through `source .venv/bin/activate && ...` (a bash builtin, so the parent is a shell), and the file `/home/user/temp_script_<8 hex>.py` written before it. Only visible where the sandbox is local (a self-hosted Docker or VM sandbox) and watched by an EDR; with a cloud sandbox it happens off your network | `main.py:691-700` | Code |
| Clone on disk | `main.py`, `analyze_logs.py`, `LICENSE` and `ctf-logs/XBOW <n>_<timestamp>/{trace.log,metrics.json}`. SHA-256 of `main.py` at `0c167b86`: `ca65f7e688c70b8fca4445b8e769d616a870deb7341ea5ab4f648a0cbc5361b8`; of `analyze_logs.py`: `bb0d464c03de35f0457f0fd3390263bb86e4dd2ab73d33bf3566d02671bb7fd8` | `git ls-tree` at `0c167b86` | Code |
| Environment | `SANDBOX_FACTORY`, `SANDBOX_SYSTEM_PROMPT`, `VALIDATOR_SYSTEM_PROMPT`, `SYSTEM_PROMPT` in the process environment | `main.py:27,517,601,1082` | Code |

## Network signals from the host

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Model API | HTTPS to `api.openai.com`, `POST /v1/responses`, model `gpt-5`, many long requests per target. With TLS inspection the request body shows `"metadata": {"name": "security_scan", "site_name": ..., "target_url": ...}` and the default prompts `You are an agent that autonomously interacts with an isolated sandbox using two tools` and `You validate security PoCs inside an isolated sandbox using two tools` | `main.py:517-524,601-611,893-905` | Config (base URL), code (body) |
| Slack webhook | HTTPS POST to the operator's `SLACK_WEBHOOK_URL` (normally `hooks.slack.com`) with `"username": "Security Scanner Bot"` when a finding is reported | `main.py:348-367,478-494` | Config |
| Sandbox provider | Not in the code: whatever the `SANDBOX_FACTORY` module calls | `main.py:25-68` | Operator |
| mail.tm | `api.mail.tm` is in the code but not reachable as published (no token is ever stored) | `main.py:147,177,219` | Code |

## Exposure on the internet

None. MAPTA opens no port and has no web UI or API. `exposure/shodan-queries.csv` and `exposure/consoles.csv` get no rows.
