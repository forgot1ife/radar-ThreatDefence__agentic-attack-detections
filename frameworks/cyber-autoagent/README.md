# Cyber-AutoAgent Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Cyber-AutoAgent**, an open-source Python agent on the AWS Strands Agents SDK with a React/Ink terminal front end. One agent works through a penetration test with a shell, an HTTP client, a Python REPL, sub-agent swarms and Python tools it writes and loads for itself, inside a Kali container, and a second agent writes the report. Tool confirmations are off by default. It defaults to Anthropic Claude Sonnet 4.5 on AWS Bedrock and also runs on Ollama or anything LiteLLM reaches. Its compose file starts a Langfuse observability stack on `0.0.0.0:3000` with a fixed login. The project was archived on GitHub after its last commit in November 2025. No vendor or CERT report of Cyber-AutoAgent in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone.

| | |
|---|---|
| Tool | [westonbrown/Cyber-AutoAgent](https://github.com/westonbrown/Cyber-AutoAgent) (archived, MIT), reviewed at `54897ff9`, release v0.1.3. No published image or package: operators build `cyber-autoagent:latest` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What Cyber-AutoAgent leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax and conversion, Suricata rules against crafted flows, KQL against the table reference, YARA against the Cyber-AutoAgent source. Baseline every rule on your own data before alerting |

## What Cyber-AutoAgent leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Agent command | `python /app/src/cyberautoagent.py --module general --objective via environment --target <t> --iterations 100 --provider bedrock --output-dir /app/outputs --keep-memory`; the placeholder `via environment` is on every run the front end starts | `src/modules/interfaces/react/src/services/DirectDockerService.ts:158-177` |
| Blind XSS callback | `dalfox ... -b https://dalfox-xss-test.com`, so that name reaches your site in dalfox payloads, and is looked up if one runs | `src/modules/operation_plugins/general/tools/advanced_payload_coordinator.py:319-330` |
| Langfuse key | `Authorization: Basic Y3liZXItcHVibGljOmN5YmVyLXNlY3JldA==` (`cyber-public:cyber-secret`) on trace exports to `/api/public/otel/v1/traces` and prompt fetches from `/api/public/v2/prompts/cyber/system/...` | `src/cyberautoagent.py:180-191`, `src/modules/prompts/factory.py:41-47`, `:105` |
| Exposed Langfuse | Langfuse on `0.0.0.0:3000` with the seeded login `admin@cyber-autoagent.com` / `changeme` and project `cyber-project-id` (`penetration-tests`); MinIO on 9090 and 9091 with `minio` / `miniosecret` | `docker/docker-compose.yml:105-212`, `:330-340` |
| Files | `outputs/<target>/OP_<YYYYMMDD_HHMMSS>/cyber_operations.log`, `security_assessment_report.md`, `~/.cyber-autoagent/config.json` | `src/cyberautoagent.py:435-447`, `react_bridge_handler.py:2793` |
| Emulation markers | `.emulation_marker_<TTP_ID>` files, `HKLM\SOFTWARE\EmulationMarkers\` keys and `emu_` accounts on hosts it reaches in the threat emulation module (prompt, so the model may vary them) | `src/modules/operation_plugins/threat_emulation/execution_prompt.md:49-55` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: Cyber-AutoAgent on a host, watchlist sweep, its markers in web and proxy logs, and threat emulation markers on hosts it reached |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: Cyber-AutoAgent on a host |
| [`sigma/`](sigma) | 8 Sigma rules for process, file, registry, DNS, proxy and web server logs |
| [`suricata/`](suricata) | Rules for the dalfox callback, the agent's Langfuse traffic and an exposed Cyber-AutoAgent Langfuse |
| [`yara/`](yara) | Rules for the source, the system prompt, the compose file and the front end's settings file |
| Docs | [What Cyber-AutoAgent leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |

What Cyber-AutoAgent sends to a target is mostly stock Kali tools and curl chosen by the model, with no user agent of its own, so the cross-framework rules carry most of the target-side detection: model API calls from servers (hunt 02), rotating proxies (hunt 04) and out-of-band lookups from your servers (hunt 09) in [`behaviors/`](../../behaviors).

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `cyber-autoagent`.
