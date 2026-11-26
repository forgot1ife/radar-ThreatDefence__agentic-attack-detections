# Clearwing Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Clearwing** ([Lazarus-AI-OSS/clearwing](https://github.com/Lazarus-AI-OSS/clearwing), formerly `Lazarus-AI/clearwing`, reviewed at `08fe47d2`, after v1.0.0), a Python tool that pairs a model-driven network pentest agent (Kali container, headless browser, Exploit-DB, payload obfuscation, a Python sleeper beacon and an operator mode that approves its own scans and, with a flag, its own exploits) with a source-code vulnerability hunter and a disclosure workflow. Public reports of its use in an intrusion were not searched for this draft, so this folder is built from the source code alone: it finds Clearwing testing you, Clearwing running on a host, and its web UI exposed.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What Clearwing leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax and conversion, Suricata rules against test flows, Sigma rules against test events, YARA against synthetic samples. Baseline every rule on your own data before alerting |

## What Clearwing leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| User agents | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Clearwing/1.0` (headless browser), `Mozilla/5.0 Clearwing/1.0` (bundle analyzer), `clearwing-asm/0.5 (+https://github.com/Lazarus-AI/clearwing)` (liveness probe) | `clearwing/agent/tools/recon/browser_tools.py:35`, `bundle_tools.py:39`, `discovery_tools.py:36` |
| Signed payloads | Scripts start with `### WATERMARK OPID:<id> SIG:<64 hex> ###`, default id `OP-IRONRAIN`; the system prompt says to sign every script and payload | `clearwing/exploitation/payloads/watermark.py:20`, `clearwing/agent/prompts.py:37` |
| Payload wrappers | XOR plus base64 `exec` stub, and a sleeper beacon polling `<c2>/checkin` and posting to `<c2>/result` | `clearwing/exploitation/payloads/obfuscator.py:34-39`, `beacon.py:16-48` |
| Callbacks | `http://<operator>:<9999-10008>/callback/<24-character token>` from your server; the listener binds `0.0.0.0` for 10 minutes | `clearwing/agent/tools/ops/callback_listener.py:107-131` |
| 1Password tools | `OP-User-Agent: 1|B|2248|clearwing|...` on Mycelium calls, `nonexistent-<8 hex>@invalid.test` on SRP enumeration, `recoveryCode` and `recovery_code` together on recovery probes | `clearwing/agent/tools/crypto/mycelium_tools.py:64`, `srp_tools.py:376`, `recovery_tools.py:157` |
| Host | `python3 <venv>/bin/clearwing scan|operate|sourcehunt|...`, container `clearwing-kali` (`kalilinux/kali-rolling`, host network), `~/.clearwing/` with audit logs of every command, Python reading the `Claude Code-credentials` keychain item on macOS | `pyproject.toml:112`, `clearwing/agent/tools/ops/kali_docker_tool.py:5,48-55`, `clearwing/core/config.py:19`, `clearwing/providers/openai_oauth.py:884-885` |
| Model clients | `clearwing (aiohttp openai fallback)`, `codex_cli_rs/0.0.0 (clearwing)` (reused ChatGPT login), a Claude Code user agent on a reused Claude login | `clearwing/llm/native.py:640,1421`, `clearwing/providers/openai_oauth.py:692-696` |
| Web UI | FastAPI on `127.0.0.1:8899` by default, `<title>Clearwing</title>` with the label `Target (IP / hostname / CIDR)`, no favicon, `GET /api/health` returns `{"status":"ok","service":"clearwing"}`; session data readable without the API key | `clearwing/ui/web/static/index.html:6,88`, `clearwing/ui/web/app.py:101-146` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Clearwing on a host, the watchlist sweep, and its user agents and callbacks in web and proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: the Clearwing command line on a host |
| [`sigma/`](sigma) | 5 Sigma rules: the command line, Python reading the Claude Code keychain item, its files, and its user agents in proxy and web logs |
| [`suricata/`](suricata) | Rules for its user agents, 1Password probes, exploit checks, signed and wrapped payloads, beacon, callbacks, model clients and an exposed web UI |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the source tree or installed package, signed payloads and payload wrappers |

Out-of-band lookups, attack tools started by an agent, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `clearwing`.

## Limits

- Most of its scanning runs nmap and other tools in the Kali container, or Python's default HTTP client, which these strings do not cover. The fixed user agents appear only on the browser, bundle and attack-surface tools.
- The watermark and the payload wrappers appear only when the agent uses those tools; the prompt asks it to, but the model decides.
- The web UI binds loopback unless the operator changes it; the sourcehunt webhook binds all interfaces but answers nothing distinctive.
- A match means Clearwing, not an attacker: it is published as a tool for authorized testing and research. Check who ran it and whether the test was agreed.
