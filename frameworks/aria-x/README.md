# ARIA-X Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **ARIA-X** ([01NGVI-QINGYI/ARIA-X](https://github.com/01NGVI-QINGYI/ARIA-X), reviewed at `015e197`, November 25, 2026, v0.3.0), an LLM-driven security testing engine written on the Python standard library only. Its README presents it as a fusion of the designs of ARTEX, Cairn and PentAGI (a blackboard of facts and intents, a planner with a todo chain, specialist roles and a sandboxed terminal), but it is a new implementation: none of their code, strings or infrastructure is in it, so the [ARTEX](../artex), [Cairn](../cairn) and [PentAGI](../pentagi) rules do not find it, apart from ARTEX's hunts for anything listening on port 8787. It has a web console and API on port 8787 (loopback by default, all interfaces in its Docker image, no authentication unless a token is set), drives targets through its own Python HTTP, port-scan and TLS tools, and runs model-written shell commands on the host or in one-shot Kali containers. Its shipped configuration uses DeepSeek. No vendor or CERT report of ARIA-X in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What ARIA-X leaves behind](source-code-signals.md), with a file and line for every signal and the check of the ARTEX, Cairn and PentAGI rules |
| Status | Experimental. Suricata rules tested against test flows, Sigma rules against test events, YARA against the strings of the ARIA-X source. Baseline every rule on your own data before alerting |

## What ARIA-X leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Targets | User agent `ARIA-X/0.3.0 (authorized security research)` on every request of its HTTP tools (`ARIA-X/0.1 (...)` before v0.2.1); `web_probe` asks for `/`, `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/login`, `/admin`, `/api`, `/health` | `src/aria_x/tools/net.py:40,215,577-578` |
| Console | Port 8787, `<title>ARIA-X · Engagement Console</title>`, `Server: ARIA-X/0.3.0`, no favicon (`/favicon.ico` answers 204), `/api/config` with `"tagline": "Autonomous Reasoning & Investigation Agent, eXtended"` and `"auth_required": false` when no token is set, 401 with `WWW-Authenticate: Bearer realm="ARIA-X"` when one is | `src/aria_x/web/index.html:8`, `src/aria_x/server/app.py:211-215,280-283,303-307` |
| Host | `python -m aria_x serve --host 0.0.0.0 --port 8787` in its image; `aria-x run --goal ...`; `bash -lc <command>` children with `ARIA_X_SANDBOX=1`; or `docker run --rm -i --name aria-x-<12 hex> ... -v <run>/work:/work -w /work kalilinux/kali-rolling bash -lc <command>` | `docker/Dockerfile:50-51`, `src/aria_x/tools/sandbox.py:163-165,217-224,278` |
| Files | `data/aria-x.db`, `runs/run_<12 hex>/work/evidence/http_<date>_<time>_<n>.json` (with the user agent), `runs/run_<12 hex>/report.html`, `configs/aria-x.toml` | `src/aria_x/config.py:438`, `src/aria_x/tools/net.py:120-130`, `src/aria_x/engine/orchestrator.py:1363-1365` |
| Network | `api.deepseek.com` by default (also OpenAI, Anthropic, Ollama); `html.duckduckgo.com` for its research search, with the ARIA-X user agent; no telemetry | `src/aria_x/config.py:67-75`, `src/aria_x/tools/net.py:679-682` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: ARIA-X on a host, its user agent and console API in web and proxy logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: the ARIA-X user agent reached a web server |
| [`sigma/`](sigma) | 4 Sigma rules: web server, proxy, process creation and file events |
| [`suricata/`](suricata) | Rules for its user agent on targets, and for its console page, Server header, API realm, configuration response, and engagement and run creation through the API |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for its source and console files, and the evidence records and reports a run writes |

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `aria-x`.

## Limits

- The user agent is the one strong target-side signal, and the model can replace it through the `headers` argument of `http_request`. Commands it runs in a shell (curl, nmap, sqlmap, msfconsole in the Kali image) carry their own fingerprints; use the cross-framework rules in `behaviors/`.
- ARIA-X has no telemetry, update check or hosted service, and nothing in it names infrastructure of its own.
- A match means ARIA-X, not an attacker: it is published for authorized testing. Check who ran it and whether the test was agreed. An exposed console without a token is a risk in itself, because anyone who reaches it can start runs whose commands execute on that host.
