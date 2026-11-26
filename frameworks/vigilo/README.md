# Vigilo Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Vigilo** ([certeu/vigilo](https://github.com/certeu/vigilo), reviewed at `82c2d353`, November 25, 2026, release `v1.0.0`), a multi-user platform published by CERT-EU for AI-driven security assessment of applications the operator is responsible for. In white-box mode, coding agent CLIs review a repository, prove findings against a running copy and write fix branches. In grey-box mode, one reasoning agent assesses a running web application, API or network segment through Vigilo's own scope-checked tools. Vigilo is a defensive tool, and its grey-box traffic names itself as an authorised test. This folder helps a SOC recognise an agreed Vigilo assessment, confirm that a test reaching it was agreed, find Vigilo running on a host, and find Vigilo instances exposed to the internet.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What Vigilo leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Built from the source code at one commit. Baseline every rule on your own data before alerting |

## What Vigilo leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Grey-box user agent | `Vigilo-Greybox/1 (authorised security test)` on every grey-box request, the headless browser's included | `src/greybox_web/netguard.py:153,822-830` |
| Grey-box markers | Header `X-Note-Name: vigilo<8 hex><e>` on crawled pages; reflection canary `vgl<8 hex>"'<>b`; probe host and origin `https://vigilo-probe-<8 hex>.invalid`; soft-404 path `/vgl-<8 hex>`; a failed login with `vgl<8 hex>` as both user and password before each login; `vigilo-callback-<8 hex>`; multipart boundary `vigilo-<8 hex>`; GraphQL `VigiloInvoke`; JSON-RPC id `vigilo-<8 hex>`; SMTP `EHLO vigilo.invalid` | `src/greybox_web/tools/` |
| White-box preflight | `HEAD <target>` with `User-Agent: Vigilo-Preflight/1.0` at the start of each run. After that the agents use curl, a browser, WhatWeb and schemathesis with their own user agents | `src/temporal/activities.py:921-936` |
| Host | `python -m src.webapi.main`, `python -m src.greybox_web.worker`, `src.temporal.worker --task-queue vigilo-…`; `claude -p` children whose prompt contains `authorised security assessment run by Vigilo` and `--dangerously-skip-permissions`; `vigilo-record` and `save-deliverable` commands; `<repo>/.vigilo/<session>/deliverables/` and `.vigilo-remote-url` | `src/ai/claude_executor.py:170-182`, `src/audit/session.py:32` |
| Exposed instance | UI title `Vigilo` with nginx's CSP ending `frame-ancestors 'none'`, no favicon; API on 8080 with `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` and `/health` `{"status":"ok"}`. JWT login, no default account | `web/index.html:6`, `web/nginx.conf:61-67`, `src/webapi/security_headers.py:11` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Vigilo on a host, the watchlist sweep, and its markers in web and proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: a Vigilo assessment reached a web server |
| [`sigma/`](sigma) | 4 Sigma rules: grey-box markers in web logs, its user agents in proxy logs, the platform's processes, and its files |
| [`suricata/`](suricata) | Rules for its user agents, markers, probes, network-mode greeting and an exposed UI or API |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the source and installed code, and for the deliverables and defenses it writes |

Model traffic from servers, attack tools started by an agent and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `vigilo`.

## Limits

- The grey-box markers are in the code, not in prompts, so they appear on every run until the code is changed. White-box agents carry no marker after the preflight request.
- A match means a Vigilo assessment. Vigilo is meant to be pointed at systems the operator is responsible for; check with the application owner that the test was agreed and that it came from the declared source.
- The UI title `Vigilo` is a common word. Use the title together with the CSP header, and expect few matches: the full deployment is reachable only by its host name.
