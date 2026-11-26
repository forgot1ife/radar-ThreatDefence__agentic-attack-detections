# Agentic Bug Hunter Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Agentic Bug Hunter** ([awarexone/Agentic-Bug-Hunter](https://github.com/awarexone/Agentic-Bug-Hunter), reviewed at `82f4512e`, package version 6.0.1, PyPI `agentic-bug-hunter`), a bug bounty toolkit of about a hundred Python and shell scripts that a coding assistant (Claude Code, Codex, OpenCode, Gemini/Antigravity) drives through skills and slash commands, or that its own ReAct agent and CLI (`bughunter`, `bughunter-agent`) run against a target with any of 17 model providers. It covers recon, scanners with fixed verifiers, a company-wordlist and password spray chain, and a local web dashboard. No vendor or CERT report of its use in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds the toolkit testing you, running on a host, and its dashboard exposed.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What Agentic Bug Hunter leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Suricata rules tested against test flows, Sigma rules against test events, YARA strings checked against the source. Baseline every rule on your own data before alerting |

## What Agentic Bug Hunter leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Scanner user agents | `agentic-bug-hunter/<tool>` on its verifiers and its CORS, CRLF, NoSQL injection, DOM XSS, LLM red-team and PoC scripts | `bughunter/tools/verifiers/base.py:31` and the scanners |
| Password spray | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Bug-Bounty-Research` on every attempt and on the cewler crawl that builds the password list; one password across all users per round, rounds 30 minutes apart by default; `grant_type=password` in OAuth mode | `bughunter/tools/_spray_http_form.py:57`, `_spray_oauth.py:56`, `spray_orchestrator.sh:34-35` |
| Probe strings | `/?_waftest=`, `Set-Cookie:crlftest=1`, `window.__cbbx('cbbx<10 hex>')`, `RT_PWNED_<8 hex>`, `RCE-VAL-` in `proof_<time>.php`, `/saml-control-<n>`, `/non_existent_<time>`, `nouser@example.invalid` / `definitely-wrong-pw` | `bughunter/tools/` scanners and `vuln_scanner.sh` |
| Callbacks | DNS lookups of `ssrf-`, `xxe-`, `sqli-`, `rce-` or `log4j-` followed by 12 hex characters in front of an interactsh host | `bughunter/tools/oob_listener.py:51-101` |
| Host | `bughunter`, `bughunter-agent`, `bughunter mcp serve`, `bughunter/tools/*.sh`; `~/.bughunter/`, `~/.cache/bbhunt/scope/`, `hunt-memory/`, `recon/<target>/spray/attempts-*.jsonl`; skills such as `~/.claude/skills/johnwick/` | `bughunter/engine.py:65-78`, `install.sh` |
| Model traffic | `HTTP-Referer: https://github.com/Awarexone/Agentic-Bug-Hunter` and `X-Title: BugHunter` to OpenRouter, OrcaRouter, Fluxion and Requesty | `bughunter/brain.py:476-530` |
| Dashboard | Plain HTTP on `127.0.0.1:8777`, no auth, title `Hunt Dashboard`, footer `Agentic Bug Hunter · local dashboard`; reached by IP on a wildcard bind it answers `403 forbidden: unrecognized Host (DNS-rebinding guard)` | `bughunter/tools/hunt_dashboard.py:397,407,497` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: the toolkit on a host, the watchlist sweep, its markers in web and proxy logs, and its spray in Entra ID sign-in logs |
| [`sentinel/analytics/`](sentinel/analytics) | Its user agents in web, proxy or sign-in logs |
| [`sigma/`](sigma) | 6 Sigma rules: web markers, proxy user agents, toolkit processes, the spray chain, its files, and out-of-band marker lookups |
| [`suricata/`](suricata) | Rules for its user agents, spray, probe strings, callback lookups, the dashboard and model gateway headers |
| [`yara/`](yara) | Rules for its source or package, and for the spray log, evidence HAR and dashboard export it writes |

Out-of-band lookups to public interactsh servers, attack tools started by an agent, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `agentic-bug-hunter`.

## Limits

- The shell scanners (`vuln_scanner.sh`, `bypass_403.sh`, `recon_engine.sh`) and the third-party tools use curl's, httpx's or nuclei's own user agents. Only their probe strings are fixed.
- In coding-assistant mode the model may write its own requests from the skills; those carry whatever the assistant chooses.
- A match means Agentic Bug Hunter, not an attacker: it is promoted to bug bounty hunters. Check who ran it and whether the program allows it. A password spray against your sign-in pages needs attention either way: most programs forbid it.
