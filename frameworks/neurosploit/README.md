# NeuroSploit Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **NeuroSploit** ([JoasASantos/NeuroSploit](https://github.com/JoasASantos/NeuroSploit), reviewed at `54d8e860`, November 24, 2026, workspace version 4.4.3, one release after `v4.4.2`), a Rust harness with a Node.js web console that runs reconnaissance, picks from about 490 specialist agent prompts, exploits a web target in parallel through model CLIs or APIs, replays every claim and has a second model vote on it. It has its own out-of-band listener and an opt-in C2 and web shell manager with beacons and persistence commands. No vendor or CERT report of NeuroSploit in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds NeuroSploit testing you, its payloads calling back from your servers, its beacons and persistence on hosts it took over, NeuroSploit running on a host, and its console exposed.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What NeuroSploit leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax, Suricata rules against test flows, YARA against the NeuroSploit source and the other agent code bases. Baseline every rule on your own data before alerting |

## What NeuroSploit leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| User agent and header | `NeuroSploit/<version>` and `X-NeuroSploit-Scan: <version>` on every request the harness sends itself, by default. The prompt tells the agents to keep the header when a WAF makes them switch to a Chrome 125 user agent | `harness/src/pipeline.rs:629-644,1062-1075` |
| First probe | `GET /nrsplt_baseline_404_check_9x7`, then `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/.git/config`, `/.env` | `harness/src/probe.rs:415-433` |
| Canaries | `NEUROSPLOIT<kind><12 hex>` (upper-case sigil): `/NEUROSPLOITsub<hex>` soft-404 checks, `NEUROSPLOITnsxss<hex>` in XSS payloads; open redirect host `neurosploit.example`; SSRF placeholder `http://oob.invalid/`; sign-ups as `nrsplt_<rand>@example.test` | `harness/src/validation.rs:327-355`, `harness/src/typesafe_agent.rs:84-133`, `harness/src/pipeline.rs:1315` |
| Out-of-band | Your servers look up or fetch `<token>.<operator domain>` where the token starts with `neurosploit`. The listener is the operator's own (`--oob-domain`, HTTP on `0.0.0.0:8080`); there is no public interaction server | `harness/src/oob.rs:136-161`, `harness/src/pipeline.rs:1205-1214` |
| Web shells and C2 | Web shell manager user agent `Mozilla/5.0 (compatible; NeuroSploit-WebShell/1.0)`, default password `ns_pass`; shells start `NeuroSploit WebShell`. Beacons `POST /api/beacon` with `X-Implant-Token`; persistence named `NSUpdate` (scheduled task, Run value, `nsupdate.service`) | `harness/src/c2/manager.rs:1036-1050,1406`, `harness/src/c2/templates.rs` |
| Host | `neurosploit` binary, `neurosploit c2 daemon --port 0 --dir .../.neurosploit/c2`, containers `neurosploit-kali` and `neurosploit-neo4j`, `claude -p ... --dangerously-skip-permissions` children, `<cwd>/.neurosploit/` (keys, vault, C2 state), `runs/ns-<time>-<target>/` | `app/src/main.rs:1726-1741`, `harness/src/models.rs:504-508` |
| Console | Plain HTTP on port 4173, all interfaces, **no authentication**; title `NeuroSploit — Console`; icon `logo.svg` with Shodan hash `-1162147578` (md5 `f8fb482e183c10bb03aaf940dde7b18c`) | `web/server.js:160,2870`, `web/public/index.html:6-7` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: NeuroSploit on a host, the watchlist sweep, its markers in web, proxy and DNS logs, and its beacons, persistence and web shells |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: a NeuroSploit scan reached a web server |
| [`sigma/`](sigma) | 9 Sigma rules: scan markers in web logs, user agents and out-of-band callbacks in proxy logs, callback lookups, the harness, Windows and Linux persistence, the Run key and its files |
| [`suricata/`](suricata) | Rules for its requests, canaries, out-of-band callbacks, web shell manager, beacons and an exposed console |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the binary and source, generated web shells, beacons and run output |

Out-of-band lookups to public services, attack tools started by an agent, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `neurosploit`.

## Limits

- The user agent is a setting (`NEUROSPLOIT_UA`, REPL `/ua`). The `X-NeuroSploit-Scan` header and the baseline probe path are in the code and stay unless the code is edited. Web server logs rarely record request headers, so the header is mostly a network signal.
- Commands the agents write themselves follow the prompt: the header, the sign-up address and the token prefix are instructions the model can drop.
- `NEUROSPLOIT_WATERMARK=off` removes the sigil from canaries (not from out-of-band tokens).
- A match means NeuroSploit, not an attacker: it is promoted to security teams and bug bounty hunters. Check who ran it and whether the test was agreed. The C2 features are off until the operator enables them with an authorization reference.
