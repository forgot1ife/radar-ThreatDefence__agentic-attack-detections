# numasec Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **numasec** ([FrancescoStabile/numasec](https://github.com/FrancescoStabile/numasec), npm `numasec`, reviewed at `1237a2f`, May 8, 2026, release v1.2.1), a TypeScript terminal agent for application security and penetration testing that drives the tester's local tools (nmap, sqlmap, nuclei, ffuf through its shell tool) and adds its own scanners, an AppSec probe, a browser, an out-of-band helper and a store for findings, evidence and reports. Its code is OpenCode renamed to numasec, with the security parts added; the [signals document](source-code-signals.md) keeps what is numasec's own apart from what it inherits from OpenCode. No vendor or CERT report of numasec in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What numasec leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Suricata rules tested against test flows written from the source. Baseline every rule on your own data before alerting |

## What numasec leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| AppSec probe | `User-Agent: numasec-appsec-probe/1.2`, `<script>numasec-xss</script>`, `' OR 1=1--`, a login as `numasec-probe@example.invalid` / `numasec-probe`, `Origin: https://evil.example` | `src/tool/appsec-probe.ts` |
| Directory fuzzer | `GET /numasec_404_check_<epoch ms>` before every run, then a built-in wordlist with OWASP Juice Shop routes | `src/scanner/dir-fuzzer.ts:20-123` |
| Service prober | Raw `GET / HTTP/1.1` with only `Host: target` on ports that stay silent | `src/scanner/service-prober.ts:25` |
| Page fetch | `User-Agent: numasec` when a Cloudflare challenge blocks its Chrome 143 string | `src/tool/webfetch.ts:99` |
| Operator traffic | `numasec-knowledge-broker/1.2` to NVD, CISA KEV, EPSS, OSV and GitHub advisories; `numasec/<version>` to model APIs; `numasec/latest/<version>/cli` to models.dev | `src/core/knowledge/broker.ts:39`, `src/session/llm.ts:369`, `src/installation/installation.ts:57` |
| Host | `numasec` binary from `node_modules/numasec-<os>-<arch>/bin/`; `<workspace>/.numasec/operation/<slug>/`; `~/.local/share/numasec/numasec.db`; `.numasec` replay files starting `{"type":"header","format":"numasec/1"`; `interactsh-client -json -o .../numasec/log/int_<hex>.jsonl` | `src/core/operation/operation.ts`, `src/tool/interact.ts:54` |
| API server | `numasec serve`, Hono on `127.0.0.1:4096` by default, no authentication unless `NUMASEC_SERVER_PASSWORD` is set; `/path` and `/agent` answer with numasec folder names and agent descriptions; clients send `x-numasec-directory` | `src/server/`, `src/cli/network.ts` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: numasec on a host, its probes and user agents in web and proxy logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: numasec probe markers in web or proxy logs |
| [`sigma/`](sigma) | 5 Sigma rules: the binary, a server bound to all interfaces, its files, proxy logs and web server logs |
| [`suricata/`](suricata) | Rules for its probes against your sites, and for its API server and client |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the binary or source, replay exports, operation notebooks and the out-of-band session file |

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `numasec`.

## Limits

- Much of what numasec does to a target is the operator's own tools with the model's flags, which the cross-framework rules in `behaviors/` cover. The markers here come from numasec's built-in probes and scanners, which its runbooks use.
- Its API server has no web page, title or favicon and answers 404 on `/`, so internet scanners do not identify it. The exposure searches are low confidence.
- Many host names, ports and paths are OpenCode's with the name changed; a rule that looks only at shape (port 4096, the Basic-auth realm, the route list) also finds OpenCode and its other forks.
- A match means numasec, not an attacker: it is published for authorized testing. Check who ran it and whether the test was agreed.
