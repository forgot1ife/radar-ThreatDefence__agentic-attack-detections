# Shannon Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Shannon**, Keygraph's open-source white-box AI penetration testing agent. It reads an application's source code, then model-driven agents map the running application with a headless browser and try to exploit injection, XSS, authentication, authorization and SSRF findings, in a Docker worker container orchestrated by Temporal. The default model is Anthropic's Claude Sonnet 4.6; OpenAI, xAI, Bedrock and any provider the Pi harness supports also work. It ships an experimental `--exp-php2shell` probe that crashes a PHP worker on an unpatched runtime.

| | |
|---|---|
| Tool | [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) (npm `@keygraph/shannon`, Docker Hub `keygraph/shannon`), reviewed at `3760d2f9` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA |
| Status | Experimental. Tested for syntax and conversion, Suricata on crafted traffic, YARA against the Shannon source, its sample reports and Keygraph's published run records. Baseline every rule on your own data before alerting |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Shannon on a host, watchlist sweep, and the php2shell probe and Shannon's browser in web and proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: Shannon CLI or worker container on a host |
| [`sigma/`](sigma) | 4 Sigma rules for process, file and web server logs |
| [`suricata/`](suricata) | Rules for the php2shell probe, the agents' browser user agent and Shannon scans in a Temporal Web UI |
| [`yara/`](yara) | Rules for the Shannon code, its PDF and Markdown reports, its run record and the browser files it writes |
| Docs | [What Shannon leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |

Shannon has no telemetry and no web console of its own, so there is no domain to block and no Shodan query for it. Its agents attack with a shell and a browser like any other agent, so the cross-framework rules carry most of the target-side detection: model API calls from servers (hunt 02), AI agent page readers next to attack traffic (hunt 03) and out-of-band lookups from your servers (hunt 09) in [`behaviors/`](../../behaviors).

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `shannon`.
