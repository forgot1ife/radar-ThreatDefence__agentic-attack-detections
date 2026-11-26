# CAI Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **CAI** (Cybersecurity AI), an open-source Python framework of AI security agents from Alias Robotics. Its red team, bug bounty and web pentester agents run shell commands on the operator's machine, in a Kali container or over SSH, by default on Alias's own `alias1` model through Alias's gateway. It can run as an HTTP API backend, and it uploads its session logs to Alias Robotics. The repository was archived on August 22, 2026; Alias moved its customers to a closed successor, CSI.

| | |
|---|---|
| Tool | [aliasrobotics/cai](https://github.com/aliasrobotics/cai) (package `cai-framework`; public PyPI to 0.5.10, 1.x from Alias's private index), reviewed at `6dc79257` (v1.1.5, archived) |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Status | Experimental. Tested for syntax and conversion, Suricata on crafted traffic, YARA against the CAI source tree and another agent code base. Baseline every rule on your own data before alerting |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: CAI on a host, watchlist sweep, and CAI telemetry, gateway, API and fetch user agent in network logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: CAI on a host or reporting from your network |
| [`sigma/`](sigma) | 6 Sigma rules for process, file, DNS, proxy and web server logs |
| [`suricata/`](suricata) | Rules for CAI telemetry (DNS, TLS and the log upload), the Alias gateway and package index, the fetch_url user agent and the CAI API |
| [`yara/`](yara) | Rules for the CAI package, its hidden telemetry endpoint, its session logs and its systemd unit |
| Docs | [What CAI leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |

CAI has no canary, payload marker or callback domain of its own. What it does to a target looks like the stock tools its agents run (nmap, curl, nc, sqlmap and the rest), so the cross-framework rules carry most of the target-side detection: model API calls from servers (hunt 02), AI agent page readers next to attack traffic (hunt 03) and out-of-band lookups from your servers (hunt 09) in [`behaviors/`](../../behaviors). Its own fetch_url user agent is the one target-side string in the code.

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `cai`.
