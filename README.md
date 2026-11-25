# Agentic Attack Detections

[![validate](https://github.com/ThreatDefence/agentic-attack-detections/actions/workflows/validate.yml/badge.svg)](https://github.com/ThreatDefence/agentic-attack-detections/actions/workflows/validate.yml)
[![release](https://img.shields.io/github/v/release/ThreatDefence/agentic-attack-detections)](https://github.com/ThreatDefence/agentic-attack-detections/releases)
[![license](https://img.shields.io/github/license/ThreatDefence/agentic-attack-detections)](LICENSE)

Open-source detection rules, hunting queries and indicators for security teams. They cover agentic attack frameworks: tools that hand an intrusion to AI agents, which plan, run real attack tools and keep going until they reach a goal.

Free to use under the MIT license. Fixes, false-positive reports and new indicators are welcome.

## What is here

- **Framework folders.** ARTEX and its AntiFox fork, Cairn, PentAGI, HexStrike, CyberStrikeAI, Strix, Hermes Agent, Agent Zero, RedAmon, Xalgorix and Pentest Swarm AI. Each folder is built from a review of the framework's source code and the public reporting on its use. Fourteen more frameworks whose consoles were found on the internet have smaller folders that say what the console and the tool look like, with the code behind each signal: AutoCVE, CyberStrike, Vulnerator AI, Decepticon, AIDA, BugTraceAI, Z3r0, AIRecon, LuaN1aoAgent, open-kritt, REDCELL, T3MP3ST, WormXGPT and Chufeng Agent Core.
- **Shared behaviors.** Rules for what these frameworks have in common, whatever the tool or the model behind it.
- **Indicators and feeds.** One CSV of 580 sourced indicators, and the feeds generated from it.
- **Exposed consoles.** A dated list of addresses where one of these consoles answers on the internet, in [`exposure/`](exposure), with a [count per framework](#exposed-consoles). It is a record of what is exposed, not a detection feed.

Formats: KQL for Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek, YARA and STIX 2.1, plus WAF rules for Cloudflare, AWS WAF and Azure WAF. Splunk has one app for every framework. Elastic has one import with a rule for every framework.

## Try it in a minute

With Suricata installed, run the ARTEX rules over the sample capture in this repository:

```bash
git clone https://github.com/ThreatDefence/agentic-attack-detections
cd agentic-attack-detections
mkdir -p out
suricata -r frameworks/artex/tests/artex-sample.pcap -S frameworks/artex/suricata/artex.rules -l out -k none
cat out/fast.log
```

You should see alerts such as:

```text
[1:3800001:1] TD ARTEX user agent artex-<role>/1.0
[1:3800020:1] TD ARTEX placeholder probe path
[1:3800023:2] TD Unsigned alg none JWT in URI
```

The capture is test traffic written from the framework source code and published reports. It is not a recorded intrusion.

## Start here

| You have | Do this |
|---|---|
| Microsoft Sentinel | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fagentic-attack-detections.json) One deployment creates every analytics rule (disabled until you enable them), every hunting query and the `AGENTIC_IOCs` watchlist. Give it the workspace name. [`deploy/sentinel/`](deploy/sentinel) has one template per framework too. Run the hunts in each folder's `hunting-order.md` order |
| Defender XDR | Run the hunts from `frameworks/*/sentinel/hunting/` in advanced hunting. They work where the tables exist |
| Suricata | Add the `.rules` files from `frameworks/*/suricata/` and `behaviors/suricata/`. HTTP rules need cleartext or decrypted traffic. DNS and TLS SNI rules work on encrypted traffic |
| Zeek | Install the behaviors package with `zkg install https://github.com/ThreatDefence/agentic-attack-detections` (or load `behaviors/zeek/agentic-behaviors/` by path), set `server_nets` to your server ranges ([setup](behaviors/zeek/README.md)), load the framework scripts `frameworks/artex/zeek/artex/`, `frameworks/cyberstrikeai/zeek/cyberstrikeai/`, `frameworks/hexstrike/zeek/hexstrike/`, `frameworks/autocve/zeek/autocve/` and `frameworks/luan1aoagent/zeek/luan1aoagent/`, and feed `frameworks/*/zeek/intel/*.intel` to the Intel framework |
| YARA | Scan container layers, home folders, `/tmp` and web roots with `frameworks/*/yara/` |
| Any SIEM with Sigma | Convert `frameworks/*/sigma/` and `behaviors/sigma/` with `sigma convert`, or take the conversions in [`generated/`](generated) |
| Splunk | Install [`agentic-attack-detections-splunk.tgz`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections-splunk.tgz) from the latest release (Apps > Install app from file). One app has the searches for every framework, the indicator lookups and a dashboard with a card per framework. Point the `aad_indexes` macro at your indexes. [Setup](deploy/splunk) |
| Elastic | Import [`agentic-attack-detections.ndjson`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections.ndjson) through Security > Rules > Import, or post it to `/api/detection_engine/rules/_import`. One file carries every framework and the shared behaviors, all disabled: the Sigma rules as query rules, the correlations as ES\|QL rules, the hand-written ARTEX rules, and an indicator match rule. For that one, load [`agentic-attack-indicators.ndjson`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-indicators.ndjson) with `POST logs-ti_agentic_attacks-default/_bulk`. Point the index patterns at your own data before you enable them. [Details](generated/elastic_ndjson) |
| A WAF: Cloudflare, AWS WAF or Azure WAF | Deploy the rules in [`waf/`](waf): framework user agents, probe markers and unsigned JWT probes to block, and reported addresses to challenge. A WAF is optional. It adds blocking at the edge to the detections, it doesn't replace them |
| A threat intelligence platform | Import `feeds/stix2.1-bundle.json`, or the per-framework lists in `feeds/by-framework/`. Steps for MISP and OpenCTI, and which fields arrive: [docs/threat-intelligence-platforms.md](docs/threat-intelligence-platforms.md) |

## Coverage

| | KQL hunts | Sentinel analytics | Sigma | Suricata | YARA | Zeek | Indicators |
|---|---|---|---|---|---|---|---|
| [ARTEX](frameworks/artex) | 31 | 7 | 36 | 46 | 4 | script, intel | 247 |
| [Cairn](frameworks/cairn) | 6 | 2 | 3 | 26 | 6 | intel | 73 |
| [PentAGI](frameworks/pentagi) | 5 | 2 | 3 | 10 | 3 | intel | 39 |
| [HexStrike](frameworks/hexstrike) | 4 | 2 | 3 | 7 | 3 | script, intel | 22 |
| [CyberStrikeAI](frameworks/cyberstrikeai) | 5 | 2 | 7 | 11 | 4 | script, intel | 74 |
| [Strix](frameworks/strix) | 3 | 1 | 3 | 5 | 3 | intel | 49 |
| [Hermes Agent](frameworks/hermes) | 4 | 2 | 3 | 7 | 4 | intel | 79 |
| [Agent Zero](frameworks/agent-zero) | 2 | | 1 | 3 | 1 | intel | 8 |
| [RedAmon](frameworks/redamon) | 3 | | 3 | 10 | 1 | intel | 19 |
| [Xalgorix](frameworks/xalgorix) | 3 | | 3 | 10 | 1 | intel | 24 |
| [Pentest Swarm AI](frameworks/pentestswarm) | 3 | | 3 | 11 | 1 | intel | 15 |
| [AutoCVE](frameworks/autocve) | | | | 2 | | script | |
| [LuaN1aoAgent](frameworks/luan1aoagent) | | | | 4 | | script | |
| [Shared behaviors](behaviors) | 9 | 2 | 6 | 18 | | package | |

Every rule names its MITRE ATT&CK techniques. [docs/attack-coverage.md](docs/attack-coverage.md) lists them per framework with links to the rules, and [`generated/attack/`](generated/attack) has an ATT&CK Navigator layer per framework and one for everything.

The other twelve console-level folders (CyberStrike, Vulnerator AI, Decepticon, AIDA, BugTraceAI, Z3r0, AIRecon, open-kritt, REDCELL, T3MP3ST, WormXGPT, Chufeng Agent Core) have no rules yet: they describe the console and the tool, and their exposure searches are in `exposure/`. Suricata counts are hand-written rules; each framework also has address rules generated from its indicators. Some indicators belong to more than one framework. Every framework is in the [Splunk app](deploy/splunk). ARTEX also has Elastic rules and ES\|QL queries, and an osquery pack.

## Frameworks

| Framework | What it is | Seen in |
|---|---|---|
| [ARTEX](frameworks/artex) | Go planner and worker agents with a web console. AntiFox is the same code renamed | Storm-0940, Storm-3358, VAPOR PANDA and criminal groups, against Microsoft 365, Okta, AWS, Azure, web applications and Active Directory |
| [Cairn](frameworks/cairn) | Python engine that drives Claude Code, Codex and Pi coding agents in Kali containers | Online retailers, payment sites, Japanese web applications and WSUS servers |
| [PentAGI](frameworks/pentagi) | Go multi-agent platform that runs Kali tools in a container per engagement | Intrusions GTIG and Mandiant reported since August 2026, and a PaperCut exploitation operator's infrastructure |
| [HexStrike](frameworks/hexstrike) | Python MCP server that gives any AI assistant about 150 security tools over an unauthenticated API | NetScaler exploitation discussion in 2025, and intrusions GTIG and Mandiant reported |
| [CyberStrikeAI](frameworks/cyberstrikeai) | Go operator console whose agents run about 90 tools, with its own implants, C2 listeners and webshell manager | FortiGate mass-exploitation infrastructure, an AWS intrusion, and education organizations in Africa and Latin America |
| [Strix](frameworks/strix) | Python AI pentest agent that runs teams of agents in a Kali sandbox, on any model | The retail card-theft campaign Gambit reported, where it found the flaws Cairn exploited |
| [Hermes Agent](frameworks/hermes) | A legitimate general-purpose agent turned into an attack console: approvals off, a bundled jailbreak skill, red-team personas | The Gambit retail operator, the Carbonato Docker botnet, and Thailand's Ministry of Finance |
| [Agent Zero](frameworks/agent-zero) | General-purpose agent in a Kali container with a built-in hacker profile and an open web UI | Threat-actor experimentation GTIG reported, with no published indicators |
| [RedAmon](frameworks/redamon) | Self-hosted penetration testing platform: a web console, a recon pipeline and an agent that exploits from a Kali sandbox with Metasploit | No public report of use in an attack. Covered from its source code |
| [Xalgorix](frameworks/xalgorix) | Go binary with a web dashboard whose agent tests web applications and APIs without approval steps and re-exploits each finding | No public report of use in an attack. Covered from its source code |
| [Pentest Swarm AI](frameworks/pentestswarm) | Go command-line tool that runs recon, exploit and report agents over about 40 security tools | No public report of use in an attack. Covered from its source code |
| [AutoCVE](frameworks/autocve) | Python platform whose agents audit source code for new CVEs and write reports, with a web console and an API | No public report of use in an attack. 256 consoles exposed |
| [CyberStrike](frameworks/cyberstrike) | TypeScript offensive security harness with a browser extension, an injection prober and a callback server. Not CyberStrikeAI | No public report of use in an attack |
| [Vulnerator AI](frameworks/vulnerator-ai) | OODA-loop pentest agent: a Hermes Agent brain driving Kali and Playwright tools over MCP | No public report of use in an attack |
| [Decepticon](frameworks/decepticon) | LangGraph red team agent with a Kali sandbox; its open web console was removed in November 2026 | No public report of use in an attack |
| [AIDA](frameworks/aida) | Platform that turns a model into a pentester working from its own tool container or Exegol | No public report of use in an attack |
| [BugTraceAI](frameworks/bugtraceai) | Self-hosted web pentest suite with agentic scanning, a web interface and an API | No public report of use in an attack |
| [Z3r0](frameworks/z3r0) | Red team workbench with specialist agents, sandboxed tools and an egress proxy pool | No public report of use in an attack |
| [AIRecon](frameworks/airecon) | Recon agent on a local Ollama model with a Kali sandbox and its own search instance | No public report of use in an attack |
| [LuaN1aoAgent](frameworks/luan1aoagent) | Pentest agent with graph-based planning (鸾鸟), a web workbench and a chisel tunnel | No public report of use in an attack |
| [open-kritt](frameworks/open-kritt) | Vulnerability research tool whose agents find and validate flaws in code | No public report of use in an attack |
| [REDCELL](frameworks/redcell) | LangGraph agents that run a pentest end to end in a Kali container, with chisel pivoting | No public report of use in an attack |
| [T3MP3ST](frameworks/t3mp3st) | Multi-agent red teaming harness with a command and control dashboard | No public report of use in an attack |
| [WormXGPT](frameworks/wormxgpt) | Hacker-themed web terminal and MCP bridge calling security tools. Not the criminal WormGPT service | No public report of use in an attack |
| [Chufeng Agent Core](frameworks/chufeng) | Agent workspace (楚锋 Agent Core) for CTF, forensics and pentest tasks; no public code | No public report of use in an attack. Built from scan data |

Each folder has a README, the hunts and rules, and a `source-code-signals.md` that explains what the framework leaves behind and where in its code each signal comes from.

## Exposure tracking as of 25 Nov 2026

This project now tracks exposure as well as detection: which of these frameworks have consoles reachable on the internet, how many there are, and how the numbers move over time.

![Active offensive agents by framework on 25 November 2026](docs/images/exposure-status-2026-11-25.png)

## Exposed consoles

Hosts on the internet that serve the web console of each framework, found in internet-wide scan data with the fingerprints the rules here use: favicons, page titles, page text that survives a rename, and certificates.

<!-- exposed-consoles:start -->
An active host is one seen in the seven days to November 25, 2026. Hosts the scan data flags as honeypots are left out of both counts.

| Framework | Active hosts | Seen in 30 days | Honeypots left out |
|---|---|---|---|
| [ARTEX](frameworks/artex) and AntiFox | 2,478 | 3,273 | 0 |
| [Hermes Agent](frameworks/hermes) | 1,220 | 2,226 | 0 |
| [CyberStrikeAI](frameworks/cyberstrikeai) | 492 | 669 | 513 |
| [PentAGI](frameworks/pentagi) | 309 | 493 | 0 |
| [AutoCVE](frameworks/autocve) | 147 | 256 | 0 |
| [Agent Zero](frameworks/agent-zero) | 113 | 173 | 0 |
| [HexStrike](frameworks/hexstrike) | 30 | 35 | 0 |
| [RedAmon](frameworks/redamon) | 22 | 38 | 0 |
| [Cairn](frameworks/cairn) | 19 | 32 | 0 |
| [Xalgorix](frameworks/xalgorix) | 6 | 12 | 0 |
| [CyberStrike](frameworks/cyberstrike) | 5 | 8 | 0 |
| [Strix](frameworks/strix) | 4 | 13 | 0 |
| [AIDA](frameworks/aida) | 4 | 5 | 0 |
| [BugTraceAI](frameworks/bugtraceai) | 3 | 3 | 0 |
| [Chufeng Agent Core](frameworks/chufeng) | 2 | 4 | 0 |
| [Z3r0](frameworks/z3r0) | 1 | 4 | 0 |
| [Decepticon](frameworks/decepticon) | 1 | 3 | 0 |
| [AIRecon](frameworks/airecon) | 1 | 2 | 0 |
| [LuaN1aoAgent](frameworks/luan1aoagent) | 1 | 1 | 0 |
| [open-kritt](frameworks/open-kritt) | 1 | 1 | 0 |
| [T3MP3ST](frameworks/t3mp3st) | 1 | 1 | 0 |
| [Vulnerator AI](frameworks/vulnerator-ai) | 0 | 21 | 0 |
| [REDCELL](frameworks/redcell) | 0 | 1 | 0 |
| [WormXGPT](frameworks/wormxgpt) | 0 | 1 | 0 |
| [Pentest Swarm AI](frameworks/pentestswarm) | 0 | 0 | 0 |
| All, each host counted once | 4,699 | 6,982 | 513 |
<!-- exposed-consoles:end -->

- An exposed console is not proof of an attack. Researchers, students and security teams run these tools, and some hosts are decoys.
- More than half of the pages titled CyberStrikeAI are flagged as honeypots, which is why that count is so much lower than a title search suggests. The flagged hosts stay in the list with `honeypot` set to `yes`.
- One network that is not flagged holds more than a third of the remaining CyberStrikeAI hosts and of the PentAGI hosts. That looks like one mass deployment or a set of decoys, not that many operators ([#21](https://github.com/ThreatDefence/agentic-attack-detections/issues/21)).
- The ARTEX count includes 229 services found by the Basic auth realm or the `X-Artex-Auth` header put in front of the console. The realm match is probable, not certain: Artex is also a company name ([details](exposure/README.md#artex-behind-basic-authentication)).
- Consoles behind Basic auth named after the tool are common: 63 realms named Cairn, 14 CyberStrikeAI, 8 PentAGI and a few for other frameworks. They now have searches, marked probable, and are added to the counts at the next full snapshot ([plain-word searches](exposure/README.md#plain-word-searches)).
- These counts come from Shodan alone. Consoles on ports Shodan has not scanned are not in them.
- Hermes Agent and Agent Zero are general-purpose agents, so their numbers count exposed agents, not attack consoles. Hermes is counted on its default port only.
- Consoles served by host name only, or on a port that has not been scanned, are not counted.

The addresses, with the port and the fingerprint that found each one, are in [`exposure/consoles.csv`](exposure/consoles.csv). The counts of every snapshot are kept in [`exposure/history.csv`](exposure/history.csv), so the numbers can be followed over time.

## Behaviors shared by agentic frameworks

[`behaviors/`](behaviors) holds rules that do not depend on any one framework.

| Behavior | Rules |
|---|---|
| An attack tool started under an AI agent CLI (Claude Code, Qwen Code, Kimi CLI, Codex, opencode, Hermes, Cairn's workers), found from the process tree | KQL hunt, Sentinel analytics rule, Sigma |
| Servers calling AI model APIs: Chinese models (DeepSeek, Qwen, GLM, Kimi, MiniMax, Doubao), gateways such as OpenRouter, and Western APIs | KQL hunt, Sigma, Zeek |
| An AI agent's page reader on your application next to attack traffic from the same address | KQL hunt, Sigma, Suricata, Zeek |
| One site probed through hundreds of rotating proxy addresses | KQL hunt, Zeek |
| Configuration and backup file theft, and probes of WSUS administration services | KQL hunt, Sentinel analytics rule, Sigma, Suricata, Zeek |
| An attack agent proving it can write to a container registry: a push to a repository named after the agent (`artex-i<id>`, `hermes-h<id>-writecheck`, `csai-push-probe`) or after a write test | Sigma, Suricata |
| Kerberos user enumeration and SMB or WinRM fan-out from one address | KQL hunt, Zeek |
| A server calling back to the address that was probing it | KQL hunt, Suricata (PentAGI worker ports), Zeek |
| AWS credentials used at machine speed from one outside address | KQL hunt |
| Servers looking up out-of-band testing domains (interactsh, Burp Collaborator, dnslog.cn), which means a blind payload ran on them | KQL hunt, Sigma, Suricata, Zeek |

The ARTEX folder also carries behavior hunts that apply to every framework: user agent family bursts (hunt 17), web and database services starting shells (hunt 11), servers calling webhook and tunnel services (hunt 12), scripts written into web folders (hunt 13), and Kerberoasting, DCSync and WinRM fan-out (hunt 16).

## Indicators and feeds

| Path | Contents |
|---|---|
| [`iocs/indicators.csv`](iocs/indicators.csv) | 580 indicators. Each row has its source, confidence, a review date for addresses and the framework it belongs to. This file is the single source for every feed |
| [`feeds/`](feeds) | Generated from the CSV: a STIX 2.1 bundle, a Sentinel watchlist, and plain lists of addresses, domains, URLs, user agents and hashes. The plain lists carry medium and high confidence rows only. Low confidence rows, which include legitimate services such as AI model APIs, need their context, so they stay in the CSV, the watchlist and the STIX bundle. [`feeds/by-framework/`](feeds/by-framework) has the lists per framework |
| [`docs/attack-coverage.md`](docs/attack-coverage.md) | Which rules cover which ATT&CK technique, per framework, with the [Navigator layers](generated/attack) beside it. `tools/build_attack.py` rebuilds both |
| [`generated/`](generated) | Every Sigma rule converted to Splunk SPL, Sentinel and Defender XDR KQL, and Elastic ES\|QL and Lucene, plus [`elastic_ndjson/`](generated/elastic_ndjson) where all of them are one Kibana import. [`SUMMARY.md`](generated/SUMMARY.md) shows which rule converted to which backend |
| [`waf/`](waf) | Cloudflare, AWS WAF and Azure WAF rules built from [`waf/signatures.yaml`](waf/signatures.yaml) and the CSV. The [README](waf/README.md) covers when a WAF helps and how to deploy |
| [`exposure/`](exposure) | Addresses where one of these consoles answers on the internet, with the fingerprint that found each one. A record of what is exposed, kept out of the feeds above. `tools/exposure_snapshot.py` rebuilds it |
| [`tools/`](tools) | Feed builder, WAF builder, release file builder, Sigma converter and validator |
| [`docs/`](docs) | [Adding a framework](docs/adding-a-framework.md) |

Each framework folder also has a Zeek intel file and Suricata address rules, generated from the same CSV.

### Downloads

Each [release](https://github.com/ThreatDefence/agentic-attack-detections/releases) carries the same content as ready-made files. These links always point at the newest release:

| File | Contents |
|---|---|
| [`agentic-attack-detections.rules`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections.rules) | Every Suricata rule in one file |
| [`agentic-attack-detections-yara.zip`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections-yara.zip) | The YARA rules, one file per framework |
| [`agentic-attack-detections-stix2.1.json`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections-stix2.1.json) | The STIX 2.1 bundle |
| [`agentic-attack-detections-indicators.zip`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections-indicators.zip) | `iocs/indicators.csv` and every feed |
| [`agentic-attack-detections-waf.zip`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections-waf.zip) | The WAF rules for Cloudflare, AWS WAF and Azure WAF |
| [`SHA256SUMS.txt`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/SHA256SUMS.txt) | SHA-256 of each file |

To keep the Suricata rules current with `suricata-update`:

```bash
suricata-update add-source agentic-attack-detections https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections.rules
suricata-update
```

## How the rules are built and checked

- **From source.** A signature string comes from the framework's code at a named commit, or from a report that published it. `source-code-signals.md` gives the file and line.
- **From reports.** Every indicator names the report it came from, and each value was checked against that report.
- **Tested.** Each Suricata rule has a test flow and a near miss. Sigma rules are run against test events, and hunts and analytics rules against sample rows in Microsoft's Kusto emulator, where cases have been written: [`tests/sigma/`](tests/sigma) and [`tests/kql/`](tests/kql) have the formats, and new cases are welcome. Every KQL query is parsed with Microsoft's parser and its columns checked. The Zeek packages run against test captures. CI runs the validator and the Suricata, Sigma and KQL tests on every push.
- **Run on real data.** Version 2.7.0 was run over 30 days of production telemetry to remove rules that could not fire and to quiet rules that were noisy.

No rule has been tested against a captured intrusion. Treat every rule as experimental until it has run on your own data.

## Confidence

| Level | Meaning | How to use it |
|---|---|---|
| High | Specific to a framework or its campaigns: its user agents, command lines, paths, prompt strings, probe artifacts, reported C2 and skimmer domains, file hashes | Alert |
| Medium | Seen in a framework's activity but changeable or shared: reported addresses, generic agent user agents, prompt text shared with similar tools | Alert after baselining, or hunt |
| Low | Common or legitimate: AI model APIs, request-collection services, agent CLI user agents, hosting ASNs, proxy providers | Context for another finding only |

Addresses from cloud and VPS providers are reassigned. Every address has a `review_by` date 180 days after it was reported. Addresses past that date are left out of the plain lists, the Zeek intel files and the Suricata address rules; they stay in the CSV and the STIX bundle as history. Check before you block.

## Testing

```bash
pip install -r tools/requirements.txt
python3 tools/validate.py                              # Sigma, KQL, ES|QL, TOML, Splunk, Suricata SIDs, YARA, Zeek, osquery, feeds
python3 -m unittest discover -s tests/feeds            # indicator confidence, expiry and SID policy
python3 tests/sigma/run_tests.py                       # Sigma rules against test events
python3 tests/kql/run_tests.py                         # hunts and analytics against sample rows; needs the Kusto emulator
lab/lab.sh up && lab/lab.sh test                       # Splunk and Elastic in Docker, every rule against test events: lab/README.md
python3 tools/convert.py                               # regenerate generated/
python3 tools/build_waf.py                             # regenerate waf/
python3 tests/waf/run_tests.py                         # offline checks of the WAF rules on every platform
python3 tools/build_release.py                         # build the release downloads into dist/
python3 tests/suricata/run_tests.py                    # one flow per Suricata rule; needs suricata and openssl
bash frameworks/artex/tests/run_network_tests.sh       # needs zeek and suricata on the PATH
bash behaviors/zeek/tests/run_tests.sh                 # needs zeek on the PATH
bash frameworks/cyberstrikeai/tests/run_zeek_tests.sh  # needs zeek on the PATH
bash frameworks/hexstrike/tests/run_zeek_tests.sh      # needs zeek on the PATH
bash frameworks/autocve/tests/run_zeek_tests.sh        # needs zeek on the PATH
bash frameworks/luan1aoagent/tests/run_zeek_tests.sh   # needs zeek on the PATH
```

`validate.py` checks KQL with Microsoft's parser when `dotnet` is installed, and Zeek scripts when `zeek` is.

## Contributing

Pull requests are welcome. The most useful contributions are false-positive reports, missed detections and new indicators with a source. See [CONTRIBUTING.md](CONTRIBUTING.md) for the checks to run, and [docs/adding-a-framework.md](docs/adding-a-framework.md) to add a framework.

Where the project is going is in the [roadmap](ROADMAP.md).

## Getting help

Open an [issue](https://github.com/ThreatDefence/agentic-attack-detections/issues). There are forms for a false positive, a missed detection, a new indicator and a new framework. Describe the shape of the event; never paste customer data. For a security problem in the repository itself, see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE). Each indicator names its source in `iocs/indicators.csv`. Use them in your own products and feeds.

## Disclaimer

Provided as is, without warranty. A match is a lead, not a verdict. Absence of a match does not mean absence of compromise.

## Credits

Started and maintained by [ThreatDefence](https://threatdefence.com), with fixes from [@jack51706](https://github.com/jack51706), [@tridev-tej](https://github.com/tridev-tej), [@Bropdrop](https://github.com/Bropdrop), [@blitzcrieg1](https://github.com/blitzcrieg1) and [@nerdyhacks](https://github.com/nerdyhacks). Background on ARTEX: the [advisory](https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting) and the [source code signals article](https://threatdefence.com/article/artex-source-code-signals-deep-hunting).

## History

This repository was `artex-detections`. GitHub redirects the old address. The ARTEX rules moved from the root to [`frameworks/artex/`](frameworks/artex); `iocs/indicators.csv` and `feeds/` kept their paths.
