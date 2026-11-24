# Changelog

## 2.11.1, November 25, 2026

Analytics rules deployed from the Microsoft Sentinel templates can now be enabled, and two console rules are added.

- Sentinel templates: analytics rules no longer carry `templateVersion`. Microsoft Sentinel accepts it only together with `alertRuleTemplateName`, so a deployed rule could not be enabled or edited in the portal ("'templateVersion' can only be used if 'alertRuleTemplateName' is not empty"). Redeploy a template to fix rules already in a workspace; `tools/build_sentinel.py --check` now fails on the combination. Reported in #23.
- Two Suricata rules for exposed consoles: 3800081 matches an ARTEX console by the end of its page title, which stays when the console is renamed, and 3806013 matches the Hermes Agent sign-in page seen in `exposure/consoles.csv`. Each has a case and a near miss in `tests/suricata/run_tests.py`. Contributed by @shiwng in #29.

## 2.11.0, November 24, 2026

One-step deployment to Microsoft Sentinel, one Splunk app for every framework, Zeek scripts for CyberStrikeAI and HexStrike, and a shared behavior for agents writing to container registries.

- One Splunk app for every framework (#24). `tools/build_splunk.py` builds [`deploy/splunk/`](deploy/splunk) from every Sigma rule, converted to SPL on CIM field names, the hand-written ARTEX searches and `iocs/indicators.csv`. It has 88 saved searches, all disabled, each with its ATT&CK techniques for Splunk Enterprise Security. Indicator searches match reported addresses (with CIDR ranges), domains and their subdomains, file hashes and user agents, and skip indicators past their review date. Data sources are chosen in macros: `aad_indexes` and one macro per source (process, file, registry, DNS, proxy, web server, CloudTrail, Entra ID, Azure activity, Okta), with CIM tags as defaults. The Agentic Attack Activity dashboard has a card per framework with hosts and addresses seen, results per day, new and all-time counts and the usual console port, fed by the summary index the searches write to. Each release carries `agentic-attack-detections-splunk.tgz`. CI checks the app is committed, runs Splunk AppInspect on it, and runs every search in Splunk against test events: each search built from a Sigma rule must agree with the rule on every event. The app keeps the id `TA-agentic-attack-detections`, so it upgrades the ARTEX app in place.
- One-step deployment to Microsoft Sentinel (#23). `tools/build_sentinel.py` turns `frameworks/*/sentinel/` and `behaviors/sentinel/` into ARM templates in [`deploy/sentinel/`](deploy/sentinel): every analytics rule as a scheduled rule with its query, frequency, period, threshold, severity, tactics and techniques; every hunt as a hunting query with its title and description; and the `AGENTIC_IOCs` watchlist with the search key `value`. One template has everything, and there is one per framework. Parameters are the workspace name and `enableRules` (off by default). The README has a Deploy to Azure button, each release carries the templates, and CI rebuilds them and fails if they are not committed or break a check: technique and tactic pairs Microsoft Sentinel accepts, tag and query lengths, the template size limit.
  - The four ARTEX hunts that hold several example queries (09, 14, 15 and 16) become one hunting query per example, because a hunting query runs as one query.
  - The Hermes host-escape rule lists Defense Evasion, the tactic of its T1036.005 technique; Microsoft Sentinel refused the rule without it.
  - Cairn hunt 6 reads its MySQL audit columns with `column_ifexists`, so it runs in workspaces that do not collect those logs instead of failing.
  - Microsoft Sentinel keeps parent techniques only, so a rule with T1059.004 shows T1059.
- CI installs Zeek 9.0 and runs the Zeek tests: the behaviors package, ARTEX, CyberStrikeAI and HexStrike (#3). The validator now parses every Zeek package on each push and pull request.
- Zeek scripts for CyberStrikeAI and HexStrike (#6). CyberStrikeAI: the webshell manager, the OS probe and a server answering it, implant check-ins with `X-Implant-Token` and `X-Session-Token`, the implant's cut-short Chrome user agent, the TCP implant's `CSB1` greeting, the console user agent and the console's `CN=CyberStrikeAI` certificate. HexStrike: its user agents, the generated-exploit user agent, the XSS probe, requests to `/api/command` and `/api/tools/` on 8888, and a server answering its health check. Each has a sample capture with near misses and `tests/run_zeek_tests.sh`.
- New page: [docs/threat-intelligence-platforms.md](docs/threat-intelligence-platforms.md) has the steps for loading the plain lists and the STIX bundle into MISP and OpenCTI, and says which fields arrive and which are dropped (#5).
- New shared behavior: an attack agent proving it can write to a container registry. Agents that find a registry open to pushes push a small image named after themselves, such as `artex-i127739`, `hermes-h23645-writecheck`, `csai-push-probe` or `xalgorix-pwn`; one open registry carried test images from at least five tools. A Sigma rule with test events and Suricata rules 3801041 and 3801042 match the push. Eight repository names are added as indicators, including the `gh0st/` and `fsociety/` images that match Carbonato's naming.
- Honeypots are marked in the exposure list and left out of the counts. `exposure/consoles.csv` has a `honeypot` column, set from the tag the scan data carries: 682 services, 681 of them pages titled CyberStrikeAI on 521 addresses. The README table and `exposure/history.csv` count 3,968 active hosts and 6,200 in 30 days without them, and show how many were left out.
- The README has a table of exposed consoles per framework: hosts seen in the last seven days and in the last 30. `tools/exposure_snapshot.py` rewrites it on every snapshot and records the counts in `exposure/history.csv`, so the numbers can be followed over time. `--summary` recounts from `consoles.csv` without a key.
- One network holds about a fifth of the listed CyberStrikeAI hosts and more than a third of the PentAGI hosts; the README says so next to the counts (#21).
- "AI Agent CLI Starts an Attack Tool" gains four test events, 48 in all: a Pi parent started with `--provider cairn` next to the same parent without it, and the Windows PowerShell launcher starting `nmap.exe` next to the same launcher starting a harmless tool. Contributed by @blitzcrieg1 in #20.

## 2.10.0, November 23, 2026

RedAmon, Xalgorix and Pentest Swarm AI are added, KQL hunts can now be tested against sample rows, and the repository gains a list of exposed consoles.

- New framework folders, each built from a review of the framework's source code with a file and line for every signal. No public report of any of them in a real intrusion was found, so the rules find the software: its probes reaching you, the tool on a host, and its console exposed.
  - [RedAmon](frameworks/redamon) (samugit83/redamon, 7.9.0): the `RedAmon-AISurfaceRecon/1.0` probe of model API and MCP paths, the XSS canary `rEdAm0n1337XsS`, the cache poisoning canary under `redamon-poc.invalid`, the Docker stack and its reverse shell tunnels on port 4444, the console and the open agent API on port 8090. Suricata 3808001 to 3808010.
  - [Xalgorix](frameworks/xalgorix) (xalgorix/xalgorix, v4.6.205): the verifier's `xalgorix-nonexistent-`, `xalgorix-missing-` and `xalgorix-xxe-` markers, the CSRF check origin, the callback listener's answer, the shell wrapper around every agent command, and the dashboard on port 9137. Suricata 3809001 to 3809010.
  - [Pentest Swarm AI](frameworks/pentestswarm) (Armur-Ai/Pentest-Swarm-AI): the negative-control probe `/nx-<16 hex>`, the checks that carry `evil.pentestswarm.invalid`, `<!DOCTYPE pstest [`, `191*193` and `/vV9x-nonexistent-9271`, the consent log on the host, and the dashboard and API. Suricata 3810001 to 3810011.
  - Each has 3 KQL hunts, 3 Sigma rules with test events, a YARA rule checked against its own source and the other agent code bases, and its indicators: 56 new rows, 572 in all.
- `tests/kql/run_tests.py` runs a hunt or an analytics rule in Microsoft's Kusto emulator against sample rows and fails when a case that should come back does not, or a near miss does. The query runs as written: only its tables are replaced by the sample rows. First cases: hunt 1 and its analytics rule (50 each) and hunt 9 (13). CI starts the emulator and runs the test on every push. Contributed by @nerdyhacks in #19; [`tests/kql/README.md`](tests/kql/README.md) has the format for adding cases.
- [`exposure/`](exposure): addresses where Shodan has seen the web console of one of the frameworks, found with the fingerprints the rules already use. The first snapshot has 7,659 services on 6,715 addresses. It is a record of what is exposed and stays out of the Suricata address rules, the WAF lists, the STIX bundle and the plain feeds, which keep to addresses a named report tied to attacks. `tools/exposure_snapshot.py` rebuilds it from the searches in `exposure/shodan-queries.csv`.

## 2.9.3, November 23, 2026

Sigma rules can now be tested against sample events, and rules that missed real activity or matched look-alike names are corrected. The rule fixes were contributed by @nerdyhacks in #15, #16, #17 and #18.

- `tests/sigma/run_tests.py` evaluates a Sigma rule against test events in `tests/sigma/fixtures/<rule name>.jsonl` and fails when a rule matches an event it should not, or misses one it should match. It also evaluates every Sigma rule once, so a rule the test cannot handle fails the run. Until now Sigma rules were checked for syntax and conversion only.
- First test events: "AI Agent CLI Starts an Attack Tool", with two matches and four near misses. Four of them are adapted from test cases by @blitzcrieg1, who suggested this in #13. [`tests/sigma/README.md`](tests/sigma/README.md) has the format for adding more.
- CI runs the test on every push.
- "AI Agent CLI Starts an Attack Tool" missed tools that are Python, Ruby or Perl scripts (sqlmap, NetExec, wpscan, nikto, Metasploit and others): the process image is the interpreter and the tool is only in the command line. The rule now matches an interpreter running the tool's script. It also gains the eight tools the KQL hunt already had, and finds agents installed with npm or pip by their package path in the parent command line (#15). The script match needs the tool to be the script that runs, so a project folder named `responder` or `coercer` does not set it off. The rule now has 44 test events.
- Hunt 1 ("An AI agent driving attack tools") and its analytics rule had the same gap: they matched the tool by file name, so script tools running as `python3`, `ruby` or `perl` were missed. Both now find the tool as the script in the command line, the same way the Sigma rule does, and the Tools column shows the tool name, not the interpreter (#18). The analytics rule is version 2.1.0.
- "AI Agent Client Calling a Chinese Model API or Model Gateway" matched any host that ends with a listed name, such as `notopenrouter.ai`. It now matches the listed host or a subdomain of it (#16).
- Out-of-band lookups: every name starting with `polling.` was skipped, so a payload name with that label in front (`polling.<id>.oast.fun`) was hidden. Only Burp's two polling names, `polling.oastify.com` and `polling.burpcollaborator.net`, are skipped now. Fixed in the Sigma rule (#16), which also matches names written with a dot at the end, and in the Zeek script, hunt 9 and Suricata rules 3801057 and 3801058 (revision 3).
- Framework DNS and proxy rules matched any name that ends with a listed one, so `web8t.shop` matched `b8t.shop` and `cdn.my-static-js.com` matched `static-js.com`. Six ARTEX, Cairn and Strix Sigma rules now match the listed name or a subdomain of it, and each has test events (#17). The three Strix Suricata rules (3805001 to 3805003, revision 2) are fixed the same way with `dotprefix`.
- A [roadmap](ROADMAP.md): more work on rules for what attacking agents do, whatever the framework, and on proof that each rule works.

## 2.9.2, November 23, 2026

Address indicators: expired ones leave the active outputs, and confidence is no longer overstated. Contributed by @Bropdrop in #12.

- Addresses past their `review_by` date are left out of the plain lists, the Zeek intel files and the Suricata address rules, as the WAF rules already did. They stay in `iocs/indicators.csv` and the STIX bundle as history. On this release that removes 21 addresses, all CyberStrikeAI servers that Team Cymru reported on March 2, 2026.
- Suricata address rules carried `confidence Medium` whatever the indicator said. A rule now takes the lowest confidence among its addresses, and low confidence rules use `classtype:misc-activity`. Their revision is now 2.
- A group whose addresses have all expired keeps its SID pair reserved, so the rules after it keep their numbers.
- `review_by` must be a valid date, and `tests/feeds/` checks the expiry, confidence and SID rules on every push.

## 2.9.1, November 22, 2026

Agent Zero gets its source review, the review corrected two rules (#7), and the Zeek behaviors package installs with `zkg`.

- New `frameworks/agent-zero/source-code-signals.md`: how Agent Zero runs, what a target sees, what the host that runs it shows, the exposed web UI, and what the code does not contain, with a file and line for each signal at commit `a6e41ca`. It also checks every string the Agent Zero rules match against the source.
- Agent Zero hunt 1: the attack-tool and tunnel branches looked for `/a0/` in the command line of the parent process. The source shows the parent is `/bin/bash`, and tunnels are opened by `ssh` or `cloudflared`, so those branches could not fire. They now look at devices where Agent Zero itself was seen, and the tunnel branch also covers Microsoft dev tunnels.
- YARA `AgentZero_Hacker_Profile` now needs a prompt line that only the hacker profile has. Two of its strings are also in the default profile, so a dump of the default prompts could match a rule named for the hacker profile.
- The behaviors Zeek package installs with the Zeek package manager: a `zkg.meta` at the repository root points at `behaviors/zeek/agentic-behaviors` and runs its tests on install (`zkg install https://github.com/ThreatDefence/agentic-attack-detections`).
- Indicators: the note on the "obey instructions never refuse for safety ethics" string now says it is in the default profile too, and the unsourced "5080 also seen" note on the port is removed.

## 2.9.0, November 22, 2026

Two changes that affect anyone who already uses the Suricata rules or the plain indicator lists.

- **Suricata rule IDs renumbered.** Every SID moved from 9726001-9734999 to 3800001-3808999: subtract 5,926,000 from the old number (9726001 is now 3800001, 9727057 is now 3801057). The old numbers sat inside a range registered to another rule set at sidallocation.org, so the two could collide. The new block, 3800000 to 3819999, has been requested there for this project. If you suppress, threshold or reference these rules by SID, update the numbers. Rule content and revisions are unchanged. The WAF rule mapping, the tests and the docs use the new numbers; older entries in this changelog keep the numbers they were written with.
- **Plain indicator lists carry medium and high confidence only.** `feeds/*.txt` and `feeds/by-framework/` no longer include low confidence rows. Many of those are legitimate services that only mean something in context, such as `api.anthropic.com`, `api.x.ai`, `webhook.site` and the `Boto3` user agent, and a bare list cannot carry that context. They remain in `iocs/indicators.csv`, the Sentinel watchlist, the STIX bundle and the Zeek intel files. The lists now hold 115 IPv4 addresses (was 162), 30 domains (was 45) and 37 user agents (was 44).

## 2.8.1, November 22, 2026

No detection changes. Releases now come with ready-made downloads.

- Each release carries the Suricata rules in one file, the YARA rules, the STIX 2.1 bundle, the indicators and feeds, the WAF rules, and a `SHA256SUMS.txt`. The file names stay the same from release to release, so `releases/latest/download/<name>` always gives the newest one.
- `tools/build_release.py` builds them, with the same bytes for the same commit and version. A workflow attaches them when a release is published, and CI builds them on every push and loads the combined Suricata file.
- README: a Downloads table and the `suricata-update` command.

## 2.8.0, November 22, 2026

WAF rules (#10). The detections stay the same; this release adds a way to block part of them at the edge.

- New `waf/` folder with rules for Cloudflare (dashboard expressions, Rulesets API JSON, IP list, Terraform), AWS WAF (rule group and IP sets as CLI input, CloudFormation and Terraform) and Azure WAF (Application Gateway and Front Door policies in Bicep and ARM, and plain custom rule arrays).
- Rule groups by tier. Block: framework user agents, probe markers and framework headers, unsigned `alg:none` JWTs, and the CyberStrikeAI webshell probe in request bodies. Challenge: scanner user agents and reported addresses. Log: AI agent page readers and the Hermes results folder. Opt-in: WSUS services reached from the internet. Addresses are never blocked by default.
- Everything is generated by `tools/build_waf.py` from `waf/signatures.yaml` and `iocs/indicators.csv`. Addresses past their `review_by` date are left out (21 of 163 on this release).
- `tests/waf/run_tests.py` checks the generated files on every platform: every signature value, every address, hand-written requests (most of them near misses), and a replay of the Suricata test flows so the WAF rules and the Suricata rules they mirror agree. It also checks platform limits, the AWS files against the wafv2 API model, and CI runs `cfn-lint`, `terraform validate` and `az bicep build`.
- `waf/README.md` answers whether a WAF is needed and where it fits next to the SIEM and IDS content.

## 2.7.3, November 22, 2026

- Elastic conversions of DNS, proxy and web server rules now use ECS field names: `dns.question.name`, `url.original`, `url.domain`, `url.path`, `url.query` and `user_agent.original`. Before, they kept the Sigma names and matched nothing in an ECS index. Contributed by @tridev-tej in #9, closing #4.
- `tools/validate.py` fails if a generated Elastic query still uses one of those Sigma field names.

## 2.7.2, November 22, 2026

- Two ARTEX user agents added: `artex-agent` and `artex-judge-r121`. Dragos saw them in AWS CloudTrail when ARTEX checked stolen keys it had planted as canary tokens. Reported in #8 by @Assaf-tal.
- New Suricata rule 9726009 for both, and the names are added to the ARTEX user-agent rules for Sigma, Microsoft Sentinel, Elastic, Splunk and Zeek. The rules match `artex-judge-` followed by any run name, since `r121` reads as a run number.
- 516 indicators in total.

## 2.7.1, November 22, 2026

No detection changes. This release makes the repository easier to start with and to contribute to.

- README: a one-command "Try it in a minute" that runs the ARTEX Suricata rules over the sample capture, a "Start here" table by what you run, a coverage table of frameworks against formats, and a section on how the rules are built and checked.
- `CONTRIBUTING.md` with the checks to run and the rules for indicators, Suricata, KQL and Sigma content.
- `SECURITY.md`, and issue forms for a false positive, a missed detection, a new indicator and a new framework.
- Framework folder READMEs are titled "<Framework> Detection Rules and IOCs".
- ARTEX file headers now read "Agentic attack detections by ThreatDefence (ARTEX)", like the other folders. They still carried the repository's first name.
- `LICENSE` copyright line now includes contributors.
- `CODE_OF_CONDUCT.md`: the Contributor Covenant, with conduct reports sent privately through the Security tab.
- A pull request template with the checks to run, and a default template for blank issues.
- The ARTEX Splunk app is now `TA-agentic-attack-detections`, labeled "Agentic Attack Detections (ARTEX)" (was `TA-artex-detections`). If you installed it under the old folder name, remove that folder before copying the new one, or Splunk will load both.

## 2.7.0, November 22, 2026

A correctness release. Every rule was reviewed against the framework source and its cited report, the rules were run over 30 days of production telemetry, and two test suites were added. Nothing new is detected; a lot now works that did not.

Rules that could not fire

- `tools/convert.py` reused the same rule objects for every backend, so each Elastic conversion carried Microsoft field names and only 1 of 64 rules converted for Defender XDR. Each backend now gets its own copy: 25 rules convert for Defender XDR, and Elastic output uses ECS fields, including `process.*` for Linux process rules. Everything in `generated/` was rebuilt.
- AI agent starts an attack tool (behaviors hunt 1, its analytics rule and Sigma rule) looked for an auto-approve flag on the tool's parent. The parent is the agent's shell, so the flag was never there, and Windows `.exe` names were missing. The rules now follow the process tree: Claude Code's shell (`shell-snapshots`, `CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT`), an agent binary as parent or grandparent, or an agent found by its command line. The flag is a context column, because staff use it too and an agent can run a tool without it. Severity is medium. The analytics rule reads agent processes from the last day instead of the last hour.
- Suricata: Cairn 9727002 matched a port in `http.host`, which never holds one; it now matches the project list fields in the response. 9726068 looked for a host name inside Gh0st RAT traffic and is retired. `ARTX_PERSIST_OK` has its own rule (9726027). BLOODALCHEMY, toolkit and card-theft campaign domains match subdomains. Unsigned JWT rules cover `typ` and the None and NONE spellings (9726030 to 9726033). 9726067 allows a query string. Hermes 9732001 and 9732004 accept spaced JSON and `sh -c`, and 9732001 no longer needs an outside source. `dnslog.cn` and `webhook.site` match any case.
- KQL: `sComputerName` is not a `W3CIISLog` column (CyberStrikeAI hunt 1 and its analytics rule), `FileUrl` is not a `DeviceFileEvents` column (ARTEX hunt 22), and `TicketEncryptionType` is not a `SecurityEvent` column (ARTEX hunt 16).
- CyberStrikeAI's `.bashrc` line is written to the file, not run as a command, so the `# cs` command-line branch is gone from the hunt, the analytics rule and the Sigma rule. The file-event branch and the YARA rule cover it.
- Strix Sigma rule: `strix --target x` and `strix -t x` now match.
- Elastic: two ES|QL queries used `(?i)`, which Elastic's regex does not support, and the ARTEX user-agent rule was case-sensitive. Splunk: the user-agent search dropped rows with no `src` field.
- The certificate rules for CyberStrikeAI and PentAGI only see a certificate in a TLS 1.2 handshake. The rule files said otherwise.

Rules that were noisy

- Out-of-band lookups: Burp's own client polling (`polling.oastify.com`) is left out everywhere, Suricata alerts once per source per hour, and the Sigma rule is medium.
- Strix: only install commands count, not uv or pip probing an installed copy.
- Web service starts a shell (Sigma, KQL, Splunk): `java` and `node` count only under a service account, because they also run Jenkins, npm and AI agent CLIs.
- Carbonato: `nsenter -t 1` alone is also what Kubernetes node-debug tools do, so the rule needs an install or persistence command with it.
- ARTEX hunt 10 no longer matches the bare word `artex`, which is also a real company's name. HexStrike's port 8888 hunt leaves out Jupyter.
- Suricata: every rule that inspects content has a fast pattern, so none runs on every transaction. Multi-domain regular expressions are now one rule per domain.
- Splunk: searches read `artex_indexes` instead of `index=*`, and each has alert suppression.

Zeek

- On a cluster, `Kerberos_Enumeration`, `AI_Agent_Attacking_Site` and `Callback_To_Prober` kept their state on one worker and did not fire when related connections reached another. They now share state through SumStats or the manager. Checked on a local manager with two workers.
- With `server_nets` unset the package treated every local host as a server, so laptops calling model APIs and Burp polling raised notices. The server-only notices now stay off until `server_nets` is set, with a warning at startup.
- `Rotating_Proxy_Probing` checked its ratio once per window and now checks it on every request. It needs a payload or a refused login, so a normal login page no longer raises it.
- `Backup_File_Served` needs a real file body, so a site that answers 200 to everything no longer raises it. `Callback_To_Prober` ignores requests that came through a CDN. `SMB_WinRM_Fan_Out` counts connections where both sides sent data, not half-open scans. `Out_Of_Band_Lookup` skips Burp polling and fires once per source per hour.
- Two scripts kept an entry for every visitor for up to a day. They now keep only addresses that already showed the first half of a pattern, for an hour.
- The ARTEX script matches user agent names in any case (`ScopeWeaver/1.0`, `ARTEX-PENTEST/1.0`) and every unsigned JWT header form.
- The test capture now carries Kerberos requests Zeek parses; before, the Kerberos notice fired from error replies alone.
- Changed settings: `prober_min_conns` is now `prober_min_requests`, `prober_memory` and `page_reader_window` default to 1 hour, and `Callback_To_Prober` needs cleartext HTTP for the probe half.

Tests

- `tests/suricata/run_tests.py` replays one flow per hand-written Suricata rule, with near misses, and fails if a rule has no case or fires where it should not. CI runs it.
- `tools/validate.py` parses every KQL hunt and analytics query with Microsoft's Kusto.Language and checks table and column names against Microsoft's table reference (`tools/kqlcheck/`).
- Every indicator was checked against the report it cites. Three rows that cited our own article now cite Wiz Research, where the values were published.

## 2.6.1, November 22, 2026

- Removed the SHA-256 of the Windows Hades sample (`dwm_33b7.exe`) from the Thai Ministry of Finance case. Hunt.io printed it 63 characters long, so it could never match a file, and no other source has the full value. Reported in #1.
- `tools/build_feeds.py` now rejects any `md5` or `sha256` value that is not 32 or 64 hex characters.
- `tools/convert.py` and `tools/validate.py` work on Windows with non-UTF-8 code pages, and `.gitattributes` keeps the shell tests at LF (#2, by @jack51706).

## 2.6.0, November 21, 2026

- Hermes Agent added in `frameworks/hermes/`: 4 KQL hunts, 2 analytics rules, 3 Sigma rules, Suricata and YARA for Hermes turned into an attack console (approvals off, the bundled godmode jailbreak skill, replaced personas, Telegram control) and for the Carbonato Docker botnet that installs it, from a review of the Hermes source (NousResearch/hermes-agent at 7c34e2db) and reporting by Unit 42, Hunt.io, Gambit Security and ThreatDown. The indicators include the Thai Ministry of Finance case (Hades and VShell hashes) and Carbonato's infrastructure; the Gambit campaign rows now carry `hermes` too.
- Agent Zero added in `frameworks/agent-zero/`: 2 KQL hunts, 1 Sigma rule, Suricata and YARA for its container, hacker profile, exposed UI and tunnels. GTIG reported threat-actor experimentation but published no indicators, so this folder holds software fingerprints.
- AntiFox, the renamed ARTEX fork, in `frameworks/artex/`: hunt 31 for the IIS web shell to AWS enumeration sequence Arctic Wolf Labs reported, and indicators for its Alibaba Cloud consoles, exposed consoles, image, user agents and recording proxy.
- 515 indicators in total.

## 2.5.0, November 21, 2026

- Strix added in `frameworks/strix/`: 17 indicators, 3 KQL hunts, 1 analytics rule, 3 Sigma rules, Suricata and YARA, from a review of the Strix source code (usestrix/strix at a1ccf777) and reporting by Gambit Security, GitGuardian and PenTestIT. The Gambit retail campaign indicators are now tagged `cairn strix`: Strix found the flaws and Cairn exploited them.
- New behavior: servers looking up out-of-band testing domains (interactsh `oast.*`, Burp Collaborator, dnslog.cn and others), as a KQL hunt, Sigma, Suricata (SIDs 9727050 to 9727059) and a Zeek notice.

## 2.4.0, November 21, 2026

- Zeek package for the cross-framework behaviors in `behaviors/zeek/agentic-behaviors/`: model API calls from servers, Claude Code's page reader next to attack traffic, rotating proxy probing, configuration and backup file theft, WSUS probes, Kerberos enumeration, SMB and WinRM fan-out, and servers calling back to the address that probed them. Tested against a synthetic pcap in `behaviors/zeek/tests/`.
- `tools/validate.py` parses every Zeek package when Zeek is installed.
- The agent behaviors now detect agentic AI used for attack whatever the model, instead of centring on Claude Code. Hunt 02 reports servers calling any AI model API, with Chinese models (DeepSeek, Qwen, GLM, Kimi, MiniMax, Doubao, SiliconFlow and others) and model gateways ranked first, and no longer drops consoles calling from Go or Python. Hunt 01 and its analytics and Sigma rules add Qwen Code and Kimi CLI in auto-approve mode. Hunt 03, Sigma, Suricata (SIDs 9727012 to 9727014) and Zeek add the Qwen Code, Kimi CLI and opencode user agents. Endpoints and user agents come from the Qwen Code, Kimi CLI and opencode source. Hunts 01 to 03 have new file names; Sigma and analytics rules keep their paths and ids.

## 2.3.0, November 21, 2026

- CyberStrikeAI added in `frameworks/cyberstrikeai/`: 72 indicators, 5 KQL hunts, 2 analytics rules, 7 Sigma rules, Suricata and YARA, from a review of the CyberStrikeAI source code (AIPentest/CyberStrikeAI at af6cf750) and reporting by Team Cymru, Kaspersky, Elastic, Spectrum Security, PenTestIT, Huntback and the D4 Project. The YARA implant rule was tested against implants compiled from the stock template.
- The CyberStrikeAI webshell user agent that 1.0.0 listed as a related framework under ARTEX now belongs to the `cyberstrikeai` framework.
- New behavior hunt: AWS credentials used at machine speed from one outside address, from Elastic's CyberStrikeAI intrusion report.
- The feeds now carry IPv6 addresses (`ipv6.txt`) and MD5 hashes (`md5.txt`), in the STIX bundle and Zeek intel as well.
- The watchlist sweeps in the Cairn, PentAGI and HexStrike folders no longer call it the Cairn watchlist.

## 2.2.0, November 21, 2026

- HexStrike added in `frameworks/hexstrike/`: 20 indicators, 4 KQL hunts, 2 analytics rules, 3 Sigma rules, Suricata and YARA, from a review of the HexStrike source code (0x4m4/hexstrike-ai at d689933) and reporting by Check Point, GTIG, Elastic and Threat Landscape.
- The HexStrike user agents that 1.0.0 listed as a related framework under ARTEX now belong to the `hexstrike` framework.

## 2.1.0, November 21, 2026

- PentAGI added in `frameworks/pentagi/`: 39 indicators, 5 KQL hunts, 2 analytics rules, 3 Sigma rules, Suricata and YARA, from a review of the PentAGI source code (vxcontrol/pentagi at cffed94) and reporting by GTIG, Elastic, Talos, Hunt.io, RST Cloud, GitGuardian and Threat Landscape.
- New behavior hunt: a server calling back to the address that was probing it, which covers reverse shells to PentAGI's worker ports and to Cairn's host network.
- Correction carried into the indicators: the PentAGI console certificate's issuer is `CN=PentAGI CA`; the server certificate itself is `CN=localhost`, `O=PentAGI`, SAN `pentagi.local`.
- Three exposed consoles run ARTEX and PentAGI on one server and are tagged with both frameworks.

## 2.0.0, November 21, 2026

The repository becomes Agentic Attack Detections and covers more than one framework. It was `artex-detections`; GitHub redirects the old address.

- ARTEX rules moved from the root to `frameworks/artex/` (Sigma, Sentinel, Splunk, Elastic, Zeek, Suricata, YARA, osquery, tests and the ARTEX docs). `iocs/indicators.csv` and `feeds/` kept their paths.
- Cairn added in `frameworks/cairn/`: 71 indicators, 6 KQL hunts, 2 analytics rules, 3 Sigma rules, Suricata and YARA, from a review of the Cairn source code and reporting by NorForge, Gambit Security, JPCERT/CC and Scutum.
- New `behaviors/` folder for rules that do not depend on one framework: coding agents in bypass mode starting attack tools, agent CLIs calling model gateways from servers, Claude Code's page reader next to scanning, rotating-proxy probing, configuration and backup theft with WSUS probes, and Kerberos enumeration with SMB or WinRM fan-out.
- `iocs/indicators.csv` gains a `framework` column as its last column. `38.244.50.120` is shared by ARTEX and Cairn reporting and carries both.
- The Sentinel watchlist alias is now `AGENTIC_IOCs` for all frameworks; each framework's watchlist sweep filters it. Re-upload `feeds/sentinel-watchlist.csv` if you uploaded it as `ARTEX_IOCs`.
- `feeds/by-framework/` has the plain lists per framework. The STIX bundle has one tool per framework.
- Generated address rules and Zeek intel moved into each framework folder. `generated/` is now split by framework and `behaviors`.
- `docs/adding-a-framework.md` describes the layout and number ranges for the next framework.

## Unreleased

- Every branded indicator now names the publication it first appeared in: Datadog Security Labs (November 9, 2026) for the `artex-*` user agents and S3 placeholder names, Wiz Research (October 22) for `/zzz-nonexistent-xyz123`, `ReconProbe/1.0` and `norma/0.4`, Microsoft (October 21) for `azure-toolkit/1.0`, and Eye Security (November 12) for `X-ARTX-KEY`, `### ARTX-AGENT`, the probe markers and `ArtExVerify/1.0`. No indicator was removed.
- Context corrected: these strings are chosen at run time by the agents or the operator, which is why they are absent from the public code. 1.1.0 described them as coming from modified builds.
- `Mozilla/5.0 (compatible; ArtExVerify/1.0)` raised to high confidence, from Eye Security's primary report.
- New section in `docs/source-code-signals.md`: where the branded strings come from.

## 1.1.0, November 21, 2026

Detections drawn from a review of the ARTEX source code (BaaRai/ARTEX at f787b5f and the BaaRai/Norma v0.4.11 agent library it builds against). See [`docs/source-code-signals.md`](docs/source-code-signals.md).

- 31 new indicators in `iocs/indicators.csv`, each with the file it comes from: the `artex-update-check` user agent, the `X-Keenable-Title: ARTEX` header, the recording proxy credential `artex-pace:artex-pace`, the `__artex-exec-drop` launcher argument and `artex-exec-` shim folder, prompt and envelope markers in model requests, more tool function names, the console title and icon hash, port 8788, skill script names and the S3 archive prefix. Feeds rebuilt.
- Context of `norma/0.4` and both `spa-api-recon` user agents now points at the code that sends them.
- The branded user agents from 1.0.0 (`artex-pentest/1.0` and the rest) are now marked as coming from modified builds: they do not appear in the upstream ARTEX code. `artex-enrich/1.0` context corrected: upstream enrichment sends `Go-http-client/1.1`.
- New hunts:
  - 23 norma page reads and the Go enrichment probe that follows them.
  - 24 the ARTEX container toolchain seen from one source (refines 17).
  - 25 request rates that match the ARTEX noise profiles.
  - 26 headless browsers and ARTEX clients signing in, and the pause while a person relays the MFA code.
  - 27 accounts registered by a source that is also probing the application.
  - 28 ARTEX running on a monitored host (refines 20).
  - 29 ARTEX console and side-channel traffic in outbound proxy logs.
  - 30 bracketed-paste bytes in shell input.
- New analytics rules: ARTEX code-default user agents, and the ARTEX agent shell or proxy credential on a host.

## 1.0.0, November 20, 2026

First public release.

- 184 indicators in `iocs/indicators.csv`, each with its source, confidence and review date, built into STIX 2.1, a Sentinel watchlist, a Splunk lookup, a Zeek intel file, Suricata address rules and plain lists.
- 31 Sigma rules and 5 Sigma correlations, converted to Splunk, Sentinel and Elastic in `generated/`.
- 22 Microsoft Sentinel and Defender XDR hunts and 5 scheduled analytics rules.
- 9 Elastic ES|QL hunts and 5 Elastic detection rules.
- A Splunk app with 15 saved searches and macros.
- A Zeek detection script, 27 Suricata rules, 4 YARA rules and an osquery pack.
- Network tests against a synthetic pcap for Zeek and Suricata.
