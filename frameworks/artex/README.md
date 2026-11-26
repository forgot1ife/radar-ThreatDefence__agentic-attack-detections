# ARTEX Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **ARTEX**, the open-source agentic AI penetration testing framework that state-aligned and criminal groups have used in real intrusions since August 2026. Includes its renamed builds and forks: ScopeWeaver, LUCK, Guanlan SEC, AntiFox and ARTEX PRO.

Maintained by [ThreatDefence](https://threatdefence.com). The full advisory, with how ARTEX works, who uses it and what each hunt looks for, is at
**https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting**

| | |
|---|---|
| Actors | Storm-0940, Storm-3358, VAPOR PANDA, an unattributed actor targeting South Korean finance, and financially motivated operators |
| Targets | Microsoft 365 and Entra ID, Okta, AWS, Azure, web applications, Active Directory |
| Platforms | Sigma, Microsoft Sentinel and Defender XDR, Splunk, Elastic, Zeek, Suricata, YARA, osquery, STIX 2.1 |
| Status | Experimental. Tested for syntax, conversion and against a synthetic pcap. Baseline every rule on your own data before alerting |

## AntiFox (added in 2.6.0)

AntiFox ([AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox)) is ARTEX 0.1.1 renamed and maintained as its own project, so every ARTEX rule applies to it. Arctic Wolf Labs tied AntiFox consoles on Alibaba Cloud to intrusions in which an IIS web shell read `web.config` secrets and stolen AWS keys were used for broad enumeration that read a production secret. **Hunt 31** covers that sequence. The indicators add the two Arctic Wolf addresses, exposed AntiFox consoles, the console title, image `ghcr.io/antifox-ai/antifox`, its `antifox-enrich/1.0` and `antifox-selfupdate` user agents, its unauthenticated recording proxy on 8788 and the web shell file patterns.

## What's new in 1.1.0

Version 1.1.0 adds detections drawn from the ARTEX source code itself, not only from reported intrusions. [`docs/source-code-signals.md`](source-code-signals.md) lists every signal with the file it comes from, the log source that sees it and how easily an operator can remove it. The article that explains them is at **https://threatdefence.com/article/artex-source-code-signals-deep-hunting**.

- **Hunts 23 to 30:** norma page reads and the Go enrichment probe, the ARTEX container toolchain seen from one source, request rates that match the ARTEX noise profiles, headless browser sign-ins and relayed MFA, accounts registered while probing, ARTEX running on a monitored host, console traffic in proxy logs, and bracketed-paste bytes in shell input.
- **Two analytics rules:** ARTEX code-default user agents, and the ARTEX agent shell or proxy credential on a host.
- **31 indicators** with the source file for each, and corrected context for `norma/0.4` and the `spa-api-recon` user agents.

The branded user agents, markers and file paths in the 1.0.0 indicators (for example `artex-pentest/1.0`, `X-ARTX-KEY` and `C:\ProgramData\artx5v\`) do not appear in the public ARTEX code. They come from reporting on intrusions, where the agents chose them at run time, and each one now names the publication it first appeared in ([where the branded strings come from](source-code-signals.md#where-the-branded-strings-come-from)). Keep hunting for them, and expect a careful operator to look like the signals in 1.1.0.

See [`CHANGELOG.md`](../../CHANGELOG.md) for the full list.

## What is in the repository

| Folder | Contents |
|---|---|
| [`iocs/indicators.csv`](../../iocs/indicators.csv) | 215 indicators: user agents, request artifacts, host artifacts, strings from the ARTEX source code, hashes, favicon hashes, domains, URLs and addresses. Each row has its source, confidence and a review date for addresses. This file is the single source for every feed |
| [`feeds/`](../../feeds) | Generated from the CSV: STIX 2.1 bundle, Sentinel watchlist and plain lists of addresses, domains, URLs, user agents and hashes |
| [`sigma/`](sigma) | 16 Sigma rules for web, proxy, process, file, DNS, AWS, Entra ID and Okta logs. The general ones moved to [`behaviors/`](#moved-to-shared-behaviors) |
| [`generated/`](../../generated) | The Sigma rules converted to Splunk SPL, Sentinel ASIM KQL and Elastic ES\|QL and Lucene. [`SUMMARY.md`](../../generated/SUMMARY.md) shows which rule converted to which backend |
| [`sentinel/hunting/`](sentinel/hunting) | 15 KQL hunts for Microsoft Sentinel and Defender XDR advanced hunting. Hunts 23 to 30 come from a review of the ARTEX source code ([`docs/source-code-signals.md`](source-code-signals.md)) |
| [`sentinel/analytics/`](sentinel/analytics) | 3 scheduled analytics rules in the Sentinel template format. Four more moved to [`behaviors/`](#moved-to-shared-behaviors) |
| [`splunk/`](splunk) | The hand-written ARTEX Splunk searches and macros. They ship in the [Splunk app](../../deploy/splunk) with the searches for every other framework |
| [`elastic/`](elastic) | 9 ES\|QL hunts and 5 detection rules in the Elastic detection-rules TOML format |
| [`zeek/`](zeek) | A detection script that raises notices for ARTEX traffic, and an Intel framework file |
| [`suricata/`](suricata) | 27 rules for user agents, probe artifacts, console pages, C2 domains and toolkit payload hosts, plus generated address rules |
| [`yara/`](yara) | 4 rules for ARTEX binaries, console assets, the backdoored console and probe files |
| [`osquery/`](osquery) | A pack for probe files and accounts, web service child shells, listening consoles and container images |
| Docs | [Where to start](hunting-order.md), the [coverage matrix](coverage.md) and the [signals in the ARTEX source code](source-code-signals.md) |
| [`tools/`](../../tools) | Feed builder, Sigma converter and validator |
| [`tests/`](tests) | A synthetic pcap and the Zeek and Suricata tests |

## Moved to shared behaviors

Many of the ARTEX rules never looked for ARTEX itself. They look for things any agent does with stolen access: password sprays, cloud permission sweeps, web services starting shells, Kerberoasting. They now sit in [`behaviors/`](../../behaviors), so they run for every framework, and they keep their ids, so a redeploy updates them in place. This folder keeps the rules that need ARTEX's own names, files, traffic or code.

| Was here | Now |
|---|---|
| Hunt 02, `02-password-spray-at-a-fixed-rhythm.kql` | [Hunt 10](../../behaviors/sentinel/hunting/10-password-spray-at-a-fixed-rhythm.kql) |
| Hunt 03, `03-a-spray-that-ends-in-a-successful-sign-in.kql` | [Hunt 11](../../behaviors/sentinel/hunting/11-a-spray-that-ends-in-a-successful-sign-in.kql) |
| Hunt 05, `05-applications-changing-their-own-access.kql` | [Hunt 13](../../behaviors/sentinel/hunting/13-applications-changing-their-own-access.kql) |
| Hunt 06, `06-scripted-microsoft-graph-bursts-by-an-application.kql` | [Hunt 25](../../behaviors/sentinel/hunting/25-scripted-microsoft-graph-bursts-by-an-application.kql) |
| Hunt 07, `07-bulk-key-vault-secret-reads.kql` | [Hunt 15](../../behaviors/sentinel/hunting/15-bulk-key-vault-secret-reads.kql) |
| Hunt 08, `08-cloudwatch-log-searches-with-a-stolen-aws-key.kql` | [Hunt 18](../../behaviors/sentinel/hunting/18-cloudwatch-log-searches-with-a-stolen-aws-key.kql) |
| Hunt 09, `09-cognito-sign-up-abuse-and-the-discovery-sweep-after-it.kql` | [Hunt 19](../../behaviors/sentinel/hunting/19-cognito-sign-up-abuse-and-the-discovery-sweep-after-it.kql) |
| Hunt 11, `11-web-and-database-services-starting-shells-and-download-tools.kql` | [Hunt 21](../../behaviors/sentinel/hunting/21-web-and-database-services-starting-shells-and-download-tools.kql) |
| Hunt 12, `12-servers-calling-webhook-and-tunnel-services-or-downloading-f.kql` | [Hunt 23](../../behaviors/sentinel/hunting/23-servers-calling-webhook-and-tunnel-services.kql) |
| Hunt 13, `13-scripts-written-into-web-directories.kql` | [Hunt 22](../../behaviors/sentinel/hunting/22-scripts-written-into-web-directories.kql) |
| Hunt 14, `14-aws-permission-testing-and-the-foothold-that-follows.kql` | [Hunt 17](../../behaviors/sentinel/hunting/17-aws-permission-testing-and-the-foothold-that-follows.kql) |
| Hunt 15, `15-azure-capability-checks-validate-sweeps-and-kudu-sign-ins.kql` | [Hunt 16](../../behaviors/sentinel/hunting/16-azure-capability-checks-validate-sweeps-and-kudu-sign-ins.kql) |
| Hunt 16, `16-kerberoasting-dcsync-and-winrm-fan-out.kql` | [Hunt 24](../../behaviors/sentinel/hunting/24-kerberoasting-dcsync-and-winrm-fan-out.kql) |
| Hunt 17, `17-user-agent-family-burst-from-one-source.kql` | [Hunt 20](../../behaviors/sentinel/hunting/20-user-agent-family-burst-from-one-source.kql) |
| Hunt 18, `18-service-principal-secret-failures-then-success.kql` | [Hunt 12](../../behaviors/sentinel/hunting/12-service-principal-secret-failures-then-success.kql) |
| Hunt 19, `19-one-application-hitting-many-resources.kql` | [Hunt 14](../../behaviors/sentinel/hunting/14-one-application-hitting-many-resources.kql) |
| Analytics rule `artex-cloudwatch-secret-search.yaml` | [`cloudwatch-secret-search.yaml`](../../behaviors/sentinel/analytics/cloudwatch-secret-search.yaml) |
| Analytics rule `artex-ec2-dryrun-burst.yaml` | [`ec2-dryrun-burst.yaml`](../../behaviors/sentinel/analytics/ec2-dryrun-burst.yaml) |
| Analytics rule `artex-fixed-rhythm-password-spray.yaml` | [`fixed-rhythm-password-spray.yaml`](../../behaviors/sentinel/analytics/fixed-rhythm-password-spray.yaml) |
| Analytics rule `artex-service-principal-self-role-assignment.yaml` | [`service-principal-self-role-assignment.yaml`](../../behaviors/sentinel/analytics/service-principal-self-role-assignment.yaml) |
| Sigma: the 5 correlations (AWS access denied sweep, EC2 DryRun burst, Azure validate sweep, Entra ID password spray, remote tasklist fan-out) | [`behaviors/sigma/correlations/`](../../behaviors/sigma/correlations) |
| Sigma: AWS access denied, EC2 DryRun, CloudWatch secret search | [`behaviors/sigma/cloud/aws/`](../../behaviors/sigma/cloud/aws) |
| Sigma: Azure validate, application credential added, role assigned to a service principal, Entra ID sign-in failure | [`behaviors/sigma/cloud/azure/`](../../behaviors/sigma/cloud/azure) |
| Sigma: web or database service starts a shell (Linux, Windows, SQL Server), remote tasklist, svchost and system binaries in the wrong folder | [`behaviors/sigma/process_creation/`](../../behaviors/sigma/process_creation) |
| Sigma: callback services in DNS | [`behaviors/sigma/dns_query/`](../../behaviors/sigma/dns_query) |
| Sigma: unsigned (alg none) token probe | [`behaviors/sigma/web/`](../../behaviors/sigma/web) |

The ARTEX hunts that stayed keep their numbers, so the gaps in the numbering are the hunts that moved.

## Quick start

**Microsoft Sentinel.** Upload `feeds/sentinel-watchlist.csv` as a watchlist with the alias `AGENTIC_IOCs` and the search key `value`, then run `sentinel/hunting/21-watchlist-indicator-sweep.kql` (it filters the watchlist to ARTEX rows). Import the analytics rules from `sentinel/analytics/` and the shared behaviors from [`behaviors/sentinel/`](../../behaviors/sentinel), or deploy both with the [Sentinel templates](../../deploy/sentinel). The hunts also run in Defender XDR advanced hunting where the tables exist.

**Splunk.** Install the [Splunk app](../../deploy/splunk) from the latest release. It has the ARTEX searches, every other framework's, and the indicator lookups. Point the `aad_indexes` macro at your indexes, run each saved search over 30 days, then enable it.

**Elastic.** Paste the ES|QL hunts into Discover. Load the TOML rules with Elastic's detection-rules tooling, or recreate them in Kibana from the query and settings in each file. Fields follow ECS and the AWS, Azure and Elastic Defend integrations.

**Zeek.** Add `@load /path/to/zeek/artex` to `local.zeek`, and load `zeek/intel/artex.intel` through the Intel framework (see [`zeek/README.md`](zeek/README.md)).

**Suricata.** Add `suricata/artex.rules` and `suricata/artex-ip.rules` to your rule files. HTTP rules need cleartext or decrypted traffic. DNS and TLS SNI rules work on encrypted traffic.

**Sigma.** Convert with `sigma convert -t <backend> -p <pipeline> sigma/`, or use the conversions in `generated/`.

**Threat intelligence platforms.** Import `feeds/stix2.1-bundle.json`.

## Confidence

| Level | Meaning | How to use it |
|---|---|---|
| High | Specific to ARTEX: a user agent naming it, its probe artifacts, reported C2 domains, file hashes | Alert |
| Medium | Seen in ARTEX activity but changeable or shared: reported addresses, generic agent SDK user agents, community-reported markers | Alert after baselining, or hunt |
| Low | Legitimate services ARTEX uses: webhook.site, DNS log services, geolocation and AI model APIs | Context for another finding only |

Addresses from cloud and VPS providers are reassigned. Every address has a `review_by` date 180 days after it was reported. Check before you block.

## Testing

```bash
pip install -r tools/requirements.txt
python3 tools/validate.py                              # from the repository root
python3 tools/convert.py
python3 frameworks/artex/tests/make_pcap.py            # regenerate the synthetic pcap
bash frameworks/artex/tests/run_network_tests.sh       # needs zeek and suricata on the PATH
```

Last run: Suricata 8.0.8 and Zeek 9.0.1, all expected alerts and notices, no hit on the benign traffic in the pcap.

The pcap is synthetic. No rule in this repository has been tested against a captured ARTEX intrusion, so treat every rule as experimental until it has run on your own data.

## Contributing

Pull requests are welcome. Add new indicators to `iocs/indicators.csv` with their source, run `python3 tools/build_feeds.py` and `python3 tools/validate.py`, and commit the regenerated files. Report false positives as issues, with the rule name and the shape of the event (no customer data).

## License

MIT. See [LICENSE](../../LICENSE). Each indicator names its source in `iocs/indicators.csv`. Use them in your own products and feeds.

## Disclaimer

Provided as is, without warranty. A match is a lead, not a verdict. Absence of a match does not mean absence of compromise.
