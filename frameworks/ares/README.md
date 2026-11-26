# Ares Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**Ares** ([dreadnode/ares](https://github.com/dreadnode/ares), reviewed at `786b2987`, October 28, 2026). Dreadnode's LLM-coordinated platform for Active Directory attacks: an orchestrator model hands tasks over Redis and NATS to seven worker roles (recon, credential_access, cracker, acl, privesc, lateral, coercion), which run impacket, NetExec, certipy, bloodyAD, pywhisker, Responder, hashcat and about 50 other tools until every forest root domain controller has been dumped. The same binary has a blue team mode that investigates those attacks in Loki and Prometheus. It is written in Rust, ships as one `ares` binary and is deployed on a Kali attack box on EC2 or in Kubernetes.

Ares has no web console or API server, so there is nothing to find on the internet. What sets it apart from the tools it drives is the residue its own wrappers leave: every machine account it adds is named `ARES-<8 hex>$`, its GPO probe task is `ARES_GPO_Probe_<8 hex>`, its SQL Server hive dump uses one fixed encoded PowerShell command with `___ARES_HIVE_` delimiter rows, and its Shadow Credentials exports use the passphrase `ares-shadow-cred`. Those are the signals in this folder. Ares ships its own detections for the techniques themselves (58 LogQL templates in `ares-core/src/detection/detections.yaml`); this folder does not copy them. This review did not search for vendor or CERT reports of Ares in real intrusions.

| | |
|---|---|
| Tool | [dreadnode/ares](https://github.com/dreadnode/ares), reviewed at `786b2987`. MIT. Not on crates.io, PyPI or Docker Hub; the docs name images under `ghcr.io/l50/` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA |
| Docs | [What Ares leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the source code, not from captured runs. Baseline every rule on your own data before alerting |

## What Ares leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Machine accounts | `ARES-<8 uppercase hex>$`, password `Ar<16 hex>!7z`, added with `impacket-addcomputer` over SAMR and then used for S4U (events 4741, 4768, 4769) | `ares-tools/src/privesc/delegation.rs:321-378` |
| GPO probe task | `pygpoabuse ... -command "cmd /c whoami" -taskname ARES_GPO_Probe_<8 hex> -f`, in SYSVOL and on every computer the GPO reaches (event 4698) | `ares-cli/src/orchestrator/automation/gpo.rs:143-160` |
| SQL Server hive dump | `xp_cmdshell` running `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABFAHIAcgBv...` (always the same), `reg save HKLM\SAM %TEMP%\a.hive` and the SYSTEM and SECURITY hives to `b.hive` and `c.hive`, output between `___ARES_HIVE_SAM_B64___` rows | `ares-tools/src/lateral/mssql.rs:345-385,480-497` |
| Shadow Credentials | `pywhisker ... --filename /tmp/ares_shadowcred_<token>_<account> --pfx-password ares-shadow-cred`, then `certipy auth -pfx ... -password ares-shadow-cred` | `ares-tools/src/acl.rs:249-270,456-480` |
| Crack jobs | `hashcat ... --session ares-hc-<pid>-<n>`, `john --session=ares-jtr-<pid>-<n>` | `ares-tools/src/cracker.rs:18-30,1073` |
| Tickets | `/tmp/ares-tickets/<src>__<tgt>__<user>.ccache` and `python3 <dir>/cross_realm_tgs.py --in-ccache ...` | `ares-tools/src/privesc/trust.rs:133,440-470` |
| ESC8 probe | `HEAD /certsrv/certfnsh.asp` with no `User-Agent` header | `ares-tools/src/privesc/adcs.rs:1343-1384` |
| Services | `/usr/local/bin/ares orchestrator` in `ares-orchestrator.service`, `/usr/local/bin/ares worker` in `ares@<role>.service`, slice `system-ares.slice`, logs in `/var/log/ares/` | `.taskfiles/ec2/scripts/launch-orchestrator.sh.tmpl:73-108`, `ansible/roles/redis/templates/ares@.service.j2` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: Ares on a host, Ares residue in Active Directory, SQL Server and Windows logs, the ESC8 probe in web and proxy logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: an `ARES-<8 hex>$` machine account created (event 4741) |
| [`sigma/`](sigma) | 9 Sigma rules for process and file events on the attack box and on a SQL Server |
| [`suricata/`](suricata) | 6 rules: the minted account in SMB and Kerberos, the GPO probe task in SMB, the hive dump request and its result rows in TDS, and the ESC8 probe |
| [`yara/`](yara) | Rules for the ares binary and source, its cross-realm ticket helper, its clock shim, the hive dump script and its config |

Ares' Kerberoasting, AS-REP roasting, DCSync, relaying and ADCS abuse look like the same attacks from any other tool; the cross-framework rules in [`behaviors/`](../../behaviors) and Ares' own detection templates cover those. Model API calls from servers are covered there too.

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `ares`.

## Limits

- Ares is built for authorized tests of Active Directory labs (its benchmarks target Dreadnode's DreadGOAD range). A match means Ares, not necessarily an attacker. Check who runs it and against what.
- The fixed names are in Ares' code, not in a config file, so they survive a change of models or prompts but not a fork that edits them.
- The SMB, Kerberos and TDS Suricata rules need cleartext traffic: SMB 3 encryption, forced TDS encryption or LDAPS hide them. The Windows event rules need the right audit policy (computer account management, other object access, PowerShell script block logging).
- Ares runs on Linux. The attack box rules need an EDR or auditd that reports Linux process command lines.
