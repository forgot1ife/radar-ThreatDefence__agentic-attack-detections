# Coverage

Which behavior each platform covers. S = Sigma rule (converted in `generated/`), N = hand-written native query or rule, I = indicator feed.

A row marked shared has its rules in [`behaviors/`](../../behaviors), where they cover every framework and still cover ARTEX ([where each one went](README.md#moved-to-shared-behaviors)).

| Behavior | Data source | Sigma | Sentinel / Defender | Splunk | Elastic | Zeek | Suricata |
|---|---|---|---|---|---|---|---|
| ARTEX user agents | Web, proxy, sign-in, CloudTrail, Okta | S | N | N | N | N, I | N |
| Placeholder probe paths | Web, WAF, S3 access | S | N | N | N | N | N |
| alg:none JWT spray on SSO routes (shared) | Web, WAF | S | N | N | N | N | N |
| OAuth callback probe | Web, WAF | S | N | N | N | N | N |
| X-ARTX-KEY header and probe markers | Web, WAF | S | | | | N | N |
| User agent family burst from one source (shared) | Web, WAF, proxy | | N | N | N | | |
| Password spray at a one-second rhythm (shared) | Entra ID, Okta | S (count) | N (rhythm) | N (rhythm) | N (rate) | | |
| Spray that ends in a success (shared) | Entra ID | | N | N | | | |
| Service principal secret guessing then success (shared) | Entra ID SP sign-ins | | N | | | | |
| One application hitting many resources (shared) | Entra ID SP sign-ins | | N | | | | |
| Application adds credentials or assigns itself a role (shared) | Entra ID audit | S | N | N | | | |
| Scripted Microsoft Graph bursts (shared) | Graph activity logs | | N | | | | |
| Bulk Key Vault secret reads (shared) | Key Vault diagnostics | | N | N | | | |
| CloudWatch secret search (shared) | CloudTrail | S | N | N | N | | |
| EC2 DryRun burst (shared) | CloudTrail | S (correlation) | N | N | N | | |
| Access denied sweep (shared) | CloudTrail | S (correlation) | N | N | N | | |
| Cognito sign-up abuse (hunt shared) | CloudTrail | S | N | N | N | | |
| Azure validate sweep and Kudu sign-ins (shared) | Azure activity, App Service | S (correlation) | N | N | | | |
| Web or database service spawning shells (shared) | EDR, Sysmon, auditd | S | N | N | N | | |
| ARTEX artifact names on hosts | EDR, Sysmon | S | N | N | N | | |
| JSP web shell names, BLOODALCHEMY files | EDR, Sysmon | S | N | N | N | | |
| svchost outside System32 (shared) | EDR, Sysmon | S | | | | | |
| Remote tasklist fan-out (shared) | EDR, Sysmon | S (correlation) | N | | | | |
| Kerberoasting, DCSync, WinRM fan-out (shared) | Domain controllers, EDR | | N | | | | |
| Callbacks to webhook and DNS log services (shared) | DNS, proxy | S | N | | | | N |
| C2 domains and addresses | DNS, TLS, network | S | N, I | I | I | I | N, I |
| ARTEX console on your network | Network, EDR | | N | | | N | N |
| Backdoored ARTEX container images | EDR, container inventory | | N | | | | |
| SQL Server toolkit: xp_cmdshell, fake system binaries, Edge update task names, payload hosts (partly shared) | EDR, Sysmon, DNS, HTTP | S | N | | | I | N, I |
| norma page reads and the Go enrichment probe | Web, WAF, proxy, sign-in, Graph | | N | | | | |
| ARTEX container toolchain from one source | Web, WAF, proxy | | N | | | | |
| Request rates matching the noise profiles | Web, WAF, proxy | | N | | | | |
| Headless browser sign-ins and relayed MFA | Entra ID | | N | | | | |
| Accounts registered while probing | Web, WAF | | N | | | | |
| ARTEX agent shells, recording proxy, resolver fan-out, S3 archives | EDR, Defender TVM, CloudTrail | | N | | | | |
| Console, update check and chat-ops alerts in proxy logs | Outbound proxy | | N | | | | |
| Bracketed-paste bytes in shell input | Syslog, auditd, EDR | | N | | | | |
| Files on disk | Disk, container layers | | | | | | YARA, osquery |
