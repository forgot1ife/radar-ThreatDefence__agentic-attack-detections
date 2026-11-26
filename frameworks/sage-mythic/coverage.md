# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Proof markers and proof files in Windows command lines (WMI, wmic, cmd) | EDR | S | N | | | |
| Remote execution through a `SageExec_` scheduled task | EDR, Security log 4698 | S | N | | | |
| Encoded marker script (`-EncodedCommand JABFAHIA...`), Defender real-time monitoring off and `C:\Windows\Temp` excluded | EDR | S | N | | | |
| PowerShell marker scripts run through `powerpick` (`CERT_AUTH_METHOD=schannel-ldap`, `New-PSDrive -Name SAGEPROOF`) | PowerShell 4104 | | N | | | |
| ADCS CA key export (`certutil -p SagePfx-v1-... -backupKey`) and certificate enrolment in `sage_cert_enroll_` | EDR | S | N | | | |
| Proof and certificate files written on targets | EDR, disk | S | N | | | Y |
| GPO immediate task with a `sage_gpo_` proof file | EDR, SYSVOL | S | N | | | |
| Sage container and BloodHound MCP processes on the Mythic host | EDR (Linux) | S | N | | | |
| `sage.db`, `.phoenix/phoenix.db`, `.sage_engagement/` on the Mythic host | EDR (Linux), disk | S | N | | | Y |
| Phoenix trace UI exposed (page, Sage spans in responses) | Network, internet scan | | N | N | | |
| Mythic GraphQL queries named by Sage | Network (decrypted) | | | N | | |
| Sage prompts and tool names in model requests | Network (decrypted) | | | N | | |
| Slack findings notice | Network (decrypted) | | | N | | |
| SharpHound 2.13.0 fetched by python-requests | Proxy | S | N | N | | |
| Sage source and prompts | Disk | | | | | Y |

S = Sigma rule, N = Sentinel hunt or analytics rule (or Suricata rule in that column), Y = YARA rule. Zeek intel is generated from `iocs/indicators.csv`; Sage has no address or domain of its own.
