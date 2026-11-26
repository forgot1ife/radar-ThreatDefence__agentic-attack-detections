# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| API server or MCP client started (git checkout or Kali package) | EDR | S | A, N | | | Y |
| Health check lookups and Kali tools run by the API server | EDR | S | N | | | |
| Metasploit run through `/tmp/mks_msf_resource.rc` | EDR | S | A, N | | | |
| Package files, service units and the resource file | EDR, disk | S | N | | | Y |
| Server and client log lines (`Executing command:`) | Syslog, journal | | N | | | |
| API server reached across the network (`/api/command`, `/api/tools/*`, `/health` on 5000) | Network, proxy, firewall | S | N | N | | |
| Exposed API server (health answer, command results, stub route) | Network | | N | N | | |
| MKS tool descriptions and instructions in model requests | Network (TLS inspection) | | | N | | |
| Model traffic from the MCP host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Kali tools against your sites (nmap, gobuster, dirb, nikto, sqlmap, WPScan, hydra, Metasploit) | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |

S = Sigma rule here, N = hunting query or Suricata rule here, A = analytics rule here, Y = YARA rule here, behaviors = cross-framework rules in `behaviors/`.

MCP Kali Server has no published addresses or domains and sends no telemetry, so there are no generated address rules or Zeek intel entries for it.
