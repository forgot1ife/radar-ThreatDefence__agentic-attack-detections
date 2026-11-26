# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| CHYing-agent dashboard, contest runners and tools container on a host | EDR | S | N | | | Y |
| Python tool calls in its Kali container (`echo <base64> \| base64 -d \| python3`) | EDR | S | N | | | |
| GhidraMCP REST (8089) and MCP bridge (8766) on all interfaces | EDR | S | N | | | |
| Work folder, database and logs | EDR, disk | S | N | | | Y |
| Web terminal probe, exit marker and delimiter in a target's terminal | Network (cleartext or decrypted WebSocket), shell history, Syslog | | N | N | | Y |
| Exposed dashboard (title, OpenAPI document, statistics API) | Network, proxy | | N | N | | |
| Orchestrator prompt and tool names in model requests | Network (TLS inspection) | | | N | | |
| Model traffic from the CHYing-agent host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Kali tools against your sites (httpx, nuclei, ffuf, sqlmap, Metasploit) | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |

CHYing-agent has no published addresses or domains and sends no telemetry, so there are no generated address rules or Zeek intel entries for it.
