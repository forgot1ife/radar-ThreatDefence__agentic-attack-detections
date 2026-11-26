# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Basic-auth probe user agent `cyber` / `aiscan`, then password guessing | Web, WAF, proxy | S | N, A | N | | |
| fetch tool user agent | Web, WAF, proxy | S | N, A | N | | Y |
| curl tool Chrome 133 header set | Network, WAF | | N (context) | N | | |
| MCP client to configured MCP servers | Network | | | N | | Y |
| cyber-scan, cyber-harness, cyber-audit processes, node command lines, Quick Connect installer | EDR | S | N | | | Y |
| Pid file, MITM CA, command logs, arsenal tools, inbox and JEV stores, Hub database | EDR, disk | S | N | | | Y |
| Hub listening (8080, IOA 8765) | EDR | | N | | | |
| Hub page, CORS headers, 401 answer, login cookie | Network, internet scan | | | N | | Y |
| Node and browser traffic to a Hub, release downloads | Network, proxy | S | N | N | | |
| Model traffic from the cyber-harness host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Scanners and tools against your sites (gogo, spray, zombie, nuclei, ...) | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |

S: Sigma rule. N: KQL hunt or Suricata rule. A: Sentinel analytics rule. Y: YARA rule.
