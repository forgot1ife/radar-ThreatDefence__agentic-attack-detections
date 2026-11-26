# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| NyxStrike user agents and `<xssTest123>` probe | Web, WAF, proxy, sign-in, CloudTrail | S | N | N | I | Y |
| StingXSS and BreachSQL markers, OpenAPI discovery user agent | Web, WAF, proxy | S | N | N | I | Y |
| Generated exploit user agent `Mozilla/5.0 (Compatible Exploit)` | Web, WAF, proxy | hexstrike | hexstrike | hexstrike | hexstrike | hexstrike |
| NyxStrike server, MCP client and the tools it starts | EDR | S | N | | | Y |
| `which` burst from the tool check | EDR | | N | | | |
| Data folder, log, browser screenshots | EDR, disk | S | N | | | |
| Local abliterated model `nyxstrike-ai` | EDR | | N | | | |
| Server answering `/health`, `/ping`, `/web-dashboard`, or `401` without a token | Network | | | N | | |
| Tool API `/api/tools/` on 8888 | Network, proxy | hexstrike | hexstrike | hexstrike | | |
| AI session requests and update check | Network, proxy | S | N | N | | |
| Exposed console (title, icon) | Internet scan | | | N | | |
| Model traffic from the NyxStrike host | Proxy, TLS | behaviors | behaviors | | behaviors | |
