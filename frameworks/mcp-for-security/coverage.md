# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Wrapper started (`node <dir>/<tool>-mcp/build/index.js <tool>`) or image `cyprox/mcp-for-security` run | EDR | S | A, N | | | |
| Tool run by a wrapper (nuclei/httpx/katana `-silent`, `scout aws --force --no-browser`, commix with the URL twice, gowitness `--write-none`, nmap, masscan, sqlmap and others) | EDR | S | N | | | |
| Set-up and work files (`mcp-config.json`, its `.tmp` files, `/opt/commix`, `/opt/smuggler`, gowitness `urls.txt`) | EDR, disk | | N | | | Y |
| Wrapper sources and builds, MobSF client, set-up scripts | Disk | | | | | Y |
| Wrapper tool descriptions in model requests | Network (TLS inspection) | | | N | | |
| MobSF wrapper's requests to the operator's MobSF | Network, proxy | | N | N | | |
| nuclei wrapper's tag lookup on raw.githubusercontent.com | Proxy (TLS inspection) | S | N | | | |
| Model traffic from the MCP host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Stock tools against your sites (nmap, masscan, nuclei, httpx, katana, ffuf, sqlmap, commix, smuggler, wpscan, sslscan, gowitness) | Web, WAF, proxy, network | behaviors | behaviors | behaviors | behaviors | |

S = Sigma rule here, N = hunting query or Suricata rule here, A = analytics rule here, Y = YARA rule here, behaviors = cross-framework rules in `behaviors/`.

MCP for Security has no published addresses or domains, sends no telemetry and has no listener, so there are no generated address rules, Zeek intel entries or exposure searches for it.
