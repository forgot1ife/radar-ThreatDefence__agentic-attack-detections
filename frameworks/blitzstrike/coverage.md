# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Blitz Strike user agents on requests to your sites | Web, WAF, proxy, network | S | N | N | | |
| Default `run_engagement` markers (`evil-blitz.example.com`, `blitzstrike-ssrf-canary`, `X-BlitzStrike`, `bs-marker.example.com`) | Web, WAF, network | S | N | N | | |
| Single-tool markers (`/bs-nonexistent-`, `blitzstrike_pollution_canary_9f3a`, `__blitz_xss__`, `zzblitz`) | Web, WAF, network | S (query string) | N | N | | |
| Your server fetched the SSRF canary from `httpbin.org` | Proxy, network | S | N | N | | |
| Answer of the self-hosted callback listener (`oob-ok`) | Network | | | N | | |
| MCP server, CLI and install on a host | EDR | S | N | | | |
| Tools the MCP server starts (nuclei, interactsh-client, chrome-devtools-mcp, tool installs) | EDR | S | N | | | |
| Callback listener opened on a random port | EDR | | N | | | |
| Home folder, reports, audit log, OpenCode personas | EDR, disk | S | N | | | Y |
| Source, npm bundle or compiled binary | Disk | | | | | Y |
| Exposed web console | n/a: there is none | | | | | |
| Out-of-band lookups from your servers (interactsh) | DNS, EDR | behaviors | behaviors | behaviors | behaviors | |
| nuclei and catalog tools against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
| AI coding client running an MCP server with shell access | EDR | behaviors | behaviors | | | |
