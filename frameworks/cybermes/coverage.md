# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| `./cybermes` launcher, Docker image Hermes (`/opt/hermes-venv/bin/hermes gateway run`) | EDR | S | N, analytics | | | |
| `cybermes-mcp` MCP server and Go tools (`smart_pipe`, `search_knowledge`) | EDR | S | N, analytics | | | |
| Scanners started with `cybermes-mcp`'s argument order | EDR | S | N | | | |
| `~/.cybermes/`, auto-loaded skill, recon and report files | EDR (file events) | S | N, analytics | | | |
| Persona, config, source, MCP binary and reports on disk | Disk | | | | | Y |
| Engine and audit-script user agents on your web servers | Web, WAF | S | N | N | | |
| Same user agents from your network (and crt.sh queries) | Proxy (TLS inspection for HTTPS) | S | N | N | | |
| AI gateway audit canary origin | Web, WAF, IDS | | N | N | | |
| npm update check and MCP binary download | Proxy with TLS inspection | S | N | N | | |
| Persona and MCP tool names in model requests | TLS-inspecting proxy, AI gateway | | | N | | |
| Hermes with attack tools, Telegram gateway, dashboard | EDR, proxy, IDS | [hermes](../hermes) | [hermes](../hermes) | [hermes](../hermes) | | |
| Model traffic from the Cybermes host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Scanner traffic against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
| Exposed console | none of its own: `cybermes-mcp` is stdio only; only the inherited Hermes dashboard, if started | | | | | |
