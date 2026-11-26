# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Codex or Claude Code CLI started with Mitsu's MCP server or prompt | EDR | S | N, analytics | | | |
| Shell tool `/bin/bash -o pipefail -c` (and the sudo form) under the Mitsu process | EDR | S | N | | | |
| Armory scanners started directly by the Mitsu process | EDR | S | N | | | |
| Managed SearXNG container and volume | EDR | S | N, analytics | | | |
| Session, configuration, provider work folder and Armory files | EDR (file events) | S | N | | | |
| Session files, reports and attack-surface map on disk | Disk | | | | | Y |
| Mitsu source (PyPI package or clone) | Disk | | | | | Y |
| Page fetch user agent on your web servers | Web, WAF | S | N | N | | |
| Page fetch and search user agent from your network | Proxy (TLS inspection for HTTPS) | S | N | N | | |
| Update check to pypi.org | Proxy with TLS inspection | S | N | N | | |
| System prompt and MCP tool names in model requests | TLS-inspecting proxy, AI gateway | | | N | | |
| Model traffic from the Mitsu host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Scanner traffic against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
| Exposed console | none: Mitsu binds its MCP server and SearXNG to 127.0.0.1 and has no web UI | | | | | |
