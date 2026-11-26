# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Web scanner user agent against your sites | Web, WAF, proxy | S | N | N | I | |
| Web scanner probe paths, parameters and values | Web, WAF | S | N | N | | |
| Login enumeration and lockout probes (request bodies) | Network (decrypted), WAF | | | N | | |
| Claude Code session, launcher supervisors, libexec helpers and pipelines | EDR | S | N | | | |
| Run folders, generated exploits and patches, configuration and per-user state | EDR, disk | S | N | | | Y |
| Claude Code settings and PoC templates RAPTOR ships or writes | Disk | | | | | Y |
| RAPTOR client user agents to registries, GitHub, OSV and NVD | Proxy (TLS inspection) | S | N | N | I | |
| Model traffic from the RAPTOR host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Fuzzers, debuggers and attack tools started by the agent | EDR | behaviors | behaviors | | | |
