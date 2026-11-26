# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Agent command, front end, image | EDR | S | N | | | Y |
| General module tool commands (dalfox callback, feroxbuster word list) | EDR | S | N | | | Y |
| Operation folders, report and front-end settings | EDR, disk | S | N | | | Y |
| Dalfox blind XSS callback in requests to your sites | Web, WAF, proxy | S | N | N | | |
| Dalfox callback looked up from your network (payload ran) | DNS | S | N | N | I | |
| Agent traffic to its Langfuse (default key, prompt names, trace export) | Network, proxy | S | N | N | | |
| Exposed Cyber-AutoAgent Langfuse (default admin login, seeded project) | Network, proxy | S | N | N | | Y (compose file) |
| Threat emulation markers on hosts it reached | EDR | S | N | | | |
| Model traffic from the agent host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Kali tools and curl against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
