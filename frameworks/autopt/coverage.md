# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| AutoPT CLI, console process or scan steps on a host | EDR | S | N | | | Y |
| AutoPT run results | EDR, disk | S | N | | | Y |
| Page reader user agents against your sites | Web, WAF, proxy | S | N | N | | |
| Vulhub PoC fetch from the operator host | Proxy (TLS inspection) | S | N | | | |
| Exposed console: page, configuration with keys, system info, agent runs | Network, proxy | S | N | N | | |
| Model traffic from the AutoPT host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| nmap, xray and curl against your sites | Web, WAF, firewall | behaviors | behaviors | behaviors | behaviors | |
