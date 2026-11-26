# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| CAI CLI, install, loop runner or Kali container on a host | EDR | S | N | | | Y |
| Shell commands run by the cai process | EDR | | N | | | |
| Session logs, API auth database and run folders under ~/.cai | EDR, disk | S | N | | | Y |
| Continuous-ops systemd user unit | EDR, disk | S | N | | | Y |
| Telemetry upload to logs.aliasrobotics.com | DNS, TLS, proxy, EDR | S | N | N | I | Y |
| Alias gateway (licence check, alias1 model) and private package index | DNS, TLS, proxy, EDR | S | N | N | I | Y |
| fetch_url user agent on your sites | Web, WAF, proxy | S | N | N | | |
| Exposed CAI API (cai --api) | Network, proxy | | N | N | | |
| Model traffic from the CAI host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Stock tools and page reads against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
