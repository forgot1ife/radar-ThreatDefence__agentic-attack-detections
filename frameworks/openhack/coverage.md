# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| OpenHack command line and background dashboard (both versions) | EDR | S | N | | | |
| Claude Code or Codex started by v2 with its isolation flags | EDR | S | N | | | |
| nmap, sqlmap, nuclei and httpx with v0.2.4's arguments | EDR | S | N | | | |
| `~/.openhack/`, subscription temporary folders, evidence and sandbox override files | EDR, disk | S | N | | | |
| v2 executable or source, v0.2.4 package | Disk | | | | | Y |
| v2 scan reports (findings with source evidence) | Disk | | | | | Y |
| Your hosts resolving or calling `oob.openhack.com` | DNS, EDR, proxy, TLS | S | N | N | I | |
| `oob.openhack.com` or canary markers in requests to your web servers | Web, WAF, network | S | N | N | | |
| Research fetch and `openhack` user agents | Proxy, TLS inspection | S | N | N | I | |
| `api.openhack.com`, `app.openhack.com`, `install.openhack.com` and the release download | DNS, proxy, TLS | S | N | N | I | |
| Forwarded v2 dashboard (6969) | Network, internet scan | | | N | | |
| Model traffic from the OpenHack host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Kali-style tools against your hosts | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
