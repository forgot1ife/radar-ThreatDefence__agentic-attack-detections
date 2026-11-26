# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Core, desktop and browser sidecar processes (`nebula-core runtime-service`, `desktop-connect`, `serve`, `headless`, `nebula-browserd`) | EDR | S | N | | | |
| Agent commands in its containers (`docker exec ... nebula-runtime-*` with its Python wrapper and `/tmp/nebula-process-*.pid`), its container names and Kali image build | EDR on the operator host | S | N | | | Y |
| Data folder, operator token, connection file, container files (`/run/nebula/public-ip`, `/etc/cron.d/nebula-public-ip`) | EDR, disk | S | N | | | Y |
| Source, built workspace and Kali image files | Disk | | | | | Y |
| `Nebula-Terminal/1`, `nebula-chat` and `Nebula/3 knowledge-source-*` user agents | Proxy, network (decrypted) | S | N | N | I | |
| Paired clients (`X-Nebula-CSRF`, `nebula_device`) and pairing redemption | Proxy, web, network | S | N | N | | |
| Tool result callbacks with `X-Nebula-Api-Key` | Network (plain HTTP on the LAN) | S | N | N | | |
| Exposed workspace page, placeholder page, manifest, liveness and API refusals | Network, web, proxy | S | N | N | | |
| Model traffic from the host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Kali tools and the agent browser against your sites | Web, WAF, proxy, firewall | behaviors | behaviors | behaviors | behaviors | |
