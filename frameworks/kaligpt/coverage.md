# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Search helper, launcher or provider module running | EDR | S | N, analytics | | | |
| Commands the model runs through the shell tool (direct children of the provider process) | EDR | S | N | | | |
| Web launcher opening the KaliGPT custom GPT | EDR | S | N | | | |
| Install folder, launchers, installer file and provider key file written | EDR (file events) | S | N | | | |
| KaliGPT source, launcher, installer and provider key file on disk | Disk | | | | | Y |
| HTTP tool user agents on your web servers | Web, WAF | S | N | N | | |
| HTTP tool user agents from your network | Proxy (TLS inspection for HTTPS) | S | N | N | | |
| Installer download, OpenSearchAPI clone, custom GPT URL | Proxy with TLS inspection | S | N | | | |
| OpenSearchAPI search helper page served to another host | Network (HTTP) | | | N | | |
| Model traffic from the KaliGPT host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Scanner traffic against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
| Exposed console | none: KaliGPT has no web UI; its search helper binds 127.0.0.1:5000 | | | | | |
