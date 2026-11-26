# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| `User-Agent: pensar-apex` on target requests | Web, WAF, proxy, IDS | S | N | Y | | |
| `PensarBot/1.0` page reader user agent | Web, WAF, proxy, IDS | S | N | Y | | |
| Sign-up test account `testuser-<13 digits>` / `TestPassword123!@#` | Request bodies (IDS, WAF) | | N (query strings) | Y | | |
| Example prompt injection marker | Request bodies (IDS, WAF) | | | Y | | |
| Callback listener answer `apex-callback <nonce>` | Network | | | Y | | |
| Agent commands with `User-Agent: pensar-apex`, callback listener bootstrap, helper markers | EDR | S | N, analytics | | | |
| CLI `pensar pentest ...`, install, `kali-apex` container | EDR | S | N | | | |
| `~/.pensar/sessions/`, `runs.sqlite`, staged listener, `/tmp/apex_payload_*` | EDR, disk | S | N | | | Y (listener, README) |
| Apex code: source, npm bundle `build/cli.js`, compiled `pensar` binary | Disk | | | | | Y |
| Install, update check, Pensar gateway | Proxy, DNS, TLS | S | N (watchlist) | | | |
| Model traffic from the Apex host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Kali tools against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
| Exposed console | none: Apex has no web UI or API server | | | | | |
