# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Clearwing command line, operator mode or webhook on a host | EDR | S | N | | | |
| Python reading the Claude Code keychain item (macOS) | EDR | S | N | | | |
| Clearwing home folder, audit logs and temporary folders | EDR, disk | S | N | | | Y |
| Source tree or installed package | Disk | | | | | Y |
| Browser, bundle analyzer and attack-surface user agents | Web, proxy, WAF | S | N | N | I | |
| 1Password Mycelium, SRP enumeration and recovery code probes | Web, network | | | N | | |
| Struts, ProFTPD and SSH banner checks | Network | | | N | | |
| Signed payloads, XOR exec stub and sleeper beacon | Network, disk | | | N | | Y |
| Beacon check-in and blind exploit callbacks | Network, proxy | | N | N | | |
| Model clients with Clearwing user agents | Proxy, TLS inspection | S | N | N | I | |
| Exposed web UI (8899) | Network, internet scan | | | N | | |
| Model traffic from the Clearwing host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Out-of-band lookups from your servers | DNS, EDR | behaviors | behaviors | behaviors | behaviors | |
| Kali tools against your hosts | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
