# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Harness requests to your sites (user agent, scan header, baseline probe) | Web, WAF, proxy, network | S | N | N | | |
| Canaries and payload markers (sigil, `neurosploit.example`, `oob.invalid`, `nrsplt_`) | Web, WAF, network | S | N | N | | |
| Out-of-band callbacks from your servers (`neurosploit*` names) | DNS, proxy, EDR | S | N | N | | |
| Web shell manager and generated web shells | Web, network, disk | S | N | N | | Y |
| C2 beacons and `NSUpdate` persistence on compromised hosts | EDR, network, registry | S | N | N | | Y |
| NeuroSploit binary, C2 daemon, containers and agent CLI children | EDR | S | N | | | Y |
| Project store, vault, C2 state and run folders | EDR, disk | S | N | | | Y |
| Exposed web console (4173, no login) | Network, internet scan | | | N | I | |
| Integration and log shipping user agents from the operator host | Proxy, network | S | N | N | I | |
| Model traffic from the NeuroSploit host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Kali tools (katana, nuclei, ffuf, gau) against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
