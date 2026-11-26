# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Deadend CLI backend started on a host | EDR | S | N | | | |
| Credential wallet, session logs and cookie state written | EDR, disk | S | N | | | Y |
| Source tree, PyPI package or prompts on disk | Disk | | | | | Y |
| Reflection marker `deadend7x7probe` against your sites | Web, WAF, proxy, network | S | N | N | | |
| Shipped test account or unreplaced placeholders in logins and sign-ups | Network, WAF (request bodies) | | N (query strings only) | N | | |
| Example header `X-App: deadend` | Network, WAF | | | N | | |
| Sandbox image pull and release download | Proxy (TLS inspection) | S | N | | | |
| Opt-in trace collector `crunch.straylabs.ai` | DNS, TLS, proxy | S | N | N | | |
| Model traffic from the Deadend CLI host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| nmap, ffuf, nikto, sqlmap and curl from the Kali sandbox | Web, WAF, firewall | behaviors | behaviors | behaviors | behaviors | |
| Exposed console | — | | | | | |

There is no exposed-console row because Deadend CLI has no listener.
