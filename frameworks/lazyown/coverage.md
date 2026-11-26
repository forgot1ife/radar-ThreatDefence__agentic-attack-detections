# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| C2 server, MCP server, CLI or launcher started; install or container pulled | EDR | S | N | | | Y |
| C2 key, launcher, credential and decoy capture files | EDR, disk | S | N | | | Y |
| `payload.json` and beacon runtime config on disk | Disk | | | | | Y |
| Exposed C2: 401 challenge, security headers, dashboard title, public health JSON | Network, proxy | | | N | | |
| Decoy page and its camera and microphone uploads | Network, proxy | | | N | | Y |
| Beacon polls, reports, staging and BOF downloads on the Gmail-style route | Proxy with TLS inspection, network | S | N | N | | |
| C2 answers to beacons (`Platform`, `BOF_NOT_FOUND`, `STAGE_FORBIDDEN`, empty command) | Network | | | N | | |
| Beacon configuration user agents | Proxy, network | S | N | N | I | |
| Beacon one-liners on a target (`/tmp/.dbus`, `$env:TEMP\svchost.exe`) | EDR | S | N | | | |
| DNS C2 zone `c2.lazyown.org` | DNS, EDR | S | N | N | I | |
| MCP and operator calls to the C2 API | Network | | | N | | |
| Operator tools (exploitalert, PyPI checks) | Proxy with TLS inspection | S | N | N | I | |
| Cloudflare quick tunnel redirector | DNS, TLS, proxy | S (with beacon paths) | N | behaviors | behaviors | |
| C2 addresses from exposure snapshots | Firewall, proxy, sign-in | | N | N (generated) | I | |
| Model traffic from the operator host | Proxy, TLS | behaviors | behaviors | | behaviors | |

S = Sigma rule, N = network or Sentinel rule or hunt, I = Zeek intel, Y = YARA rule.
