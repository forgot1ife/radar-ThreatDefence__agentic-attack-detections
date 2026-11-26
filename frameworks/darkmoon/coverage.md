# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| DarkMoon launcher, images, containers and MCP server on a host | EDR | S | N | | | Y |
| DarkMoon config, campaign files and reports | EDR, disk | S | N | | | Y |
| Edge probes: user agent `dm-edge`, `dmcb=DM1`, `X-Forwarded-Host: dm-poison.invalid` | Web, WAF, proxy, network | S | N | N | | |
| SMTP relay, spoofing and VRFY tests from `dm-test.local` | Mail server logs, network | | | N | | |
| Registry push proof `darkmoon-proof-` and SCIM user `darkmoon-test` | Registry and web logs, network | S | N | N | | |
| `/tmp/.dm_proof` written on a database or cache server | EDR | S | N | | | |
| Placeholder model key `darkmoon-local` to an on-prem model endpoint | Network (cleartext or decrypted) | | | N | | |
| DarkMoon MCP server answering on the network | Network | | | N | | |
| Model traffic from the DarkMoon host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Toolbox scans and exploitation against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |

DarkMoon has no published addresses or domains and sends no telemetry, so there are no generated address rules or Zeek intel entries for it.
