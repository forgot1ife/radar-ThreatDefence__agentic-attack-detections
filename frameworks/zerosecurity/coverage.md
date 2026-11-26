# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| `0 probe` prompts sent to a model or agent endpoint | Network (HTTP or decrypted) | | | N | | |
| `0 probe` or Nuclei target scan started on a host | EDR | S | N | | | |
| Playbook canaries `osec123xss`, `ZERO-INJ-OK` and the method `ZERO` in requests | Network, web | S | N | N | | |
| 0security CLI, Docker console and remote engine processes | EDR | S | N | | | Y |
| Verifier containers `0-verify-<hex>` | EDR | S | N | | | |
| State folder `~/.0`, access token, `/tmp/zero-engine` | EDR, disk | S | N | | | |
| Client user agents (analytics, update check, cloud, search) and `cloud.0.security` | Proxy, DNS | S | N | | Y | |
| Console listening on 48123 | EDR | | N | | | |
| Exposed console: page, control token, sign-in page, host refusal, health, headers, cookie | Network | | | N | | |
| `0 probe` reports on disk | Disk | | | | | Y |

0security publishes no attack infrastructure, so there are no generated address rules for it. Its Zeek intel entries come from the indicator CSV (the cloud host, user agents and strings).
