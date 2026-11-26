# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Exposed or reachable C2 server (root JSON, `/health`) | Network, internet scan | | N | N | | |
| Sandcat beacon and its base64 answer | Network | | N | N | | |
| Implant and payload download from `/file/download` | Network, proxy, EDR | S | N | N | | |
| Per-command scripts `dynamic_payload_*.sh` fetched and run | Network, EDR | S | N | N | | |
| Implant copied or pulled over ssh and started with `-group red` | EDR | S | N | | | |
| Incalmo's nmap, nikto, nuclei and ncat command lines | EDR | S | N | | | |
| Operator and strategy API (`/startup`, `/send_command`, LLM action queue, environment state) | Network, proxy | S | N | N | | |
| C2 server, Celery worker and `msfrpcd -P password` on the attacker host | EDR | S | N | | | |
| Run output, state database and implant log | EDR, disk | S | N | | | Y |
| Incalmo source, prompts and run configuration | Disk | | | | | Y |
| Model and usage traffic (OpenRouter, TypeSafe, LiteLLM) | Proxy, DNS | | N | | | |

S = Sigma rule, N = Sentinel hunt or analytics rule, Y = YARA rule. Zeek intel is generated from `iocs/indicators.csv`; no Incalmo indicator is an address or domain of its own.
