# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Agent windows, tmux sessions and mission prompts on a host | EDR | S | N, A | | | Y |
| sapper CLI (auto, bench, view --serve) and the board listener | EDR | S | N | | | Y |
| Engagement graph store, board snapshot, contest image run folder | EDR, disk | S | N | | | Y |
| Board page, graph JSON and poll requests | Network, proxy, web | S | N | N | | Y |
| TSecBench contest API client (shared with any contest agent) | Network, proxy | | N | N | | |
| Model traffic from the sapper-v2 host (GLM, DeepSeek) | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Coding agent in bypass mode starting attack tools | EDR | behaviors | behaviors | | | |
| Kali tools against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |

S: Sigma rule. N: KQL hunt. A: Sentinel analytics rule. Y: YARA rule.
