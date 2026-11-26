# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| BOAZ payload build started by the HexStrike server (`BOAZ_beta/Boaz.py`) | EDR | S | N | | | |
| Payloads written to `BOAZ_beta/output/` | EDR, disk | S | N | | | |
| Requests to the `/api/boaz/` routes | Network, proxy, web | S | N | N | | |
| Responses of the `/api/boaz/` routes (loader and encoder lists, build result, BOAZ missing, entropy analysis) | Network | | | N | | |
| Install scripts, `hexstrike-env` and the rewritten Claude MCP configuration | EDR, disk | | N | | | Y |
| Server, MCP client and BOAZ integration source | Disk | | | | | Y |
| HexStrike user agents, probe, `/api/command`, `/api/tools/`, `/health`, server process (unchanged) | All | [hexstrike](../hexstrike/coverage.md) | [hexstrike](../hexstrike/coverage.md) | [hexstrike](../hexstrike/coverage.md) | [hexstrike](../hexstrike/coverage.md) | [hexstrike](../hexstrike/coverage.md) |
| Model traffic from the host, AI assistant wired to the server | Proxy, EDR | behaviors | behaviors, [hexstrike](../hexstrike) | | behaviors | [hexstrike](../hexstrike) |

S = Sigma rule, N = native rule or hunt, Y = YARA rule. The HexStrike rows link to the HexStrike folder, whose rules fire on this fork unchanged.
