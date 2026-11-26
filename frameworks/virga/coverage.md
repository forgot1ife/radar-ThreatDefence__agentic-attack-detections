# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Virga server, CLI and MCP stdio server on a host | EDR | S | N | | | Y |
| Beacon built with Virga's generator (`go build` with `...implant/config.BuildC2Host=`) | EDR | S | N | | | |
| Virga server data, generator folder and model file | EDR, disk | S | N | | | Y |
| Beacon binary (Go package path, appended GGUF model) | EDR, disk | | N | | | Y |
| Beacon check-in to `/api/updates` and stage 2 download | Network, proxy | S | N | N | | |
| Listener decoy 404 page and error answers | Network | | | N | | |
| MCP servers answering and tool calls that drive beacons | Network | | | N | | |
| Web UI and unauthenticated admin API | Network, proxy | | N | N | | |
| Executables over 1.5 GB that talk on the network (beacons with a model) | EDR | | N | | | Y |
| Beacon user agents and paths in the watchlist | Proxy, web, EDR | | N | | | |

Virga has no published addresses or domains and sends no telemetry, so there are no generated address rules or Zeek intel entries for it. The model runs inside the beacon, so there is no model API traffic from victims to look for.
