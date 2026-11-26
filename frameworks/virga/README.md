# Virga Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Virga**, an experimental command and control framework in Go whose beacon can carry a local language model. The model (Qwen3-4B in GGUF format by default, run through llama.cpp) is appended to the beacon file, and on the compromised host it runs an autonomous loop: it writes `[EXECUTE: <command>]`, the beacon runs the command and feeds the output back. The server also exposes the beacons to any MCP client through two MCP servers (the docs show Claude Desktop). No public report of Virga used in an intrusion was found.

| | |
|---|---|
| Tool | [r74tech/virga](https://github.com/r74tech/virga), reviewed at `43773ffe` (November 23, 2026). No releases or container images |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What Virga leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the server, CLI, web UI and config source; the implant source was not reviewed. Suricata cases are built from the listener, MCP and admin API handlers. Baseline every rule on your own data before alerting |

## What Virga leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Beacon check-in | `POST /api/updates` whose body is one Base64 string (AES-256-GCM, nonce first); the answer is `200 text/plain` Base64. Stage 2 is `GET /api/updates/stage2` | `internal/server/listener/http.go` |
| Default key | `change-this-key-in-production-environment`. The generator passes no key to the beacon build, so default beacons probably carry it, and their traffic can then be decrypted | `configs/server.yaml:15`, `internal/cli/generator/binary.go:601-611` |
| Beacon user agent | Chrome 96 string without a beacon config; the truncated `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` with the shipped `beacon.yaml` (shared with CyberStrikeAI, AutoPT and GH05TCREW PentestAgent) | `internal/cli/generator/binary.go:107`, `configs/beacon.yaml:9` |
| Beacon file | A Go binary with `github.com/r74tech/virga/internal/implant/` function names, and with the model on, about 2.5 GB with a GGUF model appended and its size in the last 8 bytes | `internal/cli/generator/binary.go:394-407` |
| Beacon build | `go build ... -tags llama_selfextract,prebuilt -ldflags "-X 'github.com/r74tech/virga/internal/implant/config.BuildC2Host=<host>' ..."` | `internal/cli/generator/binary.go:482-611` |
| MCP servers | SSE on `:8444` (`/mcp/events`, `/mcp/message`) and Streamable HTTP on `:50012` (`/mcp`), every interface, no authentication, server name `Virga MCP Server` | `configs/server.yaml:22-31`, `internal/server/server.go:129` |
| Admin API | Port 8443, no authentication. `GET /api/forest` always returns a node `"id":"c2-server"`, `"label":"Virga C2"` | `internal/server/server.go:205-246,1166-1178` |
| Web UI | Vite dev server on `0.0.0.0:5173`, title `Virga C2 - Web UI`, stock Vite icon (Shodan hash `-1207029254`) | `web/index.html`, `web/vite.config.ts` |
| Host | `virga-server`, `virga-cli`, `virga-mcp-stdio`; `data/virga.db`, `/tmp/virga/extensions/`, `.virga_history`, `virga-generator-<random>` | `Makefile`, `configs/`, `internal/server/server.go:87` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: Virga on a host, the watchlist sweep, beacons and console calls in proxy and web logs, and executables over 1.5 GB that talk on the network |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: the Virga server, CLI or a beacon build on a host |
| [`sigma/`](sigma) | 4 Sigma rules: server and CLI processes, beacon builds, Virga files, and beacon traffic in proxy logs |
| [`suricata/`](suricata) | Rules for beacon check-ins and stage 2, the listener's decoy and error answers, the MCP servers' answers and tool calls, the web UI and the admin API |
| [`yara/`](yara) | Rules for the server and CLI, beacon binaries, beacons with an appended GGUF model, and Virga's config files |

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `virga`.

## Limits

- The check-in path, user agent, interval and key are settings. A careful operator changes them; the shipped values are what the docs and quick start use.
- The implant source was not read. Beacon-side details that come only from the implant (its other headers, how it unpacks the model, what it writes on the victim beyond `implant_debug.log` from `beacon.yaml`) are not covered.
- A match means Virga, not necessarily an attacker: it is published as a research and red-team tool. Check who ran it and whether the test was agreed.
