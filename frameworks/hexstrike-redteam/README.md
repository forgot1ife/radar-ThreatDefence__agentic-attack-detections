# Hexstrike-redteam Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Hexstrike-redteam** ([Yenn503/Hexstrike-redteam](https://github.com/Yenn503/Hexstrike-redteam), reviewed at `89779b7`), a copy of [HexStrike AI](../hexstrike) 6.0 that adds the BOAZ payload evasion framework. Any AI assistant connected through MCP can ask the server to wrap a Windows payload with one of 77 BOAZ loaders and 12 encoders, in addition to running HexStrike's 150 or so security tools. Like HexStrike, the server listens on `0.0.0.0:8888` whatever `HEXSTRIKE_HOST` says and has no authentication. No vendor or CERT report of Hexstrike-redteam in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What Hexstrike-redteam leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax, Suricata rules against test flows, YARA against the Hexstrike-redteam source and the other folders of this repository. Baseline every rule on your own data before alerting |

## What Hexstrike-redteam leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| BOAZ routes | `POST /api/boaz/generate-payload`, `GET /api/boaz/list-loaders`, `GET /api/boaz/list-encoders`, `POST /api/boaz/analyze-binary`, `POST /api/boaz/validate-options` on the HexStrike server, port 8888 | `hexstrike_server.py:17260-17370` |
| Responses | `# BOAZ Loaders`, `# BOAZ Encoding Schemes`, `Payload generated successfully at <dir>/BOAZ_beta/...`, `BOAZ framework not found at ...`, `# Binary Analysis: ... (0-8 scale)` | `boaz/boaz_manager.py` |
| Payload build | `hexstrike_server.py` starts `python3 <dir>/BOAZ_beta/Boaz.py -f <in> -o <out> -l 16 -c mingw -t donut ...` in `BOAZ_beta/`; payloads land in `BOAZ_beta/output/` | `boaz/boaz_manager.py:194-277`, `README.md:474` |
| Install | Venv `hexstrike-env`; MinGW-w64, Wine, osslsigncode, Akira and Pluto LLVM; `configure_mcp.sh` overwrites the Claude Desktop and Claude CLI MCP configuration with the server `hexstrike-ai` described as `BOAZ Red Team Payload Evasion` | `install/` |
| MCP tools | `boaz_generate_payload`, `boaz_list_loaders`, `boaz_list_encoders`, `boaz_analyze_binary`, `boaz_validate_options`, seen in model requests as `mcp__hexstrike-ai__boaz_...` | `hexstrike_mcp.py:280-610` |

## Shared with HexStrike

Everything HexStrike leaves behind is unchanged in this fork: the user agents `HexStrike-HTTP-Framework/1.0` and `HexStrike-BrowserAgent/1.0`, the probe `<hexstrikeXSSTest123>`, `Mozilla/5.0 (Compatible Exploit)`, the `/health` message `HexStrike AI Tools API Server is operational`, `/api/command`, `/api/tools/`, the script names and the `/tmp/hexstrike_*` files. HexStrike Suricata 3803001 to 3803012, its three Sigma rules, two analytics rules, four hunts, YARA rules and Zeek script all fire on Hexstrike-redteam, so run them alongside this folder. The rules here match only what the fork adds. An exposed Hexstrike-redteam server cannot be told from HexStrike by `/` or `/health`; the exposure rows for HexStrike find it.

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Hexstrike-redteam and BOAZ builds on a host, the watchlist sweep, and the BOAZ API in web, proxy and network logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: a BOAZ payload build on a host |
| [`sigma/`](sigma) | 4 Sigma rules: the BOAZ build process, payloads written to `BOAZ_beta/output/`, and the BOAZ API in proxy and web server logs |
| [`suricata/`](suricata) | Rules for requests to the BOAZ routes and their responses, on any port |
| [`yara/`](yara) | Rules for the server, MCP client and BOAZ integration module, MCP client configurations that name its BOAZ tools, and its install scripts |

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `hexstrike-redteam`.

## Limits

- BOAZ itself was not reviewed. The rules see the HexStrike side of a build (the route, the `Boaz.py` command, the output folder); what the built payload does on a Windows host is out of scope here.
- `Boaz.py` run by hand, without HexStrike, matches the process and file rules too. That is still an evasive payload being built.
- The output path is chosen per request; `BOAZ_beta/output/` is what the docs and tool description tell the assistant to use.
- A match means Hexstrike-redteam or BOAZ, not necessarily an attacker: it is promoted for red teams. Check who ran it and whether the work was agreed.
