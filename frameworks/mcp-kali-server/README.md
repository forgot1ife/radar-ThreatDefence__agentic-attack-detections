# MCP Kali Server Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **MCP Kali Server** (MKS), a small open-source bridge that lets an AI assistant run commands on a Kali Linux host. A Flask API server (`server.py`, port 5000, no authentication) runs any command and ten Kali tools (nmap, gobuster, dirb, nikto, sqlmap, Metasploit, hydra, John the Ripper, WPScan, enum4linux); an MCP client (`client.py`) plugs it into Claude Desktop, 5ire or any other MCP host. MKS has no model or planner of its own: the assistant decides what to run. Kali ships it as the package `mcp-kali-server`. No public report of MKS used in an intrusion was found.

| | |
|---|---|
| Tool | [Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server), reviewed at `00154c05` (March 17, 2026). No releases or container images. Kali package `mcp-kali-server` ([packaging](https://gitlab.com/kalilinux/packages/mcp-kali-server) read at `15136e98`, October 20, 2026) |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What MCP Kali Server leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the whole repository (two Python files) and the Kali packaging. Suricata cases are built from the server's routes and the client's requests. Baseline every rule on your own data before alerting |

## What MCP Kali Server leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| API server | Flask on `127.0.0.1:5000` by default; `--ip 0.0.0.0` is documented. **No authentication**: `POST /api/command` runs any command (upstream through `/bin/sh -c`) | `server.py:147-167,557-578` |
| Health answer | `GET /health` returns `"message": "Kali Linux Tools API Server is running"` and runs `which nmap`, `which gobuster`, `which dirb`, `which nikto` on every call | `server.py:523-545` |
| Tool routes | `POST /api/tools/<nmap|gobuster|dirb|nikto|sqlmap|metasploit|hydra|john|wpscan|enum4linux>` with `additional_args`; the client is python-requests | `server.py:170-520`, `client.py:62-107` |
| Metasploit | `msfconsole -q -r /tmp/mks_msf_resource.rc` (HexStrike's file is `/tmp/mcp_msf_resource.rc`) | `server.py:359-363` |
| Kali package | `/usr/bin/kali-server-mcp` and `/usr/bin/mcp-server` wrap `/usr/share/mcp-kali-server/server.py` and `client.py`; services `kali-server-mcp.service` and `mcp-server.service` run as user `_mcp-kali` | Kali packaging, `debian/` |
| Model requests | The MCP host sends MKS's tool descriptions, e.g. `Execute an arbitrary command on the Kali server.`, and some hosts its instructions | `client.py:118-158,392` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: MKS on a host, the watchlist sweep, and API calls in firewall, proxy and network logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: the packaged API server or its Metasploit resource file on a host |
| [`sigma/`](sigma) | 5 Sigma rules: server and client start, the Metasploit resource file run, children of the API server, MKS files, and API calls in proxy logs |
| [`suricata/`](suricata) | Rules for the health answer, raw command and tool requests on port 5000, command results, the stub route, and MKS's tool descriptions and instructions in model requests |
| [`yara/`](yara) | Rules for the API server, the MCP client and the Kali package's units and wrappers |

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `mcp-kali-server`.

## Limits

- MKS sends nothing of its own to a target. What a target sees is stock Kali tools; the cross-framework rules in `behaviors/` cover those.
- Client and server usually share a host (loopback) or an SSH tunnel, where the network rules see nothing. They fire on servers reached across the network.
- `server.py`, `client.py` and port 5000 are common names. The package paths, the `_mcp-kali` user, the resource file and the health message need a code change.
- A match means MKS, not necessarily an attacker: it is packaged in Kali for authorized testing and CTFs. Check who ran it, and treat an MKS server that answers from outside its host as an open command execution service.
