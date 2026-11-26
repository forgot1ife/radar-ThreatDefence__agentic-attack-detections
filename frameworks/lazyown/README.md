# LazyOwn Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **LazyOwn** ([grisuno/LazyOwn](https://github.com/grisuno/LazyOwn), reviewed at `f4e54de9`, version 0.5.0), a Python red team framework with a shell of several hundred attack commands, a multi-operator C2 server with HTTP and DNS beacon channels, and an MCP server through which Claude Code, Hermes Agent or OpenCode drive the whole framework. This folder is built from the source code of the C2 server, its beacon handlers and the MCP control path; the implants were not reviewed. It finds a LazyOwn C2 exposed on the internet, beacons calling it, and LazyOwn running on a host. Public reports of LazyOwn used in intrusions were not searched for this draft.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What LazyOwn leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Suricata rules tested against test flows, YARA strings checked against the LazyOwn source files, KQL parsed with the repository's checker. Baseline every rule on your own data before alerting |

## What LazyOwn leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| C2 web UI | Port 4444 (`c2_port`), HTTPS with a self-signed `CN=<ip>` certificate when `cert.pem` exists. `GET /` answers `401` with `Basic realm="Login Required"` and `Invalid credentials. Please provide valid username and password.`, and a Content-Security-Policy that allows `https://upload.wikimedia.org` images. Icon `/favicon.ico`, Shodan hash `538162949`. Dashboard title `LazyOwn Command and Control Center` | `lazyc2/security/auth.py`, `lazyc2.py`, `templates/header.html` |
| Decoy page | Strangers get `Live View Page -  564 plot listing Template` on `/login` and every 404; the page asks for camera and microphone and posts frames and recordings back to the C2 | `templates/decoy.html` |
| Beacons | `GET` and `POST /gmail/v1/users/<client id>` (the shipped malleable route) on a host that is not Google, plus `/command/<id>`, `/api/poll/<id>`, `/report/`, `/stage/beacon`, `/stage/config` and `/bof/<object>`; AES-CFB bodies in base64; answers `{"Platform":"<os>","status":"success"}`, `BOF_NOT_FOUND`, `STAGE_FORBIDDEN`. Shipped user agents include `LAzyOwnRedTeam 66_6` and an old Chrome 58 string cut to `Safari/537.3`; sleep 6 s | `lazyc2.py`, `lazyc2/beacons/service.py`, `payload.example.json` |
| DNS C2 | Queries under `c2.lazyown.org` to the C2's own DNS server on UDP 53, TXT answers such as `Servidor C2 activo` | `lazyc2.py:1769-1830` |
| Host | `python3 -W ignore lazyc2.py <port> <user> <password>`, `skills/lazyown_mcp.py` under an AI agent, tmux session `lazyown_sessions`, files under `sessions/` (`key.aes`, `c2_launch.env`, `captured_images/`) | `fast_run_as_r00t.sh`, `skills/lazyown_mcp.py` |
| Operator tools | `LazyOwn/1.0` on exploitalert.com, `lazyown-depconfuse/1.0` on PyPI | `utils.py`, `cli/commands/supply_chain.py` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: LazyOwn on a host, the watchlist sweep, and beacons and operator clients in proxy and DNS logs |
| [`sentinel/analytics/`](sentinel/analytics) | The C2 or MCP server on a host, or a lookup of the DNS C2 zone |
| [`sigma/`](sigma) | 5 Sigma rules: beacon route and user agents in proxy logs, the C2, MCP server and launcher processes, the beacon one-liners, the C2's files, and the DNS C2 zone |
| [`suricata/`](suricata) | Rules for the C2's answers, the decoy page, beacon requests and answers, the DNS channel and the operator tools |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the C2 source, `payload.json`, the decoy page, the launcher files and the beacon runtime config |

Model traffic, attack tools started by the framework, Cloudflare quick tunnels and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `lazyown`.

## Limits

- The malleable route, the user agents and the port are settings in `payload.json`. The rules cover the shipped values and the paths the C2 always serves (`/command/`, `/api/poll/`, `/stage/`, `/bof/`).
- The C2 serves HTTPS whenever a certificate is present, and the repository's redirector is a Cloudflare quick tunnel, so most beacon traffic needs TLS inspection or a sensor on the redirector. The DNS rules work without it.
- LazyOwn installs and drives other agentic frameworks through its add-ons (a fork of ARTEX, Cairn, PentAGI, VulnBot, Agent Zero and others); those leave their own signals, covered in their folders.
- A match means LazyOwn, not an attacker: it is published as a red team framework. Check who ran it and whether the test was agreed.
