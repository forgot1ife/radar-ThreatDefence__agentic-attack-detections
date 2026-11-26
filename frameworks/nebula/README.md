# Nebula Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Nebula** ([BerylliumSec/nebula](https://github.com/BerylliumSec/nebula), reviewed at `409bf4f9`, November 25, 2026, version `3.0.0-beta.3` in the tree, latest release `nebula-v3.0.46`), an operator workstation for security testing from Beryllium Security. A Python core (`nebula-core`) runs agents and missions that drive the OpenAI, Anthropic, xAI and other model APIs or the Codex, Claude and Grok command-line harnesses, a Kali container shell, a Playwright browser behind a mitmproxy interception proxy, and optional OpenVPN egress. It ships as a Linux desktop application (Tauri, `.deb` and AppImage), a headless server and a terminal client. No vendor or CERT report of Nebula in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds Nebula running on a host, its clients talking to a remote core, and its web workspace or core exposed.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What Nebula leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Checked for syntax; built from the source code with no captured traffic. Baseline every rule on your own data before alerting |

## What Nebula leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Core process | `nebula-core runtime-service --data-dir ... --bundle ... --manifest-sha256 ... --startup-id ...` started by the desktop app's `nebula-core desktop-connect --bootstrap-stdin`; `python -m nebula.v3.cli serve --host 0.0.0.0 --port 8000 --allow-remote` in the Docker image; `nebula-core headless` on 8765; `nebula-browserd` on 127.0.0.1:4711 | `src/nebula/v3/runtime_launcher.py:253-268`, `ui/src-tauri/src/sidecar.rs:770`, `Dockerfile.v3:42-43`, `src/nebula/v3/cli.py:598-603`, `src/nebula/v3/browserd.py:1124-1133` |
| Agent commands | `docker exec --interactive --workdir=/workspace nebula-runtime-<id> /usr/bin/python3 -c "import os,sys;pid=os.getpid();...os.execv('/bin/bash',['/bin/bash','--noprofile','--norc','-c',sys.argv[2]])" /tmp/nebula-process-<id>.pid '<command>'`; containers named `nebula-runtime-*`, `nebula-terminal-*`, `nebula-exec-*`, `nebula-tool`, `*-egress`; image `localhost/nebula-kali-headless` | `src/nebula/v3/automation_runtime.py:850-856,873,1064-1075`, `src/nebula/v3/sandbox.py:2503` |
| Files | `~/.local/share/nebula/v3/` (`nebula.db`, `runtime/operator-token`, `runtime/connection.json` with `"protocol": "nebula-desktop-runtime-v1"`, `runtime/supervisor.log`), `/tmp/nebula-process-<id>.pid` and `/run/nebula/public-ip` in its containers, `/etc/cron.d/nebula-public-ip` in its Kali image | `src/nebula/v3/cli.py:176-186`, `src/nebula/v3/runtime_launcher.py:24-25,75,246`, `src/nebula/v3/public_ip_update.py:13-15` |
| Own requests | User agents `nebula-chat` (terminal client to a remote core), `Nebula-Terminal/1` (Kali container to `api.ipify.org` every 5 minutes), `Nebula/3 knowledge-source-fetcher` and `Nebula/3 knowledge-source-renderer` (documents an operator adds); header `X-Nebula-CSRF` and cookie `nebula_device` from paired clients; `X-Nebula-Api-Key` on tool results posted to `/api/v1/automation-processes/<id>/results` | `src/nebula/terminal/transport.py:357-364`, `src/nebula/v3/public_ip_update.py:19-22`, `src/nebula/v3/knowledge.py:504,657`, `src/nebula/v3/automation_runtime.py:2025-2027` |
| Console | Browser workspace titled `Nebula 3` with the description `Nebula 3 local-first security engagement workspace` and icon `/nebula-icon.svg` (Shodan hash `1869598234`); a core without the workspace answers `/` with `<title>Nebula Core</title>` and `Nebula Core is running. Connect with a paired client.`; API refusals `valid bearer token required` and `new device pairings may be created only from the local machine` | `ui/index.html:9-15`, `src/nebula/v3/runtime_launcher.py:205-211`, `src/nebula/v3/authentication.py:198`, `src/nebula/v3/authentication_api.py:259` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Nebula on a host, the watchlist sweep, and its clients and console in web and proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: Nebula's command wrapper in its containers or its core process on a host |
| [`sigma/`](sigma) | 5 Sigma rules: the core processes, agent commands in its containers, its files, its user agents in proxy logs, and its console and client requests in web logs |
| [`suricata/`](suricata) | Rules for its own requests, its paired clients and tool callbacks, and an exposed workspace or core |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for its source and workspace build, and for its runtime and container files |

What the agent does to a target looks like the Kali tools and the Chromium browser it drives, so the cross-framework rules carry most of the target-side detection: model API calls from servers, attack tools started by an agent and out-of-band lookups are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `nebula`.

## Limits

- The code sends no canary, marker path, test account or user agent of its own to targets. Its agents run the stock `kali-linux-headless` tools and a Playwright Chromium with its own user agent.
- `nebula-chat`, `X-Nebula-CSRF` and `nebula_device` cross the network only when a terminal client or a paired browser talks to a remote core; the core requires HTTPS for pairing unless the operator allows plain HTTP, so these are seen in proxy logs or decrypted traffic.
- Every listener binds to loopback by default and refuses a remote bind without `--allow-remote` (and TLS for `headless` and `ui --lan`). The Docker image listens on `0.0.0.0:8000` but its compose file maps it to `127.0.0.1`.
- Nebula 1 and 2 (2023 to 2025) were a different command-line tool published as `berylliumsec/nebula` on Docker Hub and `nebula-ai` on PyPI. Nebula 2 is discontinued; none of the signals here come from it.
- A match means Nebula, not an attacker: it is promoted to penetration testers and security teams. Check who ran it and whether the test was agreed.
