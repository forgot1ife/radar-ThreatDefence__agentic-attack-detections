# sapper-v2 Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **sapper-v2** ([N1nEmAn/sapper-v2](https://github.com/N1nEmAn/sapper-v2), reviewed at `7b75e6f1`, November 11, 2026, after release `v18-champion`), a kit built for an automated attack-defense contest that runs several Claude Code (and optionally Codex) sessions in tmux with approvals turned off, types missions into them, restarts them when they die, and keeps their findings in a shared "engagement graph" on disk. The models behind it are Zhipu GLM and DeepSeek through their Anthropic-compatible endpoints. No vendor or CERT report of sapper-v2 in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds sapper-v2 running on a host, its board exposed or being viewed, and its contest client.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, exposure searches |
| Docs | [What sapper-v2 leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax, Suricata rules against test flows, YARA against the sapper-v2 source. Baseline every rule on your own data before alerting |

## What sapper-v2 leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Target side | Nothing of its own: no user agent, header, canary or callback domain. The agents run stock nmap, nuclei, sqlmap, ffuf, hydra and the rest of a Kali image, from several sessions in parallel | `docker/Dockerfile:29-66`, `kb/entries/` |
| Agent windows | Every agent runs in tmux as `cd <dir> && claude --model '<m>' --effort max --dangerously-skip-permissions 2>&1; echo DRIVE_PANE_EXITED; exec sleep infinity`, in session `sapper-cmd`, `sapper-tui` or `sapper-fleet` | `docker/commander/worker.sh:398`, `docker/commander/entrypoint.sh:105` |
| Missions | Typed with `tmux send-keys`, so the text is in the command line: `You are the autonomous field commander of a pentest campaign (TSecBench)`, `You are an autonomous pentest operator in a CTF benchmark` | `docker/commander/entrypoint.sh:125`, `docker/commander/worker.sh:251` |
| Executor prompt | `claude -p ... --append-system-prompt "You are an autonomous executor in a penetration-testing fact-graph agent system..."` | `lib/sapper.py:1449-1458,2899-2902` |
| Files | `.sapper/project.json`, `.sapper/facts/`, `.sapper/intents/`, `sapper-graph.html`; in its image `/opt/sapper/` and `/work/runs/` with `drive.log`, `commander-state.md`, `pane-env/` | `lib/sapper.py:41-44,124-128,3560`, `docker/commander/` |
| Board | `sapper view --serve`: Python `http.server`, plain HTTP, no login, `127.0.0.1:8765` by default. Title `sapper — engagement graph`; the page carries the path `/__sapper_graph__/<24 hex>.json` that returns the whole graph. No favicon | `lib/view_template.html:6`, `lib/sapper.py:3589-3667,4549-4551` |
| Contest client | Header `BENCHMARK_TOKEN` to `/openapi/v1/challenges` (TSecBench). Shared by any client of that contest | `lib/arena.py:39-40,138` |

## Exposed boards

offensive.agency (ONYPHE data) counted 4 hosts with the board title between November 2 and November 25, 2026, 1 seen in the seven days to November 25: port 2333 on a hosting provider in the United States. An exposed board shows an engagement in progress or a past one, with its targets, credentials and flags. The search is in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `sapper-v2`.

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: sapper-v2 on a host, the watchlist sweep, and its board and contest client in web and proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: sapper-v2 agent windows, tmux sessions and prompts on a host |
| [`sigma/`](sigma) | 3 Sigma rules: its processes, its files, and its board in proxy logs |
| [`suricata/`](suricata) | Rules for the board page, its graph JSON and poll, and the contest client |
| [`yara/`](yara) | Rules for its scripts and the board page or snapshot |

Model traffic from servers, coding agents in bypass mode starting attack tools, and the Kali tools against your sites are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `sapper-v2`.

## Limits

- On the target side sapper-v2 looks like any operator running Kali tools from Claude Code. Only the host and the board identify it.
- The host strings are in the code; a fork can rename them. The mission prompts are typed into the model, which then works in its own words.
- The contest client rule fires for any TSecBench contest agent, not only sapper-v2.
- A match means sapper-v2, not an attacker: it is published as a contest kit. Check who ran it and whether the test was agreed.
