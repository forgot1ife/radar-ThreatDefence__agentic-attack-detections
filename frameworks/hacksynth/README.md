# HackSynth Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**HackSynth** ([aielte-research/HackSynth](https://github.com/aielte-research/HackSynth), reviewed at `48a41f79`, June 24, 2025). Research agent from ELTE (Budapest) for autonomous penetration testing in capture-the-flag games, published with the arXiv paper 2412.01778. A Planner model writes one bash command per step, the command runs in a Kali container through the Docker API, and a Summarizer model folds the output into a running summary. It ships two benchmark sets, picoCTF and OverTheWire, and the scripts that solve them.

HackSynth is small (about 300 lines for the agent itself) and has no web interface, no API server and no listening port, so there is nothing to find on the internet. It sends no fixed user agent, marker or callback to a target: everything the target sees is a stock Kali tool chosen by the model. The useful signals are on the host that runs it. No vendor or CERT report of HackSynth in a real intrusion was found on November 26, 2026.

| | |
|---|---|
| Tool | [aielte-research/HackSynth](https://github.com/aielte-research/HackSynth), reviewed at `48a41f79`. Not on PyPI or Docker Hub |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA |
| Docs | [What HackSynth leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the source code, not from captured runs. Baseline every rule on your own data before alerting |

## What HackSynth leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Attackbox setup | `apt update && apt -y install kali-linux-headless sshpass curl && ssh-keyscan -p 2220 bandit.labs.overthewire.org >> ~/.ssh/known_hosts && ...` run once in a new `kalilinux/kali-rolling` container | `docker_setup.py:34-41` |
| Attackbox container | Named `attackbox_kali_pico`, `attackbox_kali_overthewire` or `attackbox`, with `NET_ADMIN`, `SYS_PTRACE` and `/dev/net/tun`, and `/data/cyberml_attackbox` mounted on `/data` when that folder exists | `docker_setup.py:9,20-32`, `configs/*/benchmarks/*.json:15` |
| Command wrapper | Every model command runs as `timeout 10s /bin/bash -c <command>` through a Docker exec | `pentest_agent.py:72-81` |
| Launcher | `python run_bench.py -b <benchmark>.json -c <config>.json [-k]` | `run_bench.py:132-134`, `README.md:26-28` |
| Prompts | `You are a penetration testing command generator in a CTF game` and `ENCLOSE THE COMMAND WITHIN <CMD></CMD> TAGS`, in the shipped configs and in model traffic | `configs/overthewire_bench/benchmarks/Gpt_4o.json:21-22` |
| Run logging | Every prompt output, command and command output goes to the Neptune.ai project `aielte/CyberML2024` | `run_bench.py:15-27,164-167` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: HackSynth on a host, the attackbox download and short SSH logins in network and target logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: the attackbox setup command |
| [`sigma/`](sigma) | 4 Sigma rules for process and proxy logs |
| [`suricata/`](suricata) | 1 rule for the Kali package download during attackbox setup |
| [`yara/`](yara) | Rules for the HackSynth source and its run configurations |

What HackSynth does to a target looks like the stock tools it runs and like any agent, so the cross-framework rules in [`behaviors/`](../../behaviors) carry the target-side detection: model API calls from servers (hunt 02) and Kali tools against your sites.

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `hacksynth`.

## Limits

- HackSynth is built to play public CTF games (picoCTF and OverTheWire). Its shipped targets are those platforms, not production systems. Pointing it elsewhere means writing a new benchmark file and a new `target_text`.
- The setup string, container names and launcher are easy to change; the rules catch someone running the repository as published.
- A match means HackSynth, not an attacker: it is research code run by students, researchers and security teams. Check who runs it and against what.
