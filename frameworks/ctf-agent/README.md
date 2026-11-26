# CTF Agent Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**CTF Agent** ([verialabs/ctf-agent](https://github.com/verialabs/ctf-agent), reviewed at `3366d569`, March 29, 2026), from Veria Labs. An autonomous solver for Capture The Flag competitions on the CTFd platform: a coordinator model (Claude Opus 4.6 through the Claude Agent SDK, or GPT-5.4 through the Codex CLI) polls CTFd and starts a swarm of solver models on every unsolved challenge, each in its own Docker sandbox with pwn, reversing, crypto, forensics and web tools, and the first confirmed flag is submitted. Its README reports all 52 challenges solved and first place at the BSidesSF 2026 CTF.

CTF Agent is a command-line program with no web UI. Its only listener is a message endpoint hard-coded to `127.0.0.1`, so there is nothing to find on the internet. Its fixed network signal is its CTFd client, which sends a truncated Windows 7 user agent no browser sends. On the host, its sandboxes and model CLIs leave fixed command lines and files. No vendor or CERT report of CTF Agent used outside a CTF was found on November 26, 2026.

| | |
|---|---|
| Tool | [verialabs/ctf-agent](https://github.com/verialabs/ctf-agent), reviewed at `3366d569`. Package `ctf-agent-two`, commands `ctf-solve` and `ctf-msg`. Not on PyPI or Docker Hub |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA |
| Docs | [What CTF Agent leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the source code, not from captured runs. Baseline every rule on your own data before alerting |

## What CTF Agent leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| CTFd client | User agent exactly `Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36`, `GET /api/v1/challenges?per_page=500` and the solves endpoints every 5 seconds, flags to `POST /api/v1/challenges/attempt`; with no token, a login as `admin` / `admin` | `backend/ctfd.py:14,40-76,125-193`, `backend/config.py:10-12` |
| Helper script | `pull_challenges.py` sends a full Chrome 45 on Windows 7 string taken from Eruditus | `pull_challenges.py:35` |
| Launcher and CLIs | `ctf-solve --ctfd-url ... --coordinator ...`; `codex app-server` children of it; the Claude Code CLI with the prompt `IMPORTANT: You are running inside a Docker sandbox.` | `backend/cli.py:31-43`, `backend/agents/codex_solver.py:186-191`, `backend/agents/claude_solver.py:97-104` |
| Sandbox commands | `docker exec -i <64 hex id> bash -c <command>` for the Claude solver; `timeout --signal=KILL --kill-after=5 <s> bash -c '<command>'` in the container, first `... 10 bash -c 'uname -m'` | `backend/agents/claude_solver.py:189-201`, `backend/sandbox.py:165-171` |
| Containers | Image `ctf-sandbox`, label `ctf-agent=true`, `sleep infinity`, `SYS_ADMIN`, `SYS_PTRACE`, seccomp unconfined | `backend/sandbox.py:19,126-141` |
| Files | `<tmp>/ctf-workspace-<random>/`, `logs/trace-<challenge>-<model>-<timestamp>.jsonl`, `challenges/<slug>/metadata.yml` | `backend/sandbox.py:114`, `backend/tracing.py:18-23`, `backend/ctfd.py:211-269` |
| Out-of-band | `webhook.site` tokens for XSS and SSRF callbacks | `backend/tools/core.py:128-152` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: CTF Agent on a host, its CTFd client in web and proxy logs, and the watchlist sweep |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: its sandbox start command, prompts and launcher on a host |
| [`sigma/`](sigma) | 6 Sigma rules: launcher and model CLIs, Claude solver docker exec, sandbox command wrapper (Linux), its files, its CTFd client in proxy and in web server logs |
| [`suricata/`](suricata) | 3 rules: the CTFd client user agent, its default admin/admin login, and the pull_challenges.py user agent |
| [`yara/`](yara) | Rules for the CTF Agent source and its solver traces |

What its solvers send to challenge services is stock tooling run from a sandbox (curl, nmap, pwntools), so the cross-framework rules in [`behaviors/`](../../behaviors) carry that side: model API calls from servers and out-of-band callback services.

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `ctf-agent`.

## Limits

- CTF Agent is built for CTF competitions. On a CTF you host, the rules tell you a team is running this solver; whether that is allowed is the event's rule, not a security question.
- The user agent, label, wrapper and prompts are constants in a small codebase and easy to change; the rules catch the repository as published.
- Container command lines need a sensor that sees inside containers. The Claude solver's `docker exec` lines and the launcher are seen on the host.
- A match means CTF Agent, not an attacker. Check who runs it and against what.
