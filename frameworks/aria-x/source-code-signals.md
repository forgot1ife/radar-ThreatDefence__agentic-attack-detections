# What ARIA-X leaves behind

ARIA-X ([01NGVI-QINGYI/ARIA-X](https://github.com/01NGVI-QINGYI/ARIA-X); repository created October 23, 2026; last push November 25, 2026; 116 stars and 57 forks on November 26, 2026; not archived; AGPL-3.0; Python with a plain JavaScript console; reviewed at `015e197014173de89c0905e1a314629c7b8eec96`, November 25, 2026, the merge of v0.3.0) is a Python engine for LLM-driven security testing. Its README describes it as a fusion of the designs of ARTEX, Cairn and PentAGI: a Cairn-style blackboard of facts, intents and hints, an ARTEX-style planner and todo chain, and PentAGI-style specialist roles and sandboxed terminal. It reuses none of their code: it is a new implementation on the Python standard library only (`pyproject.toml` lists no dependencies). Tags v0.1.0 (October 23, 2026), v0.2.0, v0.2.1 and v0.3.0 exist; there are no GitHub releases and no published container image. The image is built locally as `aria-x:0.3.0`. The PyPI name `aria-x` belongs to an unrelated project (version 1.6.1, homepage Lonerider007/aria-agent), so `pip install aria-x` does not install this code. File references are to the repository at `015e197`.

**Fragility** says what it takes to remove a signal: *code* means editing ARIA-X, *config* means `configs/aria-x.toml`, an environment variable or the compose file, *operator* means a choice made at run time. *Code (prompt)* marks a string the model can change through a tool argument.

## Which ARTEX, Cairn and PentAGI rules fire

ARIA-X takes ideas and vocabulary (intents, facts, hints, todo chain, planner, specialists) from the three projects, not code, strings or infrastructure. Checked against the hand-written rules in `frameworks/artex`, `frameworks/cairn` and `frameworks/pentagi`:

| Rule | Fires on ARIA-X? | Why |
|---|---|---|
| ARTEX user agents, probe markers, console titles, Basic realm, campaign domains (Suricata 3800001 to 3800086, Sigma, YARA) | No | None of the strings is in ARIA-X; its user agent is `ARIA-X/<version> (authorized security research)` and its console title `ARIA-X · Engagement Console` |
| ARTEX hunt 20 and the osquery `listening_ports` query (any process listening on 8787) | Yes, by port only | ARIA-X's console also defaults to port 8787. The hunts label the hit as ARTEX; check the process command line for `aria_x` |
| ARTEX hunt 28 (listener on 8787 or 8788 by a process named `artex`) | No | The listener is `python` running `aria_x` |
| ARTEX indicator `port,8787` and Zeek/feeds built from it | Yes, by port only | Same default port. Add `aria-x` to that row's `framework` column |
| Cairn server, dispatcher and prompt rules (OpenAPI text, `/intents/`, `/heartbeat`, anti-refusal prompt), worker command lines (`/tmp/cairn-pi/`, `cairn dispatch`) | No | ARIA-X has its own API under `/api/projects`, no dispatcher, no Codex/pi workers, and none of those strings |
| PentAGI certificate, update check (`update.pentagi.com`), page title, prompts, command wrapper (`trap "" HUP`) | No | ARIA-X has no TLS of its own, no update check and its own prompts |
| `behaviors/` Kali ffuf user agent (3801xxx) and model-API-from-server hunt | Possibly | Only if the model runs ffuf inside the Kali sandbox image, or the host is a server talking to a model API |

## How it runs

| Part | What it does | Code |
|---|---|---|
| Entry points | `aria-x` console script (`aria_x.cli:main`), `python -m aria_x`, or the checkout launcher `./aria-x` (sets `PYTHONPATH=<checkout>/src` and runs `python -m aria_x "$@"`). Subcommands `init`, `demo`, `run --goal ...`, `serve`, `doctor`, `tools`, `projects`, `graph`, `report`, `export` | `pyproject.toml:19-20`, `aria-x:8-10`, `src/aria_x/cli.py:43-104` |
| Console and API | `aria-x serve` starts a stdlib `ThreadingHTTPServer`: the single-page console (`/`, `/index.html`, `/static/*`), a JSON API under `/api/` and a Server-Sent Events stream at `/api/projects/<id>/events`. Plain HTTP, no TLS option. Default bind `127.0.0.1:8787`; `--host` and `--port` change it, and there is no check against binding a public address without a token | `src/aria_x/config.py:133-138`, `src/aria_x/cli.py:78-81,140-143,532-544`, `src/aria_x/server/app.py:207-215,268-287,541-544`, `src/aria_x/server/api.py:211-230` |
| API authentication | None unless `server.auth_token` or `ARIA_X_AUTH_TOKEN` is set. With a token: `Authorization: Bearer <token>` or `X-ARIA-X-Token: <token>`; `/api/health` stays open. The console page and static files are served before the check, so they answer without a token in every case | `src/aria_x/server/app.py:268-283,303-307,383-397`, `src/aria_x/config.py:235-236` |
| Container | `docker/Dockerfile` builds `aria-x:0.3.0` from `python:3.12-slim` (user `ariax`, uid 10001, `/app/data`, `/app/runs`), `ENTRYPOINT ["python", "-m", "aria_x"]`, `CMD ["serve", "--host", "0.0.0.0", "--port", "8787"]`. `docker run -p 8787:8787 aria-x:0.3.0` without `ARIA_X_AUTH_TOKEN` gives an unauthenticated console on every host interface | `docker/Dockerfile:18,37-44,50-51` |
| Compose | `docker/docker-compose.yml`, project `aria-x`: service `aria-x`, container `aria-x-console`, image `aria-x:0.3.0`, published on `127.0.0.1:8787:8787` only, refuses to start without `ARIA_X_AUTH_TOKEN`; read-only root, all capabilities dropped. Optional profile `sandbox` service `kali-base` (`kalilinux/kali-rolling`, `sleep infinity`, `network_mode: none`) | `docker/docker-compose.yml:9-31,35-41,53-64` |
| Models | Providers `mock` (code default), `scenario`, `openai` (any OpenAI-compatible `POST <base>/chat/completions`), `anthropic` (`POST https://api.anthropic.com/v1/messages`, `anthropic-version: 2023-06-01`, default model `claude-sonnet-4-20250514` in the client class) and `ollama` (`http://127.0.0.1:11434/v1`). The example config, `.env.example`, `aria-x init` and the compose file all default to `openai` with `https://api.deepseek.com/v1` and `deepseek-chat`. Model calls use urllib's default `Python-urllib/3.x` user agent | `src/aria_x/config.py:52-75`, `src/aria_x/llm/openai.py:30,58-63,115-117`, `src/aria_x/llm/anthropic.py:20-25,51-57,110-114`, `configs/aria-x.example.toml:20-24`, `.env.example:9-12`, `src/aria_x/cli.py:304`, `docker/docker-compose.yml:27-29` |
| Tools given to the model | `http_request`, `web_probe`, `port_scan`, `tls_probe`, `dns_lookup`, `web_search` (DuckDuckGo), `terminal_exec`, `session_open/send/read/close/list` (PTY sessions for msfconsole, ssh, shells), `file_read/write/list`, blackboard tools (`add_fact`, `add_finding`, `add_asset`, `todo_update`, `prove_goal`, `delegate_specialist`, `memory_store`, ...) | `src/aria_x/tools/builtin.py:22-30`, `src/aria_x/tools/net.py:717-809`, `src/aria_x/tools/session.py`, `src/aria_x/tools/knowledge.py` |
| Command sandbox | `local` (default): `bash -lc <command>` on the host, cwd jailed to the run's work folder, environment `ARIA_X_SANDBOX=1`. `docker`: one-shot `docker run --rm -i --name aria-x-<12 hex> --network <network> -v <workdir>:/work -w /work <image> bash -lc <command>`, image `kalilinux/kali-rolling`, network `bridge` by default. A destructive-command blocklist (rm -rf of roots, mkfs, dd to disks, fork bomb, shutdown, `curl | sh`, `history -c`, mass docker removal) applies to both | `src/aria_x/tools/sandbox.py:32-52,144-180,183-240,274-279`, `src/aria_x/config.py:94-104` |
| Interactive sessions | Local: `/bin/bash -lc <command>` on a PTY with `ARIA_X_SESSION=1` and `TERM=xterm-256color`. Docker: `docker run --rm -i -t --name aria-x-sess-<8 hex> ... bash -lc <command>`. At most 4 per run | `src/aria_x/tools/session.py:49,207-227,257-274` |
| Approvals | `safety.approval` `auto` (default), `ask` or `deny`; `ARIA_X_APPROVAL` overrides | `src/aria_x/config.py:121-128,241-242` |

## Requests that reach your targets

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| User agent | `ARIA-X/0.3.0 (authorized security research)` on every `http_request` and `web_probe` request. The version comes from `__version__`, so v0.2.1 sends `ARIA-X/0.2.1 (...)`; v0.1.0 and v0.2.0 send `ARIA-X/0.1 (authorized security research)`. Other default headers: `Accept: */*`, `Accept-Encoding: identity`; a POST body without a content type gets `Content-Type: text/plain; charset=utf-8`. No proxy is used (`ProxyHandler({})`), so requests come straight from the ARIA-X host | `src/aria_x/tools/net.py:40,215-221,236-238`, `src/aria_x/__init__.py:18` | code; code (prompt): the model can pass its own `User-Agent` in the tool's `headers` argument, which replaces the default |
| Web probe | Without a path list the `web_probe` tool requests, in order: `/`, `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/login`, `/admin`, `/api`, `/health`, each a GET with the ARIA-X user agent and a 6-second timeout | `src/aria_x/tools/net.py:577-620` | code |
| Rate | Every target request takes a per-host slot from `scope.max_rps`, default 3 requests per second | `src/aria_x/config.py:114`, `src/aria_x/tools/net.py:211` | config |
| Port scan | `port_scan`: TCP connect scan from Python (no nmap), up to 32 threads but held to the per-host rate, default ports 21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888, 9000; optional banner read of 256 bytes | `src/aria_x/tools/net.py:408-470`, `src/aria_x/config.py:115-117` | config |
| TLS probe | `tls_probe` handshakes with certificate verification, and on failure handshakes a second time without it | `src/aria_x/tools/net.py:473-575` | code |
| Shell tools | Anything the model runs through `terminal_exec` or a session (curl, nmap, sqlmap, msfconsole, ssh in the Kali image) carries that tool's own fingerprint. No user agent or marker is put into the prompts | `src/aria_x/agents/prompts.py`, `src/aria_x/tools/terminal.py:115-185` | operator |
| Demo target | `aria-x demo` attacks its own loopback target (`<title>ARIA-X Demo Target</title>`, `Server: AresDemoTarget/0.3.7`, `GET /files?path=../flag.txt`, flag `ARIA-X{demo_path_traversal_confirmed}`) on 127.0.0.1 only | `src/aria_x/demo_target.py:47,100,113`, `src/aria_x/demo.py:26` | code |

## On a host that runs it

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Processes | `python -m aria_x serve --host 0.0.0.0 --port 8787` (container), `<python> <bin>/aria-x serve`, `aria-x run --goal "..."`, `aria-x demo`, or `python -m aria_x ...` started by the `./aria-x` launcher | `docker/Dockerfile:50-51`, `aria-x:10`, `src/aria_x/cli.py:57-104` | code |
| Child shells | Local sandbox: `bash -lc <command>` children of the ARIA-X Python process, cwd `<runs>/run_<12 hex>/work`, environment `ARIA_X_SANDBOX=1`; sessions `/bin/bash -lc <command>` with `ARIA_X_SESSION=1` | `src/aria_x/tools/sandbox.py:163-165,278`, `src/aria_x/tools/session.py:223-227` | code |
| Sandbox containers | `docker run --rm -i --name aria-x-<12 hex> --network bridge -v <runs>/run_<id>/work:/work -w /work kalilinux/kali-rolling bash -lc <command>`, and `aria-x-sess-<8 hex>` with `-i -t` for sessions; `docker info --format {{.ServerVersion}}` and `docker image inspect kalilinux/kali-rolling` on readiness checks | `src/aria_x/tools/sandbox.py:192-224`, `src/aria_x/tools/session.py:211,267-273` | code (names), config (image, network) |
| Containers from compose | `aria-x-console` (image `aria-x:0.3.0`), optional `kali-base` | `docker/docker-compose.yml:16-17,53-54` | config |
| Listener | TCP 8787, `127.0.0.1` by default, `0.0.0.0` in the image | `src/aria_x/config.py:134-135`, `docker/Dockerfile:51` | config |
| Database | `<data_dir>/aria-x.db` (default `./data`, `/app/data` in the image) in WAL mode, so also `aria-x.db-wal` and `aria-x.db-shm` | `src/aria_x/config.py:153,437-438`, `src/aria_x/store/sqlite.py:46` | code (name), config (folder) |
| Run folders | `<runs_dir>/run_<12 hex>/` (default `./runs`) with `report.md`, `report.html`, `report.json` and `work/` (the sandbox cwd); HTTP evidence in `work/evidence/http_<YYYYMMDD>_<HHMMSS>_<8 digits>.json` holding `"kind": "http"`, `"run_id": "run_..."` and the request headers including the ARIA-X user agent | `src/aria_x/engine/orchestrator.py:207-214,1360-1374`, `src/aria_x/tools/net.py:114-133,295-302`, `src/aria_x/engine/engagement.py:323` | code (names), config (folder) |
| Event logs and locks | `<runs_dir>/events.jsonl` (engine) or `<data_dir>/events.jsonl` (CLI), `<data_dir>/locks/p_<12 hex>.lock` | `src/aria_x/engine/engagement.py:100-101,273-278`, `src/aria_x/cli.py:155-157` | code |
| Temporary folders | `aria-x-work-*`, `aria-x-doctor-*`, `aria-x-tools-*`, `aria-x-demo-target-*` under the temp folder | `src/aria_x/tools/sandbox.py:300-301`, `src/aria_x/cli.py:607,657`, `src/aria_x/demo_target.py:63` | code |
| Configuration | `configs/aria-x.toml`, `aria-x.toml`, `configs/aria-x.json` or `aria-x.json`, or `ARIA_X_CONFIG`; environment variables `ARIA_X_PROVIDER`, `ARIA_X_BASE_URL`, `ARIA_X_API_KEY`, `ARIA_X_MODEL`, `ARIA_X_DATA_DIR`, `ARIA_X_AUTH_TOKEN`, `ARIA_X_LOG_LEVEL`, `ARIA_X_SANDBOX`, `ARIA_X_APPROVAL` | `src/aria_x/config.py:224-242,539`, `.env.example` | code |
| Reports | HTML footer `Generated by ARIA-X <version> · AGPL-3.0-or-later · confidential`, eyebrow `ARIA-X · Authorized Security Assessment`, fallback title `ARIA-X Engagement Report — <project>` (also Chinese and Japanese templates) | `src/aria_x/report/i18n.py:178-192,313-326`, `src/aria_x/engine/orchestrator.py:1367,1385` | code |
| Prompt | Every agent system prompt opens with `# ARIA-X OPERATING DOCTRINE` (sent to the model API over TLS) | `src/aria_x/agents/prompts.py:28` | code |

## Network from the host

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Model API | `api.deepseek.com` (`/v1/chat/completions`) with the shipped defaults; `api.openai.com`, `api.anthropic.com`, local Ollama on 11434, or any OpenAI-compatible host. User agent `Python-urllib/3.x` | `src/aria_x/config.py:67-75`, `.env.example:10` | config |
| Research search | `web_search` fetches `https://html.duckduckgo.com/html/?q=<query>` with the ARIA-X user agent. Out of target scope by design, so it is the one ARIA-X request that goes to a third party; a TLS-inspecting proxy sees the user agent | `src/aria_x/tools/net.py:674-684` | code |
| No telemetry | No update check, analytics, webhook, tunnel or MCP client in the code | | |

## Exposure

| Surface | Fingerprint | Code | Uniqueness |
|---|---|---|---|
| Console page on `/` | `<title>ARIA-X · Engagement Console</title>` (the middle dot is U+00B7), `<meta name="description" content="ARIA-X console — autonomous security engagement control plane.">`, `/static/style.css`, inline SVG logo with gradient id `aria-x-mark`. Same title and description since v0.1.0. Served without a token even when one is set | `src/aria_x/web/index.html:7-31`, `src/aria_x/server/app.py:268-273` | High |
| Server header | `Server: ARIA-X/0.3.0` on every response (`sys_version` empty, so no Python version) | `src/aria_x/server/app.py:211-215` | High |
| Other headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: no-referrer`, `Cache-Control: no-cache`, and on HTML a CSP starting `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'` | `src/aria_x/server/app.py:57-61,426-436,514-516` | Low on their own |
| Favicon | None: `/favicon.ico` answers `204` with `Content-Type: image/x-icon` and no body, so there is no favicon hash. The logo files in `assets/` are not served | `src/aria_x/server/app.py:280-283` | n/a |
| 401 on the API | With a token set: `401`, `WWW-Authenticate: Bearer realm="ARIA-X"`, body `{"error": "unauthorized", "message": "missing or invalid bearer token"}` | `src/aria_x/server/app.py:303-307`, `src/aria_x/server/api.py:70-71` | High (only seen when `/api/...` is requested) |
| `/api/health` | `{"ok": true, "version": "0.3.0", "time": "..."}`, always without a token | `src/aria_x/server/api.py:261-262`, `src/aria_x/server/app.py:387-389` | Low on its own |
| `/api/config` | Without a token: the configuration (data and runs folders, model provider, base URL, model, budgets, sandbox, scope), `"tagline": "Autonomous Reasoning & Investigation Agent, eXtended"`, the tool catalog and `"auth_required": false`. The API key is masked as `***` | `src/aria_x/server/api.py:264-271`, `src/aria_x/config.py:284-330` | High |
| Unauthenticated control | Without a token anyone who reaches the port can create a project with an `authorized` scope (`POST /api/projects`), start a run (`POST /api/projects/p_<12 hex>/runs`), add hints and approve pending actions; with the default `local` sandbox the model's commands run as `bash -lc` on the host | `src/aria_x/server/api.py:211-230,334-410`, `src/aria_x/web/app.js:816-821` | n/a |

The scout notes (exposure pass, group 3) were confirmed at the same commit. Two additions: the console page answers without a token even when one is set, and an unauthenticated API lets a remote user start runs whose commands execute on the host.
