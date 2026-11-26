# What CAI leaves behind

CAI, Cybersecurity AI ([aliasrobotics/cai](https://github.com/aliasrobotics/cai), package `cai-framework`, by Alias Robotics, first commit March 31, 2025) is a large Python framework of security agents (red team, bug bounty, web pentester, DFIR, blue team and more) built on a fork of the OpenAI Agents SDK. It drives a shell on the operator's machine, in a Docker container or over SSH, and talks to any model LiteLLM reaches; by default it uses Alias's own `alias1` model through Alias's gateway. The repository was archived on August 22, 2026 as a single commit, `6dc79257` (CAI v1.1.5), and Alias moved its customers to a closed successor, Cybersecurity Superintelligence (CSI). It had about 9,900 stars and 1,570 forks when reviewed. File references are to the repository at `6dc79257777f5f1c9500b4d2319935d34a47412e`.

Public PyPI only carries `cai-framework` up to 0.5.10 (December 19, 2025). Version 1.x was installed from Alias's private package index (`packages.aliasrobotics.com:664`, see below). Only 1.1.5 was reviewed: the archive has no earlier history.

**Fragility** says what it takes to remove a signal: *code* means editing CAI, *config* means an environment variable or option, *operator* means a choice the operator or the model makes each time.

## How it runs

| Part | What it does | Code |
|---|---|---|
| CLI | `cai` (REPL), `cai --tui` (Textual UI), `cai --api` (HTTP backend), `--yaml <file>` (parallel agents), `--prompt <text>`, `--yolo` (no confirmation for sensitive shell commands), `--unrestricted` ("abliteration steering"), `--continue`, `--update`. Other entry points: `cai-replay`, `cai-bench`, `cai-ctr` | `src/cai/cli.py:220-238`, `pyproject.toml:282` |
| Licence check | On every start, unless `CAI_LICENSE_OFF=1`: `GET https://api.aliasrobotics.com:666/key/info` with `Authorization: Bearer <ALIAS_API_KEY>`; the CLI exits if the key is missing or rejected. `https://api.aliasrobotics.com:665/v1/validate` is defined next to it | `src/cai/util_ext.py:32-33`, `:102-116`, `:139-148`, `src/cai/cli.py:162-184` |
| Update check | In parallel, unless `CAI_SKIP_UPDATE_CHECK=1`: `python -m pip index versions --index-url https://packages.aliasrobotics.com:664/<ALIAS_API_KEY>/ cai-framework` (the key is in the URL path), or public PyPI when `CAI_LICENSE_OFF=1` | `src/cai/util_ext.py:238-263`, `:399` |
| Model | `CAI_MODEL`, default `alias1`, through `https://api.aliasrobotics.com:666/` (OpenAI compatible, `/chat/completions`), key `ALIAS_API_KEY`. Other models through LiteLLM (OpenAI, Anthropic Claude, DeepSeek, Ollama and the rest). `--unrestricted` points `OPENAI_API_BASE` at the same gateway | `src/cai/config.py:198`, `src/cai/util/llm_api_base.py:8`, `src/cai/cli.py:251-259`, `src/cai/sdk/agents/models/chatcompletions/httpx_client.py:150-165` |
| Model client user agent | `Agents/Python <version of a package named "agents">`, which is `Agents/Python 0.0.0` in a normal install (no such package). The upstream OpenAI Agents SDK sends the same string when run from source | `src/cai/sdk/agents/models/openai_chatcompletions.py:312`, `src/cai/sdk/agents/version.py` |
| Shell | Every agent's commands run with `shell=True` in the workspace `~/.cai/workspace[/<CAI_WORKSPACE>]`, or `docker exec -w /workspace <container> sh -c <command>` when a container is active, or over SSH (`sshpass -p ... ssh -o StrictHostKeyChecking=no`) | `src/cai/tools/executor.py:1110-1170`, `:1675`, `src/cai/tools/container.py:33-35`, `src/cai/tools/command_and_control/sshpass.py:58-62` |
| Containers | `/virtualization` runs `docker run -d --name kali-security --network=host -v <workspace>:/workspace --workdir /workspace --cap-add=NET_ADMIN --cap-add=NET_RAW --security-opt=seccomp=unconfined kalilinux/kali-rolling tail -f /dev/null`. Parrot runs as `cai-parrotsec`; other catalog images as `cai-<id>` (`cai-pen2`). Default image `CAI_DOCKER_IMAGE=kalilinux/kali-rolling` | `src/cai/repl/commands/_virtualization_monolith.py:216-277`, `:1657`, `:1662`, `:1825`, `src/cai/config.py:259` |
| Tools | Wrappers build plain command lines: `nmap <args> <target>`, `curl <args> <target>`, `wget <args> <url>`, `echo "<data>" \| nc -w 3 <host> <port> <args>; exit`, a PHP web shell `<?php system($_GET['cmd']); ?>`, `tcpdump -U -i <if> -w -` over SSH, plus Shodan (`api.shodan.io`), C99 (`api.c99.nl`), Google Custom Search and Perplexity lookups | `src/cai/tools/reconnaissance/*.py`, `src/cai/tools/reconnaissance/netcat.py:30-32`, `src/cai/tools/web/webshell_suit.py:20`, `src/cai/tools/network/capture_traffic.py:56` |
| Web fetch | `fetch_url` sends `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36` (a two-part Chrome version, which real Chrome never sends) and retries through curl-cffi with a Chrome 124 TLS fingerprint on 403/503 or a bot challenge. `CAI_FETCH_USER_AGENT` overrides it | `src/cai/tools/web/fetch_url.py:224-233`, `:305-311`, `:566` |
| Prompts | Every agent prompt starts with `# CAI CYBER BASELINE` and "You are operating inside CAI, a cybersecurity-specialized framework." The web pentester prompt says written authorization already exists for every task | `src/cai/util/prompts.py:14-16`, `:48`, `src/cai/prompts/system_web_pentester.md` |
| Session log | `~/.cai/logs/cai_<uuid>_<YYYYmmdd_HHMMSS>_<user>_<os>_<release>_<public ip with _>.jsonl` (prefixed with the workspace name if set). The first line is `{"event": "session_start", ..., "alias_api_key": "<key>"}`; every model request and response follows | `src/cai/sdk/agents/run_to_jsonl.py:89-160` |
| Public IP lookup | Before naming that file: TCP connect to `1.1.1.1:53`, then `GET https://api.ipify.org`, falling back to `https://ifconfig.me`. `CAI_SKIP_NETWORK_CHECK=true` skips it | `src/cai/sdk/agents/run_to_jsonl.py:108-133` |
| Telemetry | The URL is hidden as three base64 pieces, `aHR0cHM6Ly9sb2dzLg==`, `YWxpYXNyb2JvdGljcy5jb20v`, `dXBsb2Fk`, which join to `https://logs.aliasrobotics.com/upload`. Before each upload: TCP connect to `8.8.8.8:53` (or `GET https://www.google.com`). Upload: `POST` multipart with `session_id` and the whole session log as field `log` (file name `cai_....jsonl`), by `python-requests`. At the end of every session to `/upload` (off with `CAI_TELEMETRY=false`), and every 5 model interactions to `/upload/intermediate`, which `CAI_TELEMETRY` does **not** turn off | `src/cai/internal/components/endpoints.py:21-23`, `network.py:13-17`, `transfer.py:33-38`, `metrics.py:55-88`, `src/cai/cli_headless.py:2502-2505`, `src/cai/sdk/agents/models/openai_chatcompletions.py:355`, `:668`, `:4529-4537`, `src/cai/config.py:223` |
| API server | `cai --api`: FastAPI on uvicorn, `127.0.0.1:8000` by default (`CAI_API_HOST`, `CAI_API_PORT`; next free port up to +25 if busy). Docs show `--api-host 0.0.0.0 --api-port 8080` | `src/cai/api/server.py:21-70`, `docs/api.md:8` |
| Persistence | The continuous-ops wizard writes `~/.cai/continuous_ops/run_<12 hex>/` and can install a systemd user unit `cai-cops-run_<12 hex>.service` (`Description=CAI Continuous Ops worker`, `ExecStart=<python> -m cai.continuous_ops.loop_runner --run-dir <dir>`, `Restart=always`) with `systemctl --user enable --now`, or run in tmux session `cai-cops-<8 hex>` | `src/cai/continuous_ops/wizard.py:853`, `:888`, `:939`, `src/cai/continuous_ops/systemd_unit.py:52-100` |

## Signals on the target side

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Web fetch user agent | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36` with `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf,application/json;q=0.9,*/*;q=0.5`. Real Chrome sends `Chrome/124.0.0.0` | `src/cai/tools/web/fetch_url.py:224-233` | Config (`CAI_FETCH_USER_AGENT`) |
| Stock tools | nmap, curl, wget, nc, sshpass, ffuf, sqlmap, gobuster and whatever the model picks, with their own defaults. The netcat wrapper always sends a line (empty or `<data>`) with a 3 second timeout | `src/cai/tools/reconnaissance/*.py` | Operator |
| PHP web shell | `<?php system($_GET['cmd']); ?>` uploaded as `shell.php`, driven as `?cmd=` | `src/cai/tools/web/webshell_suit.py:20-51` | Code; common to many tools, context only |
| Markers | None. The code has no canary, payload marker, test account or callback domain of its own; the prompts only use `attacker.com` and `evil.com` as examples | `src/cai/prompts/system_apt_agent.md`, `system_android_sast.md` | |

## Signals on a host that runs CAI

| Signal | What it looks like | Fragility |
|---|---|---|
| Command | `cai --api`, `cai --tui`, `cai --yolo`, `cai --unrestricted`, `cai --yaml <file>`, `pip install cai-framework` (or with `--index-url https://packages.aliasrobotics.com:664/<key>/`). A bare `cai` is too short to hunt on its own | Code |
| Children | `/bin/sh -c <command>` children of the `python .../bin/cai` process, in `~/.cai/workspace` | Code |
| Files | `~/.cai/logs/cai_*.jsonl`, `~/.cai/usage.json`, `~/.cai/api_auth.json` and `api_auth.json.key`, `~/.cai/debug/cai_*.log`, `~/.cai/workspace/`, `~/.cai/continuous_ops/run_*` | Code |
| Container | `kali-security` from `kalilinux/kali-rolling` with `--network=host`, `seccomp=unconfined`, `/workspace` mount and `tail -f /dev/null` | Code (name), config (image) |
| Persistence | `~/.config/systemd/user/cai-cops-run_<hex>.service` running `-m cai.continuous_ops.loop_runner` | Operator (wizard) |
| Environment | `ALIAS_API_KEY`, `CAI_MODEL`, `CAI_LICENSE_OFF`, `CAI_TELEMETRY`, `CAI_YOLO`, `CAI_UNRESTRICTED`, `CAI_WORKSPACE`, `CAI_API_HOST` in `.env` or the process environment | Config |

## Network signals from the host

| Signal | What it looks like | Fragility |
|---|---|---|
| Telemetry | DNS and TLS to `logs.aliasrobotics.com`, `POST /upload` and `/upload/intermediate` (multipart `name="log"; filename="cai_...jsonl"`). The intermediate upload runs every 5 model turns even with `CAI_TELEMETRY=false` | Code |
| Licence and model gateway | TLS to `api.aliasrobotics.com` on **TCP 666** (model and `/key/info`) and 665 (`/v1/validate`). Unusual ports for TLS | Config (`CAI_LICENSE_OFF=1` and a non-Alias model remove it) |
| Private package index | TLS to `packages.aliasrobotics.com` on **TCP 664**, the API key in the URL path | Config (`CAI_SKIP_UPDATE_CHECK=1`) |
| Public IP and reachability | TCP 53 to `1.1.1.1` and `8.8.8.8` with no DNS query in it, `api.ipify.org`, `ifconfig.me`, `www.google.com`. Context only | Config |
| Model API user agent | `Agents/Python 0.0.0` on model requests, visible only with TLS inspection | Code |

## An exposed CAI API

CAI has no web console. `cai --api` serves a JSON API only, so an exposed CAI is a bare uvicorn server:

- `/` returns `404 {"detail":"Not Found"}` (no route), with uvicorn's `server: uvicorn` header. Nothing on `/` identifies CAI, so a search engine that only fetches `/` will not find it.
- `GET /api/v1/health` (no authentication) returns `{"status":"ok","version":"1.1.5"}`; `GET /api/tags` and `/api/v1/tags` (no authentication) return `{"tags":["meta","auth","catalog","sessions","inference","commands","ux"]}` (`src/cai/api/app.py:220-235`).
- `GET /api/openapi.json` has `"title":"CAI API"` and `"description":"Backend HTTP state for the Cybersecurity AI Framework"`; `/api/docs` is FastAPI's Swagger page, titled `CAI API - Swagger UI` by FastAPI from the app title, and `/api/redoc` is titled `CAI API - ReDoc` (`src/cai/api/app.py:101-108`). The Swagger page loads its favicon from `fastapi.tiangolo.com`, so the host has no favicon hash of its own.
- Authentication: the header `X-CAI-API-Key` (`CAI_API_KEY_HEADER`) carries `ALIAS_API_KEY` or a session token. **When neither `ALIAS_API_KEY` nor `CAI_API_KEY` is set, every route is open** (`src/cai/api/app.py:129-173`). The licence check needs `ALIAS_API_KEY` unless `CAI_LICENSE_OFF=1`, so an open API is one started in licence-off mode without a key. The open routes create sessions that run agents with a shell, which is remote command execution on the operator's machine.
- `POST /api/v1/auth/add-ip` issues a random user and session token bound to a device address; `/api/v1/auth/register` and `/api/v1/auth/login` handle named users. On first start the server prints a default login `default-<6 hex>` with a random password and stores users in `~/.cai/api_auth.json`, AES-GCM encrypted with the key next to it (`src/cai/api/auth.py:262-283`). CORS defaults to `*` with credentials (`CAI_API_CORS`).

## What has been seen in the wild

- No public report of CAI used maliciously was found, and no public detection rules for it existed before these.

## What the code does not contain

CAI ships no implant, C2 or persistence on targets. It has a raw reverse-shell listener tool and a PHP web-shell generator, and its systemd unit only keeps its own loop running on the operator's machine. Its telemetry sends the operator's full session logs, including the targets, commands, model output and the Alias API key, to Alias Robotics.
