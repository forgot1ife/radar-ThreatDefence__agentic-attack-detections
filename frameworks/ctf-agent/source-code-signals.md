# What CTF Agent leaves behind

CTF Agent ([verialabs/ctf-agent](https://github.com/verialabs/ctf-agent); first commit March 23, 2026; MIT, copyright Veria Labs, Inc.; Python with a Dockerfile; 951 stars and 171 forks on November 26, 2026; not archived; no releases or tags; reviewed at `3366d569` (`3366d569557c4fda3fd153040632de65e255396d`), March 29, 2026, the last commit on `main`) is an autonomous solver for Capture The Flag competitions run on the CTFd platform. Its README says it solved all 52 challenges of the BSidesSF 2026 CTF. A coordinator model watches the CTFd platform and starts a "swarm" for every unsolved challenge: several solver models (Claude Opus 4.6 through the Claude Code CLI, GPT-5.4, GPT-5.4-mini and GPT-5.3-codex through the Codex CLI) race on the same challenge, each in its own Docker sandbox, and the first confirmed flag is submitted to CTFd. File references are to the repository at `3366d569`. The Python package is named `ctf-agent-two` and is not published on PyPI; there is no Docker Hub image and no hosted service.

The repository has four commits, all from March 23 to 29, 2026. `pull_challenges.py` and the CTFd login code are credited to [es3n1n/Eruditus](https://github.com/es3n1n/Eruditus) (`README.md:152`, `pull_challenges.py:4-5`); the Eruditus code was not reviewed.

**Fragility** says what it takes to remove a signal: *code* means editing CTF Agent, *config* means a CLI flag, `.env` value or setting, *operator* means a choice made at run time. *Code (prompt)* marks a string that is in a system prompt: removing it means editing CTF Agent, but the model decides what it runs.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Install | `uv sync`, then `docker build -f sandbox/Dockerfile.sandbox -t ctf-sandbox .`, then `cp .env.example .env`. Needs Python 3.14, Docker, the `codex` CLI and the `claude` CLI bundled with `claude-agent-sdk` | `README.md:59-77,142-148`, `pyproject.toml:1-22` |
| Entry points | `ctf-solve` (`backend.cli:main`) and `ctf-msg` (`backend.cli:msg`), usually `uv run ctf-solve --ctfd-url <url> --ctfd-token <token> --challenges-dir challenges --max-challenges 10 -v`. Options: `--image` (default `ctf-sandbox`), `--models`, `--challenge <dir>` (one challenge, no coordinator), `--no-submit`, `--coordinator claude\|codex`, `--coordinator-model`, `--msg-port` (default 0). Prints the banner `CTF Agent v2` | `pyproject.toml:20-22`, `backend/cli.py:31-83` |
| Settings | `.env` and environment: `CTFD_URL` (default `http://localhost:8000`), `CTFD_USER` and `CTFD_PASS` (default `admin` / `admin`), `CTFD_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `AWS_REGION` (`us-east-1`), `AWS_BEARER_TOKEN`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `OPENCODE_ZEN_API_KEY`, `SANDBOX_IMAGE`, `CONTAINER_MEMORY_LIMIT` (`16g`) | `backend/config.py:8-33`, `.env.example:1-8` |
| Coordinator | Default: Claude Agent SDK with model `claude-opus-4-6`, `permission_mode="bypassPermissions"`, an in-process MCP server named `coordinator` (tools `fetch_challenges`, `get_solve_status`, `spawn_swarm`, `check_swarm_status`, `submit_flag`, `kill_swarm`, `bump_agent`, `broadcast`, `read_solver_trace`, seen by the model as `mcp__coordinator__<tool>`). `--coordinator codex` starts `codex app-server` with model `gpt-5.4` and `clientInfo` `ctf-coordinator` 2.0.0. The Claude coordinator's prompt says "NEVER kill a swarm" and "Cost is not a concern" | `backend/agents/claude_coordinator.py:34-56,107-158`, `backend/agents/codex_coordinator.py:30-31,140-175,339` |
| Event loop | Polls CTFd every 5 seconds, starts a swarm for each new or unsolved challenge (up to `--max-challenges`), kills swarms of solved ones, and sends the coordinator a status line every 60 seconds | `backend/agents/coordinator_loop.py:69-208`, `backend/poller.py:19-125` |
| Solvers | Default specs `claude-sdk/claude-opus-4-6/medium`, `claude-sdk/claude-opus-4-6/max`, `codex/gpt-5.4`, `codex/gpt-5.4-mini`, `codex/gpt-5.3-codex` (reasoning effort `xhigh`). When a subscription quota runs out a solver falls back to `bedrock/us.anthropic.claude-opus-4-6-v1`, `azure/gpt-5.4`, `azure/gpt-5.4-mini` or `zen/gpt-5.3-codex-spark`. Providers `bedrock`, `azure`, `zen` and `google` go through Pydantic AI | `backend/models.py:21-27,50-98`, `backend/agents/codex_solver.py:48-50`, `backend/agents/swarm.py:34-39,70-110` |
| Claude solver | Claude Agent SDK with the solver prompt, `allowed_tools=["Bash", "WebFetch", "WebSearch"]`, `permission_mode="bypassPermissions"`, `env={"CLAUDECODE": ""}`. A PreToolUse hook rewrites every Bash command to `docker exec -i <container id> bash -c <command>`, turns `submit_flag <flag>` and `notify_coordinator <msg>` into CTFd calls and `echo`, and denies Read, Write, Edit, Glob, Grep and the rest | `backend/agents/claude_solver.py:97-273` |
| Codex solver | `codex app-server` over stdio (JSON-RPC), `clientInfo` `ctf-agent` 2.0.0, thread with `personality: pragmatic`, `cwd: /challenge`, `approvalPolicy: on-request`, `sandbox: read-only`, `serviceTier: flex` and its own dynamic tools `bash`, `read_file`, `write_file`, `list_files`, `submit_flag`, `web_fetch`, `webhook_create`, `webhook_get_requests`, `view_image`, `notify_coordinator`, all run by CTF Agent, not by Codex | `backend/agents/codex_solver.py:57-116,174-230` |
| Sandbox | One container per solver from image `ctf-sandbox`: `Cmd ["sleep", "infinity"]`, `WorkingDir /challenge`, label `ctf-agent=true`, `ExtraHosts host.docker.internal:host-gateway`, `CapAdd SYS_ADMIN, SYS_PTRACE`, `SecurityOpt seccomp=unconfined`, device `/dev/loop-control`, the configured memory and 2 CPUs. Not privileged. Binds a new host folder `ctf-workspace-<random>` (Python `tempfile.mkdtemp`) on `/challenge/workspace` read-write, and the challenge's `distfiles` and `metadata.yml` read-only. Deleted when the solver stops; at start every container with the label `ctf-agent` is force-deleted | `backend/sandbox.py:19,49-68,109-149,272-296` |
| Sandbox image | `ubuntu:22.04` with netcat, curl, wget, nmap, gdb, binwalk, exiftool, steghide, sleuthkit, foremost, tesseract, sagemath, podman (nested containers), radare2, flatter, uv, zsteg, stegseek, pwntools, angr, z3, volatility3, pyghidra, PyTorch, RsaCtfTool and CADO-NFS; tool list copied to `/tools.txt` | `sandbox/Dockerfile.sandbox:4-139`, `sandbox/sandbox-tools.txt` |
| Operator messages | A raw asyncio HTTP server on `127.0.0.1` (hard-coded), port `--msg-port` (0 = random, logged as `Operator message endpoint listening on http://127.0.0.1:<port>`). Any POST with a body is queued for the coordinator as `OPERATOR MESSAGE: ...` and answered `{"ok": true, "queued": ...}`; anything else gets `400` with `{"error": "POST with JSON body required", "usage": "POST {\"message\": \"...\"}"}`. No authentication. `ctf-msg "<text>"` posts to `http://127.0.0.1:9400/msg` by default | `backend/agents/coordinator_loop.py:88-89,152-158,233-280`, `backend/cli.py:192-215` |
| Output | `challenges/<slug>/metadata.yml` and `challenges/<slug>/distfiles/` for each pulled challenge; one JSONL trace per solver in `logs/`; results and costs on stdout. `.gitignore` also lists `workspace/`, `codex-schema-*/`, `creds.json` and `.claude/scheduled_tasks.lock` | `backend/ctfd.py:195-271`, `backend/tracing.py:15-58`, `.gitignore:1-27` |
| Telemetry, update check | None found in the repository. The Claude Code and Codex CLIs it drives have their own | whole repository |
| Standalone helper | `python pull_challenges.py --url <ctfd> (--token <t> \| --username <u> --password <p>) [--output ./challenges]` downloads every challenge and unlocks free hints with `POST /api/v1/unlocks` | `pull_challenges.py:7-19,166-222,351-360` |

## Signals on the target side

The target here is first the CTFd platform the agent plays on, and second the challenge services its solvers attack.

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| CTFd client user agent | Exactly `Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36` on every request to CTFd: a Windows 7 string cut off before `(KHTML, like Gecko)`, which no browser sends. httpx client, `follow_redirects=False`, TLS verification off | `backend/ctfd.py:14,36-47` | Code |
| CTFd polling | `GET /api/v1/challenges?per_page=500`, then `GET /api/v1/users/me` and `/api/v1/teams/<id>/solves` or `/api/v1/users/<id>/solves`, every 5 seconds for the whole competition, with `Authorization: Token <token>` and `Content-Type: application/json` | `backend/ctfd.py:89-100,125-128,173-193`, `backend/poller.py:24,85-125`, `backend/agents/coordinator_loop.py:85` | Code |
| Challenge pull | `GET /api/v1/challenges/<id>` for every visible challenge and a download of each file it lists (auth headers only to the CTFd host) | `backend/ctfd.py:163-171,195-237` | Code |
| Flag submission | `POST /api/v1/challenges/attempt` with `{"challenge_id": <id>, "submission": "<flag>"}`; without a token it first fetches `/challenges` for `csrfNonce` and sends it as `CSRF-Token`, retrying once on 403 | `backend/ctfd.py:78-87,102-123,142-149` | Code |
| Default login | With no `CTFD_TOKEN`, `GET /login` for the nonce, then `POST /login` with `name=admin&password=admin&_submit=Submit&nonce=<nonce>` (form-encoded) unless `CTFD_USER` and `CTFD_PASS` are set | `backend/config.py:10-13`, `backend/ctfd.py:49-76` | Config |
| pull_challenges.py user agent | The full string `Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36` on `/login`, `/challenges`, `/api/v1/users/me`, `/api/v1/challenges`, `/api/v1/challenges/<id>`, `/api/v1/unlocks` and `/api/v1/hints/<id>`. Taken from Eruditus, so it is not unique to CTF Agent | `pull_challenges.py:35,42-120,157-240` | Code |
| Host web fetch | The `web_fetch` tool of the Pydantic AI and Codex solvers fetches from the operator host (not the sandbox) with `User-Agent: Mozilla/5.0` exactly and TLS verification off; it refuses loopback, link-local and RFC 1918 addresses. Bare `Mozilla/5.0` is used by many scripts: context only | `backend/tools/core.py:90-125` | Code |
| Out-of-band callbacks | `webhook_create` posts to `https://webhook.site/token` and hands the model `https://webhook.site/<uuid>` for XSS, SSRF and bot challenges; `webhook_get_requests` reads `https://webhook.site/token/<uuid>/requests`. The Claude solver prompt says to `curl` to webhook.site instead. A target sees requests to `webhook.site/<uuid>` from its bot or server | `backend/tools/core.py:128-152`, `backend/prompts.py:150-157` | Code, code (prompt) |
| Sandbox traffic | Everything else the solvers send comes from the sandbox through the host's Docker bridge: curl, wget, nmap, netcat, python requests and pwntools with their default user agents and banners. Connection info naming `localhost` or `127.0.0.1` is rewritten to `host.docker.internal` | `backend/prompts.py:49-55,96-110`, `sandbox/Dockerfile.sandbox:10-12` | Code (prompt) |

## Signals on a host that runs CTF Agent

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Launcher | `ctf-solve` with `--ctfd-url`, `--ctfd-token`, `--challenges-dir`, `--coordinator`, `--max-challenges`, `--msg-port` or `--no-submit`; under `uv run` the process is `<venv>/bin/python <venv>/bin/ctf-solve ...`. `ctf-msg "<text>"` for hints | `pyproject.toml:20-22`, `backend/cli.py:31-43,192-196` | Code (names), operator (flags) |
| Model CLIs | `codex app-server` started by the `ctf-solve` Python process, one per Codex solver and one for the Codex coordinator. The Claude Code CLI started by the Claude Agent SDK with the solver or coordinator prompt; whether the prompt is on the `claude` command line depends on the SDK version and was not checked | `backend/agents/codex_solver.py:186-191`, `backend/agents/codex_coordinator.py:151-156`, `backend/agents/claude_solver.py:256-277` | Code |
| Claude solver commands | Each model Bash command becomes `docker exec -i <64 hex container id> bash -c '<command>'`, run by the Claude Code CLI's shell | `backend/agents/claude_solver.py:189-201` | Code |
| Sandbox command wrapper | Through the Docker API: `bash -c "timeout --signal=KILL --kill-after=5 <seconds> bash -c '<command>'"` inside the container, 60 seconds by default for tools and 300 for the sandbox default. The first command of every sandbox is `timeout --signal=KILL --kill-after=5 10 bash -c 'uname -m'` | `backend/sandbox.py:151-171`, `backend/tools/core.py:20`, `backend/agents/claude_solver.py:93`, `backend/agents/codex_solver.py:177` | Code |
| Containers | Image `ctf-sandbox` (local build), label `ctf-agent=true`, command `sleep infinity`, workdir `/challenge`, `SYS_ADMIN` and `SYS_PTRACE`, seccomp unconfined, `/dev/loop-control`, extra host `host.docker.internal`. Up to `--max-challenges` x solvers at once (50 with the defaults); warnings at 100, 200 and 500 | `backend/sandbox.py:19,26,109-145`, `backend/cli.py:100-101,160-161` | Code (label, options), config (image) |
| Workspace folders | `<tmp>/ctf-workspace-<random>/` (`/tmp/` on Linux), mounted on `/challenge/workspace`; removed when the solver stops | `backend/sandbox.py:114,120,288-294` | Code |
| Solver traces | `logs/trace-<challenge>-<model>-<YYYYmmdd-HHMMSS>.jsonl` in the working directory (`/` and spaces in names become `_`). Lines `{"ts": <epoch>, "type": "start", "challenge": ..., "model": ...}`, then `tool_call`, `tool_result`, `usage`, `model_response`, `loop_break`, `bump`, `flag_confirmed`, `turn_complete`, `finish`, `stop` | `backend/tracing.py:15-58`, `backend/agents/claude_solver.py:131,163,277,337-376` | Code |
| Challenge folders | `challenges/<slug>/metadata.yml` (keys `name`, `category`, `description`, `value`, `connection_info`, `tags`, `solves`, `hints`) and `challenges/<slug>/distfiles/` | `backend/ctfd.py:205-269`, `backend/cli.py:37` | Code, config (folder) |
| Loopback listener | `127.0.0.1:<random>` (or the `--msg-port`) owned by the `ctf-solve` process for the whole run | `backend/agents/coordinator_loop.py:274-276` | Code (bind), config (port) |
| Environment | `CTFD_URL`, `CTFD_TOKEN`, `CTFD_USER`, `CTFD_PASS` and the model keys above, in `.env` in the working directory | `backend/config.py:8-33` | Config |

## Network signals from the host

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| CTFd | The user agent and request pattern above, to the competition's CTFd host | `backend/ctfd.py` | Code |
| Anthropic and OpenAI | Through the Claude Code and Codex CLIs, with their own hosts and user agents (not set in this repository). Codex threads ask for `serviceTier: flex` | `backend/agents/claude_solver.py:256-273`, `backend/agents/codex_solver.py:211-220` | Config |
| Fallback providers | Amazon Bedrock `bedrock-runtime` in `us-east-1` by default, Azure OpenAI at `AZURE_OPENAI_ENDPOINT`, OpenCode Zen at `https://opencode.ai/zen/v1`, Google AI Studio for `google/*` specs | `backend/models.py:55-91`, `backend/config.py:21-25` | Config |
| webhook.site | `POST https://webhook.site/token` and `GET https://webhook.site/token/<uuid>/requests` from the host | `backend/tools/core.py:128-152` | Code |
| Sandbox build | `git clone` of radare2, flatter, stegseek, RsaCtfTool (GitHub) and CADO-NFS (`gitlab.inria.fr`), `https://astral.sh/uv/install.sh`, the kubic podman repository on `download.opensuse.org`, PyTorch CPU wheels from `download.pytorch.org`, at image build time only | `sandbox/Dockerfile.sandbox:49-125` | Code |

## Prompts

These go to the model API with every request; they are visible where model traffic is inspected, in Claude Code or Codex session files, or on disk in the source.

| Prompt | Text | Code |
|---|---|---|
| Solver | `You are an expert CTF solver. Find the real flag for the challenge below.` | `backend/prompts.py:72-73` |
| Sandbox preamble (Claude and Codex solvers) | `IMPORTANT: You are running inside a Docker sandbox. All files are under /challenge/ — distfiles at /challenge/distfiles/, workspace at /challenge/workspace/. Do NOT use any paths outside /challenge/.` | `backend/agents/claude_solver.py:97-104`, `backend/agents/codex_solver.py:205-210` |
| Coordinator | `You are a CTF competition coordinator running for the ENTIRE duration of a live competition.` | `backend/agents/claude_coordinator.py:34-35`, `backend/agents/codex_coordinator.py:30-31` (its own copy, same first line) |
| Instructions | `**Use tools immediately. Do not describe — execute.**`, `Ignore placeholder flags`, `Once CORRECT: output FLAG: <value> on its own line.`, `Do not guess. Do not ask. Cover maximum surface area.` | `backend/prompts.py:159-179` |

The prompts carry no scope or authorization text: the agent attacks whatever challenge services CTFd lists.

## Exposure

None. CTF Agent has no web UI and no API server. Its only listener, the operator message endpoint, is bound to `127.0.0.1` in the code (`backend/agents/coordinator_loop.py:274`) on a random port unless `--msg-port` is given, so internet scans should not see it; it would need a port forward or a proxy. The repository holds no favicon, logo or HTML page. No rows are added to `exposure/shodan-queries.csv` or `exposure/consoles.csv`.

## What has been seen in the wild

No public report of CTF Agent used against a target outside a CTF was found on November 26, 2026. Its README reports first place at the BSidesSF 2026 CTF.

## What the code does not contain

No implant, C2, persistence, payload or exploit code, and no scope check. It solves whatever CTFd lists and submits flags unless `--no-submit` is given. Its solver containers run with `SYS_ADMIN`, `SYS_PTRACE`, seccomp off and nested podman, which is the host's main exposure while it runs.

## Rules

| Rule | Signal |
|---|---|
| [`suricata/ctf-agent.rules`](suricata/ctf-agent.rules) 3813341 | CTFd client user agent |
| [`suricata/ctf-agent.rules`](suricata/ctf-agent.rules) 3813342 | Default admin/admin login |
| [`suricata/ctf-agent.rules`](suricata/ctf-agent.rules) 3813343 | pull_challenges.py user agent (shared with Eruditus) |
| [`sigma/web/web_ctf_agent_ctfd_client.yml`](sigma/web/web_ctf_agent_ctfd_client.yml) | CTFd client user agent in web server logs |
| [`sigma/proxy/proxy_ctf_agent_ctfd_client.yml`](sigma/proxy/proxy_ctf_agent_ctfd_client.yml) | CTFd client user agents in proxy logs |
| [`sigma/process_creation/proc_creation_ctf_agent_launcher.yml`](sigma/process_creation/proc_creation_ctf_agent_launcher.yml) | Launcher and model CLIs |
| [`sigma/process_creation/proc_creation_ctf_agent_solver_docker_exec.yml`](sigma/process_creation/proc_creation_ctf_agent_solver_docker_exec.yml) | Claude solver commands |
| [`sigma/process_creation/proc_creation_lnx_ctf_agent_sandbox_command_wrapper.yml`](sigma/process_creation/proc_creation_lnx_ctf_agent_sandbox_command_wrapper.yml) | Sandbox command wrapper |
| [`sigma/file_event/file_event_ctf_agent_files.yml`](sigma/file_event/file_event_ctf_agent_files.yml) | Workspace folders and solver traces |
| [`yara/ctf-agent.yar`](yara/ctf-agent.yar) | Source files and solver traces |
| [`sentinel/analytics/ctf-agent-sandbox-on-a-host.yaml`](sentinel/analytics/ctf-agent-sandbox-on-a-host.yaml) | Sandbox start, prompts and launcher |
