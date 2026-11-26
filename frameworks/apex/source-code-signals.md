# What Pensar Apex leaves behind

Pensar Apex ([pensarai/apex](https://github.com/pensarai/apex), first commit October 7, 2025, reviewed at `6e3c5488d1dcdc63b1c37fd207e65919873489e6`, November 25, 2026, version 2.7.0; TypeScript on Bun; 334 stars and 68 forks on November 26, 2026; not archived) is a terminal penetration testing agent from Pensar. The repository's `LICENSE` is Apache-2.0 and the README badge says Apache 2.0, but `package.json:341` says MIT. It is published on npm as `@pensar/apex` (latest 2.7.0, first published October 21, 2025), as standalone `pensar-<os>-<arch>` binaries on GitHub releases (`.github/workflows/release.yml:25-42,70`), through the Homebrew tap `pensarai/tap`, and through install scripts at `pensarai.com`. It is the open core of the commercial Pensar Console (`console.pensar.dev`), which can run the same agent as a managed service. File references are to the repository at `6e3c5488`.

**Fragility** says what it takes to remove a signal: *code* means editing Apex, *config* means a setting in `~/.pensar/config.json` or an environment variable, *operator* means a choice made at run time, *code (prompt)* means the model decides, steered by a prompt in the code.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Entry points | `pensar` opens the TUI (needs Bun). `pensar pentest --target <url>`, `pensar targeted-pentest --target <url> --objective <text>`, `pensar threat-model`, `pensar -p <prompt>` (operator session) and `pensar --resume <session-id>` run headless. `bin/pensar.js` re-runs itself under `bun` for the TUI and otherwise imports `build/cli.js` under Node | `package.json:2-4`, `bin/pensar.js:10-45`, `src/cli.ts:266-290` |
| Approval | The headless operator session sets `requireApproval: false`; approval prompts exist only in the interactive operator mode | `src/cli.ts:730` |
| Local run worker | `pensar agent-runs start --detach` starts a worker (`agent-runs worker --run <id> --store <db>`) that serves `POST /rpc` over a private Unix socket (mode 0600). No TCP port | `src/cli/agent-runs.ts:27-38`, `src/core/runtime/localWorkerTransport.ts:77-85,187-192`, `src/core/runtime/launchLocalWorker.ts:16-56` |
| Shell | Local agent commands run as `bash --norc --noprofile -c <command>` in their own process group (`cmd /d /s /c` on Windows). Long jobs (the callback listener, white-box jobs) run as `/bin/sh -c <command>` | `src/core/agents/offSecAgent/tools/perCommandShell.ts:156-173`, `src/core/whitebox/jobKernel.ts:177-184` |
| Tools it drives | Whatever the model writes in `execute_command`, with examples for nmap, curl, nikto, gobuster and ffuf in the tool description; a Playwright MCP browser (`@playwright/mcp`, Chromium or Camoufox); an HTTP client; a PoC runner; email (IMAP, Gmail, Outlook) and SMS inbox tools for sign-up flows; web search; sandboxes on Daytona or a remote host | `src/core/agents/offSecAgent/tools/executeCommand.ts:324-338`, `playwrightMcp.ts`, `tools/email/adapters.ts:9,98`, `src/core/tools/daytonaSandbox.ts` |
| Kali container (optional) | `container/docker-compose.yml`: service, image and container `kali-apex` (`kali-apex:latest`, built from `kalilinux/kali-rolling` with nmap, sqlmap, nikto, gobuster, hydra, john, hashcat and more, then `bun install -g @pensar/apex`), `NET_ADMIN` and `NET_RAW`, `seccomp:unconfined`, bridge network, the repository mounted on `/home/pentest/app`, user `pentest` with passwordless sudo. No published ports | `container/docker-compose.yml:1-24`, `container/Dockerfile:1-61` |
| Models | Pensar's own gateway first (`pensar:anthropic.claude-opus-4-6-v1` over `https://gateway.pensar.dev/gateway/invoke` when signed in), then Anthropic (`claude-opus-4-6`), OpenAI (`gpt-5.6-sol`), Google (`gemini-3.1-pro-preview`), OpenRouter, Concentrate, Inference.net, Bedrock; also Ollama (`http://127.0.0.1:11434`), Hoonify, Baseten, Inception and custom OpenAI-compatible endpoints | `src/core/providers/utils.ts:9-29`, `src/core/api/constants.ts:1-15`, `src/core/ai/providers/pensar.ts:255`, `README.md` |
| Pensar services | Console API `https://api.pensar.dev` (sign-in, web search gateway `/agents/web_search`, workspace apps and issues), sign-in through WorkOS device flow (`api.workos.com`). Requests carry `X-Pensar-Client: cli`, `X-Pensar-Client-Version` and `X-Pensar-Command`; gateway and web search requests are signed with `X-Pensar-Timestamp`, `X-Pensar-Nonce` and `X-Pensar-Signature`. `PENSAR_API_URL`, `PENSAR_GATEWAY_URL` and `PENSAR_CONSOLE_URL` override the hosts | `src/core/api/constants.ts`, `src/core/api/clientIdentity.ts:15-19`, `src/core/agents/offSecAgent/tools/webSearch.ts:241-257`, `src/core/auth/device-flow.ts:37,99` |
| Update check and upgrade | `GET https://registry.npmjs.org/@pensar/apex/latest`; `pensar upgrade` for script installs runs `bash -c "curl -fsSL https://pensarai.com/install.sh \| bash"` | `src/core/installation/index.ts:35,107` |
| Telemetry | None by default. OpenTelemetry spans are no-ops unless the host registers an SDK; W&B Weave tracing only with `WANDB_API_KEY`; Herdr state reports (`herdr ... --source pensar-apex`) only inside Herdr | `README.md`, `src/core/integrations/herdr.ts:11`, `src/core/integrations/wandb/` |
| Web UI, API server | None. The only TCP listener is the agent's own short-lived callback listener (below) | whole repository |

## Signals on the target side

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Default user agent | `User-Agent: pensar-apex`. Every new session snapshots `defaultHeaders`, which default to this value, and the session fallback is the same. The resolver adds session headers only to in-scope URLs | `src/core/config/config.ts:17-23`, `src/core/session/index.ts:36-38,627-638`, `src/core/http/targetHeaders.ts:71-109` | Config (`pensar config headers`, `--no-global-headers`, `--header`) |
| User agent on shell tools | For in-scope hosts Apex rewrites the model's command: `curl` gets `-H "User-Agent: pensar-apex"` and ` --max-redirs 0` appended; `wget` gets `--header="User-Agent: pensar-apex"` and `--max-redirect=0`; nuclei, ffuf, gobuster, httpx, feroxbuster, dirb, wfuzz and wpscan get `-H`; sqlmap gets `--headers=`; nikto gets `-headers`. A header the command already sets (including `-A`) is left alone | `src/core/http/targetHeaders.ts:203-316,572-612`, `src/core/agents/offSecAgent/tools/executeCommand.ts:461` | Config |
| get_page user agent | `Mozilla/5.0 (compatible; PensarBot/1.0; +https://pensar.dev)` with `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` and `Accept-Language: en-US,en;q=0.5`, when the agent reads a page as text | `src/core/tools/backends/local.ts:83-100,928` | Code |
| Browser user agent | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36`, 1920x1080 viewport. The session's `pensar-apex` header is stripped from browser requests on purpose. An ordinary Chrome string | `src/core/agents/offSecAgent/tools/playwrightMcp.ts:337-346`, `src/core/http/targetHeaders.ts:115-133` | Code |
| Auth endpoint probe | `probe_auth_endpoints` sends GET and then POST `{}` (`Content-Type: application/json`) to 43 fixed paths in order: `/api/login`, `/api/auth/login`, `/api/v1/login`, ... `/token`, `/api/session`, `/api/me` ... `/api/admin`, `/dashboard`, `/api/dashboard`, with the session user agent | `src/core/agents/offSecAgent/tools/probeAuthEndpoints.ts:7-61,138-187` | Code (the model chooses to call it) |
| Sign-up test account | The registration prompt tells the model to create `email: test-<Date.now()>@example.com`, `username: testuser-<Date.now()>` (13-digit millisecond time) and `password: TestPassword123!@#` and submit it at once | `src/core/agents/specialized/authenticationAgent/prompts.ts:404-412` | Code (prompt) |
| Callback listener | `start_callback_listener` runs a Node HTTP server, bound to `0.0.0.0` on an ephemeral port by default, for up to 600 s (maximum 3600 s). The payload URL is `<advertised base>/<32 hex nonce>/cb`. A correlated path gets `200`, `Content-Type: text/plain`, body `apex-callback <nonce>`; any other path gets `404` `not found`. No `Server` header | `src/core/agents/offSecAgent/tools/callbackListener.ts:21-22,126-175,251-263,598-616,642,685` | Code |
| PoC requests | `http_poc` writes a bash script whose requests run `curl -q -g -sS --proto '=http,https' --max-time 30 --suppress-connect-headers -D "$header_file" -o "$body_file" -w '%{http_code}' ... --url <url>` with only the headers the model gave, so the target sees curl's own user agent | `src/core/agents/offSecAgent/tools/httpPoc.ts:139-178` | Code |
| Example prompt injections | The shipped example library (`examples/prompt-injection/`) asks the target model to answer `PROMPT_INJECTION_TEST_DIRECT_OVERRIDE`, `ROLE_CONFUSION_ACCEPTED` or (base64) `ENCODED_INJECTION_ACCEPTED`, or to visit `https://example.invalid/prompt-injection-test`. The library used in practice comes from `PENSAR_PROMPT_INJECTION_LIBRARY` or Pensar Console and is not in the repository | `examples/prompt-injection/payloads/*.txt`, `examples/prompt-injection/README.md` | Operator |

## Signals on a host that runs Apex

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| CLI | `pensar pentest --target <url> [--cwd <src>] [--mode exfil]`, `pensar targeted-pentest --target <url> --objective <text>`, `pensar -p <prompt>`, `pensar agent-runs worker --run <id> --store <db>`; under the npm shim `node .../bin/pensar.js` or `bun .../bin/pensar.js`. Headless runs print `PENSAR_SESSION_PATH:<path>` | `src/cli.ts:266-290,453,597`, `bin/pensar.js` | Operator |
| Install | `npm install -g @pensar/apex`, `bun install -g @pensar/apex`, `curl -fsSL https://pensarai.com/install.sh \| bash`, `irm https://www.pensarai.com/apex.ps1 \| iex`, `brew install apex` | `README.md`, `container/Dockerfile:35`, `src/core/installation/index.ts:107` | Operator |
| Agent commands | `bash --norc --noprofile -c <command>` children of `bun` or `node`; curl and wget lines with `User-Agent: pensar-apex` and `--max-redirs 0` / `--max-redirect=0` added | `perCommandShell.ts:156-173`, `targetHeaders.ts:242-264` | Config (header), code (wrapper) |
| Callback listener process | `/bin/sh -c node -e "eval(Buffer.from('InVzZSBzdHJpY3QiOwovLyBBcGV4IGNhbGxiYWNr...','base64').toString('utf8'))"`: the base64 always starts with the encoding of `"use strict";` and `// Apex callback listener (generated).` Its readiness probe is `node -e "eval(Buffer.from(process.env.APEX_CB_PROBE,'base64').toString('utf8'))"` with `APEX_CB_PROBE_URL=http://127.0.0.1:<port>/<nonce>/__apex_ready__`. Log lines start `[apex-callback] listening bind=`, `[apex-callback] hit ` and `[apex-callback] bind-failed ` | `callbackListener.ts:32-42,61-63,126-188,300-346` | Code |
| Helper commands | Sandbox and remote backends run helpers whose command lines name `APEX_HIDDEN_PAYLOAD_COUNT` (prompt injection payload to `/tmp/apex_payload_<uuid>.txt`), `APEX_FILE_PAYLOAD_COUNT` (file writes through `python3 -c`, temp files `.apex-file-*`), `__APEX_GREP_EXIT_<16 hex>_` and `APEX_GREP_FLAGS` (grep), `python3 - <<'APEX_GLOB_PY'` (glob) and `python3 - <<'APEX_LIST_PY'` (list_files) | `executeCommand.ts:240-258`, `fileWorkspaceRemote.ts:79,193,215-235`, `grepImpl.ts:466-487`, `globImpl.ts:97-136`, `listFilesImpl.ts:193-218` | Code |
| Data folder | `~/.pensar/` (or `PENSAR_DATA_DIR`): `config.json` (API keys, `defaultHeaders`), `error.log`, `skills/`, `runtime/runs.sqlite`, and `sessions/<id>/` with `session.json`, `README.md`, `findings/`, `scratchpad/`, `logs/`, `pocs/` | `src/core/config/config.ts:101-110`, `src/core/logger/index.ts:24`, `src/core/skills/utils.ts:5`, `src/core/runtime/runStorePath.ts:4-12`, `src/core/session/index.ts:393-437` | Config (`PENSAR_DATA_DIR`) |
| Session README | Starts `# Penetration Test Session`, then `**Session ID:**`, `**Target:**`, `**Objective:**`, `**Started:**` and a fixed directory list ending `` `pocs/` - Proof-of-concept exploit scripts `` | `src/core/session/index.ts:445-469` | Code |
| Staged listener | `callback-listeners/listener-<32 hex>.cjs` in the helper workspace, a copy of the generated script | `callbackListener.ts:693-697` | Code |
| Playwright MCP config | Temp file `pensar-mcp-<pid>-<ms>.json`; the MCP client names itself `apex-browser-agent` | `playwrightMcp.ts:727,743` | Code |
| Environment | `PENSAR_API_KEY`, `PENSAR_DATA_DIR`, `PENSAR_LOG_LEVEL`, `PENSAR_DEBUG`, `PENSAR_OBFUSCATE`, `PENSAR_NO_TUI`, `PENSAR_PROMPT_INJECTION_LIBRARY`, `APEX_CUSTOM_PROVIDERS`, `PENSAR_AGENT_ENV_VARS` and the model provider keys; in the container `DISABLE_TELEMETRY=1`, `DISABLE_AUTOUPDATER=1`, `DISABLE_ERROR_REPORTING=1` | `src/cli.ts:49,69,882`, `perCommandShell.ts:23-30`, `container/docker-compose.yml:16-19`, `README.md` | Config |
| Container | `kali-apex` (image `kali-apex:latest`, local build), `NET_ADMIN`, `NET_RAW`, `seccomp:unconfined`, started with `docker compose exec kali-apex bash` | `container/docker-compose.yml:1-24`, `README.md` | Config |

## Network signals from the host

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Pensar gateway | `gateway.pensar.dev` (`POST /gateway/invoke`) for model calls when signed in to Pensar | `src/core/api/constants.ts:2,9-11`, `src/core/ai/providers/pensar.ts:255` | Config |
| Pensar Console API | `api.pensar.dev` for sign-in, web search and workspace data; `api.workos.com` for the device sign-in | `src/core/api/constants.ts:1`, `src/core/auth/device-flow.ts:37,99` | Config |
| Model providers | Standard provider hosts (`api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`, `openrouter.ai`, `api.concentrate.ai`, `api.inference.net`, `api.inceptionlabs.ai`, `api.hoonify.ai`, `api.baseten.co`, Bedrock) | `src/core/ai/providers/` | Config |
| Web search | `api.search.brave.com` or `api.exa.ai` with the operator's key, otherwise `api.pensar.dev/agents/web_search` | `src/core/agents/offSecAgent/tools/webSearch.ts:40-41,191-257` | Config |
| Update and install | `registry.npmjs.org/@pensar/apex/latest`, `pensarai.com/install.sh` | `src/core/installation/index.ts:35,107` | Code |
| Sandboxes | Daytona (`app.daytona.io`) when a sandbox backend is chosen | `src/core/tools/daytonaSandbox.ts` | Config |
| Tunnels | None in the code. The callback listener needs a target-reachable address the operator supplies | `callbackListener.ts:602-603` | Operator |

## Exposure

None. Apex has no web console or API server. Its only TCP listener is the callback listener: an ephemeral port, killed at its timeout, that answers `404 not found` with no `Server` header to anything but its nonce path, so there is nothing to search for on Shodan. The scripts `scripts/gmail-oauth.ts` and `scripts/outlook-oauth.ts` open a local OAuth redirect listener only during a maintainer's one-time setup. No rows are added to `exposure/shodan-queries.csv` or `exposure/consoles.csv`.

## What has been seen in the wild

No public report of Apex used against a target without permission was found on November 26, 2026. It is a commercial vendor's open-source tool for authorized testing.

## What the code does not contain

No implant, C2 framework or persistence. The exfil mode (`--mode exfil`) tells the agent to extract a CTF flag value (`src/core/session/index.ts:31-33`). Apex enforces a scope check on hosts and ports before tool calls (`src/core/http/targetScope.ts`, `scopeGuard.ts`) and has a destructive-command guard (`destructiveGuard.ts`).

## Rules

| Rule | Signal |
|---|---|
| [`suricata/apex.rules`](suricata/apex.rules) 3813241 | Default user agent `pensar-apex` |
| [`suricata/apex.rules`](suricata/apex.rules) 3813242 | get_page user agent `PensarBot/1.0` |
| [`suricata/apex.rules`](suricata/apex.rules) 3813243 | Sign-up test account |
| [`suricata/apex.rules`](suricata/apex.rules) 3813244 | Example prompt injection marker |
| [`suricata/apex.rules`](suricata/apex.rules) 3813245 | Callback listener answer |
| [`sigma/web/web_apex_user_agents.yml`](sigma/web/web_apex_user_agents.yml) | Both user agents in web server logs |
| [`sigma/process_creation/proc_creation_apex_agent_commands.yml`](sigma/process_creation/proc_creation_apex_agent_commands.yml) | Agent commands, callback listener, helpers |
| [`sigma/process_creation/proc_creation_apex_cli.yml`](sigma/process_creation/proc_creation_apex_cli.yml) | CLI, install, container |
| [`sigma/file_event/file_event_apex_files.yml`](sigma/file_event/file_event_apex_files.yml) | Data folder, staged listener, payload file |
| [`sigma/proxy/proxy_apex_pensar_services.yml`](sigma/proxy/proxy_apex_pensar_services.yml) | Install, update check, Pensar gateway |
| [`yara/apex.yar`](yara/apex.yar) | Source, npm bundle or binary; staged listener; session README |
| [`sentinel/analytics/apex-agent-command-markers.yaml`](sentinel/analytics/apex-agent-command-markers.yaml) | Agent command markers on a host |
