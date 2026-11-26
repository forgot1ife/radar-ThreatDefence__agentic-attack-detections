# What numasec leaves behind

numasec ([FrancescoStabile/numasec](https://github.com/FrancescoStabile/numasec), npm `numasec`, AGPL-3.0-or-later, repository created February 2, 2026, reviewed at `1237a2f` (`1237a2f3515aebbd5260383c7088aa0ea806b600`, May 8, 2026, release v1.2.1), about 850 stars and 105 forks on November 26, 2026) is a terminal AI agent for application security and penetration testing. It drives the tools already installed on the tester's machine (nmap, sqlmap, nuclei, ffuf and the rest through its `bash` tool) and adds its own built-in scanners, an AppSec probe, a browser, an out-of-band helper, a vulnerability-intelligence broker and an operation store for findings, evidence and reports. File references are to the repository at `1237a2f`; paths under `src/` are `packages/numasec/src/`.

**Built on OpenCode.** The TypeScript code base is OpenCode (the open-source coding agent) renamed to numasec, with security tools, agents and the operation kernel added. The evidence is in the repository itself: a commit titled "fix: opencode branding" that replaces the OpenCode brand in the TUI footer (`030fc0b`, April 20, 2026); dependencies on `@opencode-ai/plugin`, `opencode-gitlab-auth` and `opencode-poe-auth` (`packages/numasec/package.json:129,183-184`, `src/plugin/plugin.ts:16-17,54`); a patch file whose paths still read `anomalyco/opencode` (`patches/solid-js@1.9.10.patch:1`); tests that expect a repository `sst/numasec` (`packages/numasec/test/cli/github-remote.test.ts:5`); and OpenCode's hosts renamed mechanically (`opencode.ai` became `numasec.ai`, `api.opencode.ai` became `api.numasec.ai`, `x-opencode-directory` became `x-numasec-directory`). The repository does not say it is a fork. The earliest commits (February 2026, "v3.0.0") were a different, Python code base; the TypeScript code arrived with the "v5.0.0 rewrite" in April 2026.

So two kinds of signal exist, and the tables below keep them apart:

- **numasec-specific**: strings that only numasec's own additions contain (its probes, scanners, markers, user agents, operation files).
- **Inherited from OpenCode, renamed**: the HTTP server, its routes, the client header, the data folders and environment variables. Their names say numasec, so they still identify it, but their shape (port 4096, Hono, the Basic-auth realm, the `/path` and `/agent` routes) is the same as stock OpenCode and as other OpenCode forks in this repository (CyberStrike, DarkMoon). A query that matches only the shape finds all of them.

**Fragility** says what it takes to remove a signal: *code* means editing numasec, *config* means an option, environment variable or config file, *operator* means a choice the person running it makes, *code (prompt)* means text the model is told to use and may vary.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Install | `npm install -g numasec` or `bun add -g numasec`; the `numasec` package is a Node launcher (`bin/numasec`) that runs a Bun-compiled binary from the platform package `numasec-<os>-<arch>[-baseline][-musl]` (`numasec-linux-x64`, `numasec-darwin-arm64`, `numasec-windows-x64` and so on, binary `numasec` or `numasec.exe`). `NUMASEC_BIN_PATH` overrides the binary | `README.md:256-264`, `packages/numasec/bin/numasec:20-23,53-54,151-178` |
| Container | `docker run -it --rm -v "$PWD:/work" -w /work francescostabile/numasec:latest`: Alpine with Chromium, entrypoint `numasec`. The image is pushed by the release workflow to `<DOCKERHUB_USERNAME>/numasec`; the Docker Hub repository `francescostabile/numasec` did not answer the public API on November 26, 2026, so its name is unverified | `README.md:270`, `packages/numasec/Dockerfile:1-21`, `.github/workflows/release.yml:295-325` |
| CLI | `numasec` (TUI), `numasec run`, `numasec serve`, `numasec acp`, `numasec attach <url>`, `numasec operation`, `numasec replay`, `numasec export`, `numasec mcp`, `numasec upgrade`. In the TUI: `/pwn <target>`, `/runbook run appsec-web-triage <target>`, `/runbook run web-surface <target>`, `/mode pentest` | `src/index.ts:67,151-172`, `README.md:235-249` |
| Agents | `security`, `pentest`, `appsec`, `osint`, `hacking` plus OpenCode's `plan`, `general`, `explore`. The `security` prompt tells the model to "Assume the operator has authorization" and to refuse only what the provider refuses | `src/agent/agent.ts:125-221`, `src/agent/prompt/security.txt:64-65` |
| Tools | `bash`, `http_request`, `browser` (Playwright Chromium), `scanner` (crawl, js, dir-fuzz, ports, service), `appsec_probe`, `interact` (out-of-band), `knowledge`/`cve`, `net` (raw TCP/UDP), `vault`, `identity`, `evidence`, `finding`, `report`, `share`, `runbook` | `src/tool/`, `README.md:291-296` |
| Models | Any provider the AI SDK reaches (OpenAI, Anthropic, Google, xAI, Bedrock, OpenRouter, Ollama, Copilot, Codex login, OpenAI-compatible). No default provider of its own is hard-coded; the model list comes from `https://models.dev/api.json` | `src/provider/provider.ts`, `src/provider/models.ts:110-127` |
| Server | `numasec serve` (and `numasec acp`) starts the Hono HTTP API. Default host `127.0.0.1`, port 0 meaning "try 4096, else a random port". `--mdns` changes the default host to `0.0.0.0` and publishes `numasec-<port>` on `numasec.local`. The TUI runs its server in a worker with no listener unless `--port`, `--hostname` or `--mdns` is given | `src/cli/network.ts:5-31,52-56`, `src/server/adapter.bun.ts:24`, `src/server/adapter.node.ts:33`, `src/server/mdns.ts:15-16`, `src/cli/cmd/tui/thread.ts:181-200`, `src/cli/cmd/acp.ts:23-26` |
| Auth | None unless `NUMASEC_SERVER_PASSWORD` is set (`serve` prints "Warning: NUMASEC_SERVER_PASSWORD is not set; server is unsecured."). With it: HTTP Basic, user `numasec` unless `NUMASEC_SERVER_USERNAME`, Hono's default realm, and `?auth_token=<base64 user:pass>` also accepted. An open server gives a shell (`/pty`), file reads and agent runs to anyone who reaches it | `src/cli/cmd/serve.ts:11-16`, `src/server/middleware.ts:39-50`, `src/server/instance/index.ts:37-42` |
| Telemetry | None by default. OpenTelemetry export only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set | `src/effect/observability.ts:8` |

## Signals on the target side

These are what a web server, WAF or IDS in front of the tested application sees. All are numasec-specific (OpenCode has no scanners).

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| AppSec probe user agent | `User-Agent: numasec-appsec-probe/1.2` with `Accept: application/json,text/html,*/*` on every request of the `appsec_probe` tool, which the `appsec-web-triage` runbook runs | `src/tool/appsec-probe.ts:216-221`, `src/core/play/data/appsec-web-triage.ts:58-66` | Code |
| SQL injection probe | The first text field of an observed form, or the first query parameter of an observed search route, set to `' OR 1=1--` (GET query or JSON body) | `src/tool/appsec-probe.ts:331,353,369` | Code |
| XSS marker | The same field set to `<script>numasec-xss</script>`; the tool then looks for `numasec-xss` in the answer | `src/tool/appsec-probe.ts:333,361,370,478` | Code |
| Login probe | A JSON POST to an observed login form with the identity field `numasec-probe@example.invalid` and the password `numasec-probe` | `src/tool/appsec-probe.ts:394-404` | Code |
| CORS probe | `Origin: https://evil.example` on the first observed route | `src/tool/appsec-probe.ts:16,433-441` | Code |
| IDOR probe | An observed object route with its numeric id replaced by `1` | `src/tool/appsec-probe.ts:409-428` | Code |
| Directory fuzzer baseline | `GET /numasec_404_check_<epoch milliseconds>` before every dir-fuzz run, to learn what not found looks like | `src/scanner/dir-fuzzer.ts:122-123` | Code |
| Directory fuzzer wordlist | About 150 built-in paths, including OWASP Juice Shop routes (`api/Challenges`, `api/SecurityAnswers`, `rest/saveLoginIp`, `rest/deluxe-membership`, `rest/memories`, `encryptionkeys`, `support/logs`), 10 requests at a time. The `web-surface` and `api-surface` runbooks pass the literal words `common` (and `api`) as the wordlist, so they request `/common`, `/common.php`, `/common.txt`, `/common.js` (and `/api`, `/api.php` and so on) | `src/scanner/dir-fuzzer.ts:20-74,107`, `src/core/play/data/web-surface.ts:62-63`, `src/core/play/data/api-surface.ts:54` | Code |
| Crawler | Fetches `/robots.txt`, `/sitemap.xml`, then `/openapi.json`, `/swagger.json`, `/api-docs`, `/v2/api-docs`, `/v3/api-docs` | `src/scanner/crawl.ts:105,121,135` | Code |
| Runtime user agent of the scanners | The crawler, JS analyser and dir fuzzer call `fetch()` with no user agent, so requests carry the runtime default. The published binaries are compiled with Bun, whose default is `Bun/<version>` (Bun 1.3.11 or later). This is Bun behavior, not a string in the numasec code | `src/scanner/crawl.ts:151`, `src/scanner/dir-fuzzer.ts:80`, `packages/numasec/script/build.ts:212-218`, `packages/numasec/package.json` (`engines.bun >=1.3.11`) | Code |
| Service prober | On a port that sends no banner within 2 seconds it writes the raw bytes `GET / HTTP/1.1\r\nHost: target\r\n\r\n`: a request with only a `Host: target` header and no user agent | `src/scanner/service-prober.ts:24-25,76-84` | Code |
| Port scanner | TCP connects to a fixed list of 39 ports (21, 22, 23, 25, 53, 80, ... 3000, 3001, 4000, 5000, 5173, ... 9200, 9300, 11211, 27017), 50 at a time | `src/scanner/port-scanner.ts:25-29,97` | Code |
| Browser | Playwright Chromium (headless, `--headless=new` on some paths) with `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36` and `ignoreHTTPSErrors`. A real Chrome 143 sends the same string: context only | `src/tool/browser.ts:173-177,219-223` | Code |
| Page fetch | The `webfetch` tool sends the same Chrome 143 string; if Cloudflare answers 403 with `cf-mitigated: challenge` it retries with the user agent `numasec` | `src/tool/webfetch.ts:80-101` | Code |
| Out-of-band | `interact` starts `interactsh-client`, so payloads make the target look up `<id>.oast.live/.fun/.me/.site/.pro/.online`; without it the tool hands out `https://webhook.site/#!/<token>?id=int_<hex>` | `src/tool/interact.ts:51-82` | Operator (tool installed) |
| Model-driven commands | nmap, sqlmap, nuclei, ffuf, hydra, impacket, testssl and others through `bash`, with whatever flags the model picks | `src/agent/prompt/pentest.txt:26`, `src/agent/prompt/hacking.txt:21` | Code (prompt) |

## Signals on a host that runs numasec

| Signal | What it looks like | Code | Fragility | Origin |
|---|---|---|---|---|
| Process | `numasec` / `numasec.exe` from `node_modules/numasec-<os>-<arch>/bin/`, started by the `bin/numasec` Node launcher; `numasec serve`, `numasec acp`, `numasec attach http://...` | `packages/numasec/bin/numasec:151-178` | Code | numasec packaging, OpenCode layout |
| Server on all interfaces | `numasec serve --hostname 0.0.0.0`, `--mdns`, or the same flags on the TUI | `src/cli/network.ts:11-19,52-56` | Operator | OpenCode |
| Child environment | Every command the agent runs inherits `AGENT=1`, `NUMASEC=1` and `NUMASEC_PID=<pid>`; PTY shells also `NUMASEC_TERMINAL=1` | `src/index.ts:103-105`, `src/pty/service.ts:190` | Code | OpenCode (renamed from `OPENCODE=1`) |
| Out-of-band helper | `interactsh-client -json -o <data>/numasec/log/int_<12 hex>.jsonl -v`, with its sessions in `<state>/numasec/interact-sessions.json` | `src/tool/interact.ts:31,47-54` | Code | numasec |
| Operation folder | `<workspace>/.numasec/operation/<slug>/` with `.activity.json`, `cyber/ledger.jsonl`, `cyber/facts.jsonl`, `cyber/relations.jsonl`, `evidence/manifest.jsonl` and `evidence/<sha256>.<ext>`, `context/active-context.md` (starts `# Active Operation Context`), `workflow/`, `deliverable/.../report.md`, `report.json`, `manifest.json`, `manifest.sha256`; `share-<stamp>/` and `share-<stamp>.tar.gz` from `/share` (made with `tar -czf`; the bundle holds a derived `numasec.md` notebook) | `src/core/operation/operation.ts:34-170,367-398,422-439`, `src/core/evidence/store.ts:17-21`, `src/core/deliverable/build.ts:466-590`, `src/tool/share.ts:133-134,190` | Code | numasec |
| Replay export | `.numasec` files, JSON lines starting `{"type":"header","format":"numasec/1",...,"numasec_version":"..."}` | `src/core/replay/format.ts:7,139-151`, `docs/NUMASEC_FILE_FORMAT.md` | Code | numasec |
| Data folders | `~/.local/share/numasec/` (`numasec.db`, `log/<ISO time>.log`, which records the command-line arguments), `~/.config/numasec/` (`vault.json` credential store, `numasec.json`), `~/.local/state/numasec/`, `~/.cache/numasec/` (`models.json`, `bin/`); a project config in `<workspace>/.numasec/` | `src/global/global.ts:8-26`, `src/storage/db.ts:30-35`, `src/util/log.ts:64-66`, `src/index.ts:107-112`, `src/core/vault.ts:28` | Code | OpenCode layout, renamed |
| Environment variables | `NUMASEC_SERVER_PASSWORD`, `NUMASEC_SERVER_USERNAME`, `NUMASEC_CHROMIUM_PATH`, `NUMASEC_DISABLE_AUTOUPDATE`, `NUMASEC_MODELS_URL`, `NUMASEC_CONFIG` and some 60 more | `src/flag/flag.ts`, `src/tool/browser.ts:213` | Code | Mostly OpenCode, renamed |
| Listening port | 4096 (or random) on `127.0.0.1` by default | `src/server/adapter.bun.ts:24` | Config | OpenCode |

## Network signals from the host

| Signal | What it looks like | Code | Fragility | Origin |
|---|---|---|---|---|
| Model list | `GET https://models.dev/api.json` with `User-Agent: numasec/<channel>/<version>/<client>` (for example `numasec/latest/1.2.1/cli`), every 5 minutes at most | `src/provider/models.ts:22,110-127`, `src/installation/installation.ts:57`, `src/flag/flag.ts:153-158` | Config (`NUMASEC_DISABLE_MODELS_FETCH`, `NUMASEC_MODELS_URL`) | OpenCode (renamed UA) |
| Model calls | Every provider except the `numasec*` ones gets `User-Agent: numasec/<version>` and `x-session-affinity: <session id>`; OpenRouter, Vercel and ZenMux also get `HTTP-Referer: https://numasec.ai/` and `X-Title: numasec` | `src/session/llm.ts:358-373`, `src/provider/provider.ts:404-423,512-520` | Code | OpenCode (renamed) |
| Vulnerability intelligence | `User-Agent: numasec-knowledge-broker/1.2` to `services.nvd.nist.gov`, `www.cisa.gov` (KEV feed), `api.first.org` (EPSS), `api.osv.dev`, `api.github.com/advisories` | `src/core/knowledge/broker.ts:39,144-150,308-317,337,350,412,433` | Code | numasec |
| Update check | One second after the TUI starts: `registry.npmjs.org/numasec/latest` (npm, bun, pnpm installs), `formulae.brew.sh/api/formula/numasec.json`, Chocolatey, Scoop, or `https://api.github.com/repos/FrancescoStabile/numasec/releases/latest` otherwise. Patch releases install themselves unless `autoupdate` is off. For the `curl` install method the upgrade pipes `https://numasec.ai/install` into `bash` (an OpenCode path renamed; nothing in the repository shows who controls numasec.ai, and it was not contacted for this review) | `src/cli/cmd/tui/thread.ts:202-204`, `src/cli/upgrade.ts:8-33`, `src/installation/installation.ts:143-160,198-256` | Config (`NUMASEC_DISABLE_AUTOUPDATE`) | OpenCode (renamed) |
| Web search | `https://mcp.exa.ai/mcp`, only with `NUMASEC_ENABLE_EXA` or an experimental flag | `src/tool/mcp-exa.ts:4`, `src/tool/registry.ts:389` | Config | OpenCode |
| mDNS | With `--mdns`: an mDNS service `numasec-<port>` of type `_http._tcp` on host `numasec.local` | `src/server/mdns.ts:15-24` | Operator | OpenCode (renamed) |
| Login callbacks | Codex (ChatGPT) login on port 1455 `/auth/callback`, MCP OAuth callback server, both only while logging in | `src/plugin/codex.ts:15`, `src/mcp/oauth-callback.ts:9` | Operator | OpenCode |

## An exposed numasec server

numasec has no web console. OpenCode's build step that embeds a web UI (`packages/app`) is still in the build script, but that package is not in the repository and the script sets `embeddedFileMap = null`, so the binaries embed nothing (`packages/numasec/script/build.ts:58-62,81,222`). What can be exposed is the HTTP API of `numasec serve`, `numasec acp` or a TUI started with `--hostname`/`--mdns`.

- `GET /` has no route: Hono answers `404 Not Found` in plain text. There is no title, favicon or `Server` header, so nothing on `/` identifies numasec.
- `GET /path` answers `{"home":"...","state":"<home>/.local/state/numasec","config":"<home>/.config/numasec","worktree":"...","directory":"..."}` (`src/server/instance/index.ts:128-165`). The folder names are numasec's; stock OpenCode answers the same shape with `opencode`.
- `GET /agent` lists the agents, including `"description":"Penetration testing specialist. Systematic recon, enumeration, exploitation, and reporting."` and the full system prompts (`src/server/instance/index.ts:254-275`, `src/agent/agent.ts:143-147`). This is numasec-specific.
- A client (`numasec attach`, `numasec run --attach`, the SDK) sends `x-numasec-directory` on POSTs and `?directory=` on GETs (`packages/sdk/src/v2/client.ts:16-43,59-64`, `src/server/instance/middleware.ts:21`).
- `/global/health` (`{"healthy":true,"version":...}`) is defined in `src/server/instance/global.ts:73-95` but not mounted at `1237a2f`, so it answers 404.
- With a password, every route answers 401 with `WWW-Authenticate: Basic realm="Secure Area"`, Hono's default and shared with OpenCode and any other Hono server (`src/server/middleware.ts:49`).
- The browser CORS allow list is localhost, 127.0.0.1, Tauri, `https://*.numasec.ai` and `--cors` origins (`src/server/middleware.ts:68-82`).

Internet scanners index `/`, so a numasec server is close to invisible to them. The Shodan rows for this folder are low confidence and say so.

## What the code does not contain

numasec ships no implant, C2, persistence or credential theft. The operation folders, replay files and share bundles stay on the operator's disk. It has no telemetry of its own. No vendor or CERT report of numasec used in an intrusion was found on November 26, 2026.
