# What Vigilo leaves behind

Vigilo ([certeu/vigilo](https://github.com/certeu/vigilo); published by CERT-EU; repository created July 9, 2026; EUPL-1.2; 78 stars and 20 forks on November 26, 2026; not archived; one release, `v1.0.0`, which is the reviewed commit; reviewed at `82c2d353` (`82c2d353abe6b6e639a958a3e719a8efb9f43ff3`), November 25, 2026) is a multi-user platform for AI-driven security assessment of applications the operator is responsible for. It has two modes. **White-box**: coding agent CLIs (Claude Code, Codex CLI or OpenCode) review a repository, prove findings against a running copy of the application and write fix branches. **Grey-box**: one reasoning agent calls a model API directly and assesses a running web application, API or network segment only through Vigilo's own scope-checked tools, without the source. Languages: Python (FastAPI API, Temporal worker, grey-box worker) and TypeScript (React UI). The visible history starts on November 18, 2026 with 13 commits, so earlier history was not published.

Vigilo is a defensive tool, and its grey-box traffic is built to be recognised: every request carries a fixed user agent that says it is an authorised test, its payloads are inert markers under `.invalid` or with a `vgl`/`vigilo` prefix, and each finding it reports includes "detection hints" that tell the application owner how to spot these requests (`src/greybox_web/tools/injection.py:124-153`, `src/greybox_web/tools/exposure.py:104-129`). This folder documents those markers so that a SOC can tell an agreed Vigilo assessment from other traffic, and can see when a Vigilo instance is exposed.

File references are to the repository at `82c2d353`.

**Fragility** says what it takes to remove a signal: *code* means editing Vigilo, *config* means an environment variable or setting, *operator* means a choice made at run time. *Code (prompt)* marks a string the code hands to the model as an instruction: removing it means editing Vigilo, but the model may change it on any run.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Platform | Docker Compose. `deploy/docker-compose.full.yml`: Traefik `v3.7.8` (the only service that publishes ports, 80 and 443, routing on `Host(${VIGILO_HOSTNAME:-vigilo.example.com})`), `postgres:16`, `mailhog/mailhog`, `temporalio/temporal:1.5.0`, `worker` (white-box), `api`, `greybox-worker` and `ui`. `docker-compose.plain.yml` turns Traefik off and publishes the UI's nginx on `${VIGILO_HTTP_PORT:-8080}`. `docker-compose.api.yml` runs `vigilo-api` with `ports: ["8080:8080"]` and an optional `greybox-worker` | `deploy/docker-compose.full.yml:52-79,86,102-112,133-177,258-333`, `deploy/docker-compose.plain.yml:25-34`, `deploy/docker-compose.api.yml:11-87` |
| Images | Built locally, not published to a registry: `vigilo-worker:latest` (Wolfi base, white-box tools) and `vigilo-api:latest` (`python:3.13-slim`, shared by the API and the grey-box worker). The UI image is `nginx:1.27-alpine` with the built SPA. The PyPI name `vigilo` belongs to an unrelated project | `Dockerfile:10,48`, `deploy/Dockerfile.api:1,24-25`, `deploy/docker-compose.api.yml:37,48`, `deploy/docker-compose.full.yml:137,177,263`, `web/Dockerfile:9` |
| API | FastAPI app `Vigilo Platform API`, served by uvicorn on `0.0.0.0:8080` (public) and an internal listener on `0.0.0.0:8081` for per-run secret redemption (not published, not proxied). `/docs`, `/redoc` and `/openapi.json` exist only in dev mode or with `VIGILO_API_DOCS_ENABLED=true`. `GET /` answers FastAPI's 404 | `src/webapi/main.py:21-26`, `src/webapi/settings.py:24-25,44-45,70-72`, `src/webapi/app.py:88-94` |
| UI | React SPA behind nginx on port 80 in the container. nginx proxies `/api/` to `http://api:8080/`. Title `Vigilo`; no favicon | `web/nginx.conf:3-69`, `web/index.html:6` |
| Login | JWT bearer login (fastapi-users) at `POST /auth/jwt/login` (`/api/auth/jwt/login` through the UI); the browser keeps the token in `localStorage` under `vigilo_token`. No default account: the first admin is created only from `VIGILO_FIRST_ADMIN_EMAIL` and `VIGILO_FIRST_ADMIN_PASSWORD` (the sample file shows the placeholder `change-me-now`). The API refuses to start with the default JWT secret `CHANGE_ME` outside dev mode | `src/webapi/app.py:81-84,109-114`, `src/webapi/auth/backend.py:22`, `src/webapi/bootstrap.py:12-23`, `env.sample:93-94`, `web/src/api/client.ts:4-11` |
| White-box worker | `python3 -m src.temporal.worker --serve --task-queue vigilo-pipeline` (Temporal engine) or one container per run, `python -m src.temporal.worker --serve --task-queue vigilo-<12 hex> --exit-with-workflow <session>`, labelled `vigilo.run_id` (docker engine). It also has a stand-alone CLI form `python -m src.temporal.worker /repos/target --url <target> --session-id <id> --stages full`. Runs as user `scanner` (uid 1001) with `HOME=/tmp`, the repository mounted at `/repos/target` | `deploy/docker-compose.full.yml:169`, `src/webapi/engine/docker_temporal.py:102-118`, `src/temporal/worker.py:62-73`, `Dockerfile:123-148` |
| White-box agents | `claude -p <prompt> --model <m> --max-turns <n> --output-format stream-json --verbose --dangerously-skip-permissions`, or `codex exec --model <m> --json --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox <prompt>`, or `opencode run --model <m> --format json --dangerously-skip-permissions --dir <cwd>`, chosen by `VIGILO_EXECUTOR` (default `claude`). The environment carries `VIGILO_AGENT=<agent name>`; platform secrets (`VIGILO_SECRET*`, `VIGILO_JWT*`, `VIGILO_FERNET*` and others) are stripped | `src/ai/claude_executor.py:170-182`, `src/ai/codex_executor.py:196-202`, `src/ai/opencode_executor.py:117-123`, `src/ai/executor.py:173,215`, `src/ai/envguard.py:16-25` |
| White-box tools | Claude Code, Codex CLI `0.142.5`, Playwright CLI `0.1.1` (with its skill copied to `/tmp/.claude/skills` and `/tmp/.codex/skills`), Chromium, `subfinder` `v2.13.0`, WhatWeb `0.6.3`, `schemathesis` `4.13.0`, curl, git. Helper commands `vigilo-record`, `save-deliverable`, `generate-totp`, `config-codex` in `/usr/local/bin`. Git commits made in the worker use `Vigilo Agent <agent@localhost>` | `Dockerfile:25,28-34,45,71-82,108-120` |
| Grey-box worker | `python -m src.greybox_web.worker`, with `seccomp=unconfined`, `apparmor=unconfined`, all capabilities dropped except `SETUID` and `SETGID`. Agent-written analysers run under bubblewrap (or `unshare`) in `/tmp/vigilo-tool-*` with no network. The grey-box agent calls the model API itself with httpx | `deploy/docker-compose.api.yml:44-87`, `src/greybox_web/sandbox.py:323-338,397,647`, `src/greybox_web/exploration/client.py:37-41` |
| Model | White-box: Anthropic API, AWS Bedrock or Azure Foundry through Claude Code; an OpenAI or OpenAI-compatible endpoint through Codex (`CODEX_BASE_URL`, default `https://api.openai.com/v1`); LiteLLM through OpenCode. Grey-box: `https://api.anthropic.com` (default model `claude-sonnet-5-5` when none is set) or an OpenAI-compatible base (default `https://api.openai.com`, model `gpt-4o-mini`). Anthropic's API is genuinely part of Vigilo's default configuration | `env.sample:8-57`, `src/greybox_web/exploration/client.py:37-41`, `src/greybox_web/modelsel.py:26` |
| Scope and safety | Grey-box requests, browser requests, redirects, TCP connections and DNS lookups go through one guard that checks scope, blocks metadata and link-local addresses (private ranges only when allowed) and records every exchange. PUT, PATCH and DELETE need the operator's per-target permission. White-box agents have a shell and are not isolated per scan | `src/greybox_web/netguard.py:153-158`, `README.md:213-244` |
| Telemetry | None found. Outbound traffic is the model API, GitLab (cloning and merge requests when configured), the target and SMTP for notifications | `src/services/gitlab_mr.py`, `src/webapi/settings.py:51-58` |

## Signals on the target side: grey-box

Every grey-box request goes through `GuardedHttpClient`, which sets the user agent itself; the headless browser and agent-written analysers have no network of their own and are answered through the same client (`src/greybox_web/tools/browser.py:82-86,297-307`). So the markers below apply to everything the grey-box agent sends.

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| User agent | `Vigilo-Greybox/1 (authorised security test)` on every grey-box HTTP request, browser page loads and sub-requests included. Sent by httpx, followed by `Accept: */*` when the tool sets no `Accept` | `src/greybox_web/netguard.py:153,822-830` | Code |
| Echo header | `X-Note-Name: vigilo<8 hex><e>` (raw angle brackets) on the root fetch and on every page of the crawl | `src/greybox_web/tools/discovery.py:28-37,86-88,410-412,541-543` | Code |
| Reflection canary | `vgl<8 hex>"'<>b` in one query or form parameter; form-encoded it reads `vgl<8 hex>%22%27%3C%3Eb`. Agent-authored instruments use the same canary | `src/greybox_web/tools/injection.py:37-41,69-76,164`, `src/greybox_web/verify.py:181`, `src/greybox_web/tools/dynrun.py:86-87` | Code |
| Open redirect probe | A redirect parameter set to `https://vigilo-probe-<8 hex>.invalid/`; the host is read back from `Location` and never contacted | `src/greybox_web/tools/injection.py:44-46,258-266`, `src/greybox_web/verify.py:216` | Code |
| CORS probe | `Origin: https://vigilo-probe-<8 hex>.invalid`, then a second random one for verification | `src/greybox_web/tools/cors.py:25-26,57-58`, `src/greybox_web/verify.py:91-93` | Code |
| Soft-404 baseline | `GET /vgl-<8 hex>` at the site root before the exposure verdict | `src/greybox_web/tools/exposure.py:132-134`, `src/greybox_web/verify.py:137,158` | Code |
| Login baseline | Before every login with a test account, and before the default-credential check, one failed login with the same value `vgl<8 hex>` in both the user and the password field: form (`user=vgl…&password=vgl…`, after any hidden CSRF fields), JSON (`{"user": "vgl…", "password": "vgl…"}`), JSON-RPC `auth.login`, or the query string for a GET form. Field names default to `user` and `password` and follow the login form | `src/greybox_web/tools/auth.py:77-86,126-130,240-270,326-338`, `src/greybox_web/verify.py:260-261` | Code |
| Default credentials | `admin/admin`, `admin/password`, `admin/admin123`, `root/root`, `test/test`, only when the target allows authentication testing | `src/greybox_web/tools/auth.py:29-35` | Code |
| Sensitive paths | `/.git/HEAD`, `/.git/config`, `/.env`, `/.svn/entries`, `/.DS_Store`, `/backup.zip`, `/db.sql`, `/config.bak`, `/server-status`, `/phpinfo.php`, `/.htaccess`, `/web.config`, and directory listings of `/static/`, `/uploads/`, `/assets/`, `/backup/`, `/admin/`, `/files/`. Generic on their own | `src/greybox_web/tools/exposure.py:57-96` | Code |
| Discovery | `/robots.txt`, `/sitemap.xml`, then a bounded crawl | `src/greybox_web/tools/discovery.py:443,472` | Code |
| Callback check | A trigger parameter (default `url`) set to the operator's callback URL with `vigilo-callback-<8 hex>`, and polls of the observation URL for that token and for `vigilo-control-<8 hex>`. Both URLs must be in scope and on a loopback or private address: Vigilo has no public out-of-band service | `src/greybox_web/tools/callback.py:72-81,90-91` | Code |
| Upload | `multipart/form-data; boundary=vigilo-<8 hex>`, default file name `vigilo-<8 hex>.txt`, default content `vigilo-file-<8 hex>` | `src/greybox_web/tools/fileops.py:83,93,97-101` | Code (boundary), operator (name and content can be set) |
| GraphQL and JSON-RPC calls | GraphQL documents named `query VigiloInvoke` or `mutation VigiloInvoke`; JSON-RPC requests with `"id":"vigilo-<8 hex>"` (compact JSON) | `src/greybox_web/tools/apiops.py:141,209-210,216-217` | Code |
| Network mode | TCP banner and identification probes: `HEAD / HTTP/1.0`, `PING`, `QUIT`, `version`, `FEAT`, and SMTP `EHLO vigilo.invalid` then `QUIT` | `src/greybox_web/netcap.py:43-54` | Code |
| Proxy | Targets reachable only through a forward proxy use an admin-defined egress proxy (`VIGILO_GREYBOX_EGRESS_PROXIES_ENABLED`), never `HTTP(S)_PROXY` | `README.md:303-312`, `src/greybox_web/netguard.py:348-353` | Config |

## Signals on the target side: white-box

White-box agents test the live copy themselves with a shell and a browser, so there is no fixed marker beyond the first request.

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Preflight | `HEAD <target URL>` with `User-Agent: Vigilo-Preflight/1.0`, certificate checks off, at the start of every white-box run that has a target URL. With a cookie-based login, one more `GET` with httpx's default user agent checks the cookie | `src/temporal/activities.py:850-936` | Code |
| Agent tools | `curl`, `playwright-cli` (headless Chromium), `whatweb` (WhatWeb 0.6.3 user agent), `schemathesis` 4.13.0, `subfinder` (passive sources). No Vigilo marker; the user agents are each tool's default | `prompts/whitebox/shared/_tools.txt:5`, `prompts/shared/_tools.txt:14`, `Dockerfile:25-45` | Code (prompt) |
| Proof harnesses | Proof scripts print `VIGILO_RESULT: VULNERABLE` or `VIGILO_RESULT: NOT_VULNERABLE`; they run on the worker, not on the target | `prompts/whitebox/prover.txt:83-88` | Code (prompt) |
| Patch delivery | Fix branches `fix/<ID>` such as `fix/VG-007` or `fix/VG-007-VG-009`, pushed to GitLab with merge requests titled `Fix VG-007: <title>`, commits by `Vigilo Agent <agent@localhost>`. Only when the operator configures delivery | `prompts/remediation.txt:7,91`, `src/services/gitlab_mr.py:330-347`, `Dockerfile:118-120` | Config |

## Signals on a host that runs Vigilo

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Processes | `python -m src.webapi.main` (listening on 8080 and 8081), `python -m src.greybox_web.worker`, `python3 -m src.temporal.worker --serve --task-queue vigilo-pipeline` or `vigilo-<12 hex>`, `temporal server start-dev --db-filename /home/temporal/temporal.db --ip 0.0.0.0` | `deploy/Dockerfile.api:25`, `deploy/docker-compose.full.yml:112,169,297`, `src/webapi/engine/docker_temporal.py:102-107` | Code (module paths), config (queue name) |
| Agent CLIs | Children of the worker: `claude -p` with the prompt in the command line, which contains `This is an authorised security assessment run by Vigilo.` for every white-box agent, and `--dangerously-skip-permissions`; or `codex exec ... --dangerously-bypass-approvals-and-sandbox`, or `opencode run ... --dangerously-skip-permissions` | `prompts/whitebox/shared/_engagement.txt:2`, `src/ai/claude_executor.py:170-182` | Code (prompt) |
| Agent commands | `vigilo-record show leads`, `vigilo-record lead --file /tmp/leads.json`, `vigilo-record verdict --file /tmp/VG-004.verdict.json --evidence-file /tmp/VG-004.md`, `save-deliverable --type <TYPE> --file-path <path>`, `playwright-cli -s=<session>` | `prompts/whitebox/shared/_ledger.txt:9-14,59`, `prompts/whitebox/planner.txt:40`, `prompts/whitebox/shared/_tools.txt` | Code (prompt) |
| Files | `<repo>/.vigilo/<session>/` with `agents/`, `prompts/` and `deliverables/` (`code_analysis_deliverable.md`, `findings_critique.json`, `comprehensive_security_assessment_report.md`, `remediation_report.md`, `remediation_manifest.json`, `sca_findings.json`, `integrity_analysis.json`); `<repo>/.vigilo-remote-url`; `.git/vigilo-rebuild.json`, `.git/vigilo-delivery.json`, `.git/vigilo-delivery.lock`, `.git.vigilo-old`, `.git.vigilo-new`; temporary folders `vigilo-tool-*`, `vigilo-probe-*`, `vigilo-askpass-*`, `vigilo-rebuild-*`, `vigilo-push-*`. `comprehensive_security_assessment_report.md` is also the report name Shannon uses, so do not attribute on it alone | `src/audit/session.py:32,69-72`, `src/types/deliverables.py:38-44`, `src/services/git_manager.py:333-337`, `src/services/git_push.py:106-110,156,307-309,718`, `src/greybox_web/sandbox.py:397,647` | Code |
| Data | Default SQLite `vigilo_platform.db` outside Docker; Postgres database and user `vigilo`; volumes `vigilo_pg`, `vigilo_jobs` (`/data/jobs`), `vigilo_uploads`, `temporal_data`, `acme_data`; network `vigilo_net` | `src/webapi/settings.py:15,33-37`, `deploy/docker-compose.full.yml:345-352` | Config |
| Environment | `VIGILO_EXECUTOR`, `VIGILO_AGENT`, `VIGILO_DOCKER=true`, `VIGILO_GREYBOX_WEB_ENABLED`, `VIGILO_GREYBOX_SANDBOX_ISOLATION`, `VIGILO_INTERNAL_API_URL=http://api:8081`, `VIGILO_JWT_SECRET`, `VIGILO_FERNET_KEY` | `Dockerfile:140`, `env.sample`, `src/ai/executor.py:215` | Code |
| Local development | `scripts/greybox_local_stack.sh` keeps state in `~/.cache/vigilo-e2e`; evaluation output in `~/.cache/vigilo-e2e/eval/` | `scripts/greybox_local_stack.sh:11-14`, `scripts/greybox_eval.py:22` | Code |

## Outbound traffic from the operator host

| Destination | What it is | Code | Fragility |
|---|---|---|---|
| `api.anthropic.com`, Azure Foundry, AWS Bedrock | Model calls from Claude Code (white-box) and from the grey-box worker (httpx, `x-api-key` and `anthropic-version` headers) | `src/greybox_web/exploration/client.py:37,333`, `env.sample:11-27` | Config |
| `api.openai.com` or another OpenAI-compatible base | Codex CLI and the grey-box worker with the `codex` backend | `entrypoint.sh:54`, `src/greybox_web/modelsel.py:26` | Config |
| LiteLLM gateway (`LITELLM_BASE_URL`, example `http://litellm:4000`) | OpenCode backend | `env.sample:51-57` | Config |
| GitLab | Cloning repositories and opening merge requests | `src/services/git_manager.py`, `src/services/gitlab_mr.py` | Config |
| Let's Encrypt (or `ACME_CASERVER`) | Traefik certificates for `VIGILO_HOSTNAME` | `deploy/docker-compose.full.yml:72-76` | Config |

## An exposed Vigilo instance

| Signal | Exact value | Code | Survives a rename |
|---|---|---|---|
| UI page title | `<title>Vigilo</title>`; the login card reads `Vigilo` and `Sign in to run assessments.` (in the script bundle) | `web/index.html:6`, `web/src/pages/Login.tsx:30-31` | No |
| UI headers (nginx) | `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-cache` on the page; `Server: nginx/1.27.x` (image default, inferred) | `web/nginx.conf:61-67`, `web/Dockerfile:9` | Yes |
| Favicon | None. `/favicon.ico` falls back to the SPA page (`try_files $uri $uri/ /index.html`), so there is no favicon hash | `web/nginx.conf:67` | n/a |
| Storage key | `vigilo_token` in `localStorage`, inside the script bundle | `web/src/api/client.ts:4` | Yes, unless rebuilt |
| API headers (uvicorn) | `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and uvicorn's `server: uvicorn` (default, inferred). `Strict-Transport-Security` only with `VIGILO_HSTS_ENABLED` | `src/webapi/security_headers.py:11,36-42`, `src/webapi/main.py:23` | Yes |
| API without login | `GET /health` returns `{"status":"ok"}`; `GET /version` returns `{"version":"1.0.0"}` at this commit; `GET /` returns `{"detail":"Not Found"}`. Through the UI these are `/api/health` and `/api/version` | `src/webapi/routers/system.py:14-25`, `pyproject.toml:7` | Yes |
| API docs | Only in dev mode: `/docs` with the title `Vigilo Platform API` | `src/webapi/app.py:88-94` | No |
| Ports | API compose: `8080` on all interfaces. Plain override: UI on `${VIGILO_HTTP_PORT:-8080}` (the file warns to bind it to `127.0.0.1` when a proxy fronts it). Full compose: only 80 and 443 through Traefik, which answers a request by IP with its generic 404 and default certificate | `deploy/docker-compose.api.yml:38`, `deploy/docker-compose.plain.yml:19-32`, `deploy/docker-compose.full.yml:77-79,328` | Config |
| Login | `POST /auth/jwt/login`, form fields `username` and `password` (fastapi-users), rate-limited after failures | `src/webapi/app.py:96-114` | Yes |

An exposed Vigilo UI needs a login before it shows data, and there is no default account. The task notes report one Shodan host for `http.title:"Vigilo" "frame-ancestors 'none'"`; the count was not re-run for this review. `Vigilo` is a short common word, so the title alone matches other sites; the nginx CSP narrows it. A Vigilo API published by the API compose file serves no HTML, so it can only be found by its headers.

## Signals in model traffic

Where model traffic is inspected, white-box prompts contain `This is an authorised security assessment run by Vigilo.` and the role lines `You are the surveyor: a principal security engineer who maps an unfamiliar application quickly and accurately.` (`prompts/whitebox/shared/_engagement.txt:2`, `prompts/whitebox/surveyor.txt:2`). The grey-box network prompt starts `You are the reasoning agent of an authorised, bounded security assessment of a NETWORK SEGMENT` (`src/greybox_web/exploration/prompts.py:118`).

## What has been seen in the wild

- No report of Vigilo used in an intrusion was found, and none is expected: it is published by CERT-EU for assessing one's own applications, and its grey-box requests name themselves as an authorised test.
- No public detection rules for Vigilo were found.

## What the code does not contain

No implant, C2, web shell, persistence or exploit payload. Grey-box payloads are inert by design: canaries, a single appended quote, `.invalid` hosts that are never contacted, and default-credential pairs only when allowed. There is no public out-of-band service: the callback check only accepts in-scope loopback or private listeners. White-box agents do have a shell and can write their own proof scripts, so what they send to the live copy is open-ended and carries no Vigilo marker after the preflight request.

## Not verified, and inferred

- Nothing was run. Header order, `server: uvicorn` and nginx's `Server` header are inferred from the libraries' defaults.
- Whether the guard could ever send a second `User-Agent` header: the code lets callers add headers other than `Host`, `Cookie`, `Authorization` and `Content-Length` (`src/greybox_web/netguard.py:828-830`), but no tool at this commit adds one.
- A forward proxy sees the grey-box user agent only for plain-HTTP targets or with TLS inspection; httpx's `CONNECT` request carries no user agent (inferred).
- The Shodan count of one host comes from the task notes, not from a query made in this review.
- The first visible commit is dated November 18, 2026, four months after the repository was created, so earlier versions were not reviewed.
