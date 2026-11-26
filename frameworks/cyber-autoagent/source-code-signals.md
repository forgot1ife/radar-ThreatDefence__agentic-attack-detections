# What Cyber-AutoAgent leaves behind

Cyber-AutoAgent ([westonbrown/Cyber-AutoAgent](https://github.com/westonbrown/Cyber-AutoAgent), first commit May 26, 2025, archived, reviewed at `54897ff9` (`54897ff91d16ed05bacfb9b96526021d7aaa3026`), November 29, 2025, release v0.1.3) is a Python agent built on the AWS Strands Agents SDK, with a React/Ink terminal front end written in TypeScript. One agent ("Ghost") drives a shell, an HTTP client, a Python REPL, a file editor, a swarm of sub-agents and tools it writes for itself, then a second agent writes a report. It has about 550 GitHub stars and 137 forks, is MIT licensed, and is no longer maintained. File references are to the repository at `54897ff9`.

There is no Docker Hub image, PyPI package or npm package: the README badge points at `cyberautoagent/cyber-autoagent` on Docker Hub, which does not exist, and the PyPI name `cyber-autoagent` and npm name `cyber-autoagent-cli` in the package files were never published (checked November 26, 2026). Operators build the image `cyber-autoagent:latest` themselves.

**Fragility** says what it takes to remove a signal: *code* means editing Cyber-AutoAgent, *code (prompt)* means a string the model is told to use, so the model may vary it, *config* means an environment variable, option or compose edit, *operator* means something the person running it chooses.

## How it runs

| Part | What it does | Code |
|---|---|---|
| CLI | `python src/cyberautoagent.py --target <t> --objective <o> [--module general\|ctf\|code_security\|context_navigator\|threat_emulation] [--iterations 100] [--provider bedrock\|ollama\|litellm] [--model ...] [--output-dir ...] [--memory-path ...] [--service-mode]`. Tool confirmations are off unless `--confirmations` is given: it sets `BYPASS_TOOL_CONSENT=true` | `src/cyberautoagent.py:257-347`, `:388-392` |
| Front end | `node /app/src/modules/interfaces/react/dist/index.js` (npm bins `cyber-react`, `cyber-native`). It starts the Python agent with `--objective via environment` and passes the real objective in `CYBER_OBJECTIVE`, with `CYBER_UI_MODE=react` | `docker/Dockerfile:244`, `src/modules/interfaces/react/package.json:7-10`, `src/modules/interfaces/react/src/services/PythonExecutionService.ts:637-669`, `DirectDockerService.ts:158-217` |
| Container | Image `cyber-autoagent:latest` built from `kalilinux/kali-rolling` with about 90 tools (nmap, sqlmap, nuclei, ffuf, feroxbuster, gobuster, nikto, hydra, metasploit-framework, katana, httpx, zaproxy, burpsuite and more). User `cyberagent` with passwordless sudo. `EXPOSE 8080`, but nothing listens on it. Ad-hoc containers run as root with `NET_RAW`, `NET_ADMIN`, `SYS_PTRACE` | `docker/Dockerfile:4`, `:21-133`, `:146-148`, `:236`, `DirectDockerService.ts:480`, `:522-539` |
| Compose stack | Container names `cyber-autoagent`, `cyber-langfuse`, `cyber-langfuse-worker`, `cyber-langfuse-postgres`, `cyber-langfuse-clickhouse`, `cyber-langfuse-redis`, `cyber-langfuse-minio`. Volume `../outputs:/app/outputs`. Networks `default` and `cyber-autoagent_default` | `docker/docker-compose.yml:7`, `:106`, `:216`, `:284`, `:300`, `:319`, `:331`, `:77`, `:82-84` |
| Models | Bedrock by default: `us.anthropic.claude-sonnet-4-5-20250929-v1:0` (Anthropic Claude on AWS Bedrock), embeddings `amazon.titan-embed-text-v2:0`. Ollama default `llama3.2:3b` on `http://localhost:11434` or `http://host.docker.internal:11434`. LiteLLM for OpenAI, Anthropic, Gemini, xAI, Cohere, Azure | `src/modules/config/manager.py:431`, `:465`, `:472`, `:500`, `:954-965`, `docker/docker-compose.yml:17-43` |
| Memory | mem0 with local FAISS by default, per target: `outputs/<target>/memory/mem0.faiss` and `mem0.pkl`. OpenSearch when `OPENSEARCH_HOST` is set, mem0 platform when `MEM0_API_KEY` is set | `src/modules/tools/memory.py:229-231`, `:376-391`, `DirectDockerService.ts:190-191` |
| Meta-tooling | The agent writes Python tools with `editor` into `outputs/<target>/OP_<timestamp>/tools/` and loads them with `load_tool`; the Strands agent is created with `load_tools_from_directory=True` | `src/modules/config/manager.py:720-748`, `src/modules/prompts/templates/tools_guide.md:54-58`, `src/modules/agents/cyber_autoagent.py:938` |
| Observability | On by default in the compose stack (`ENABLE_OBSERVABILITY=true`). Exports OpenTelemetry traces to Langfuse at `<LANGFUSE_HOST>/api/public/otel` with `Authorization=Basic base64(cyber-public:cyber-secret)` unless the keys are changed, service name `cyber-autoagent`. Fetches and seeds its prompts at `/api/public/v2/prompts/cyber/system/system_prompt` and the other `cyber/...` names | `docker/docker-compose.yml:55-61`, `src/cyberautoagent.py:180-195`, `src/modules/prompts/factory.py:41-47`, `:65-75`, `:105`, `:134` |
| Telemetry to the author | None. No update check, analytics or crash reporting was found in the Python or TypeScript code. The bundled Langfuse runs with `TELEMETRY_ENABLED: "false"` | `docker/docker-compose.yml:185` |
| Output | `outputs/<target>/OP_<YYYYMMDD_HHMMSS>/` with `cyber_operations.log`, `security_assessment_report.md`, `artifacts/`, `tools/`, `execution_prompt_optimized.txt`, `adaptive_prompt.json`; front-end config at `~/.cyber-autoagent/config.json` (stores provider keys in clear JSON) | `src/cyberautoagent.py:435-447`, `src/modules/handlers/react/react_bridge_handler.py:2793`, `src/modules/tools/prompt_optimizer.py:16`, `:401`, `src/modules/interfaces/react/src/contexts/ConfigContext.tsx:492` |

## Signals on the target side

The agent's traffic is mostly whatever stock Kali tool or `curl` the model picks, with that tool's defaults. No user agent of its own is set anywhere in the code. The fixed strings below come from the three tools of the default `general` module, which run only when the model calls them, and from the threat emulation prompt.

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Blind XSS callback | `dalfox url <url>?<param>=FUZZ -b https://dalfox-xss-test.com --mining-dict --skip-bav --silence --timeout 10` for up to 10 parameters: dalfox payloads that make a browser load `https://dalfox-xss-test.com`, sent to your site | `src/modules/operation_plugins/general/tools/advanced_payload_coordinator.py:319-330` | Code |
| XSS, SSTI, command and LDAP probes | `curl -s --max-time 10 '<url>?<param>=<script>alert(1)</script>'` (then `javascript:alert(1)`, `<img src=x onerror=alert(1)>`), `{{7*7}}`, `${7*7}`, `; whoami`, `\| whoami`, `*`, `*)(&`, all with curl's default user agent | `advanced_payload_coordinator.py:354-391`, `:528-560` | Code |
| CORS probe | `curl -s -I --max-time 10 -H 'Origin: https://evil.com'` then `Origin: null`, only when `corsy` is missing. Many scanners send the same | `advanced_payload_coordinator.py:476-488` | Code |
| Auth path sweep | `curl -s -I --max-time 5` to about 30 paths (`/login`, `/oauth/authorize`, `/saml`, `/mfa`, `/2fa`, `/reset`, ...), then `feroxbuster -u <url> -w /tmp/auth_wordlist.txt -t 20 -C 404 --silent --no-recursion` with a 14-word list, then method and `X-Originating-IP: 127.0.0.1` / `X-Forwarded-For: 127.0.0.1` bypass checks | `src/modules/operation_plugins/general/tools/auth_chain_analyzer.py:135-275`, `:887-1000` | Code |
| Recon chain | `subfinder -d <t> -silent -timeout 60`, `assetfinder --subs-only`, `waybackurls`, `curl -s https://crt.sh/?q=%.<t>&output=json`, `httpx -l <file> -title -tech-detect -status-code -silent -timeout 10`, `katana -list <file> -js-crawl -depth 2 -silent -timeout 30` | `src/modules/operation_plugins/general/tools/specialized_recon_orchestrator.py:198-337` | Code |
| Threat emulation markers | Told to leave a marker for every technique: files `.emulation_marker_<TTP_ID>`, processes `emulation_<name>`, registry keys under `HKLM\SOFTWARE\EmulationMarkers\`, accounts `emu_<username>` | `src/modules/operation_plugins/threat_emulation/execution_prompt.md:49-55` | Code (prompt) |
| CTF flag hunting | Looks for `flag{UUID}`, `FLAG{UUID}`, `@FLAG@` | `src/modules/operation_plugins/ctf/execution_prompt.md:4` | Code (prompt) |

## Signals on a host that runs Cyber-AutoAgent

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Agent command | `python /app/src/cyberautoagent.py --module general --objective via environment --target <t> --iterations 100 --provider bedrock --output-dir /app/outputs --keep-memory` from the front end; `cyberautoagent.py ... --target ... --objective ...` by hand; `cyberautoagent.py --service-mode` for the idle compose container | `DirectDockerService.ts:158-177`, `:1211`, `PythonExecutionService.ts:637-640`, `src/cyberautoagent.py:279-283` | Code (`via environment`), operator (direct runs) |
| Front end | `node .../interfaces/react/dist/index.js`, `docker images -q cyber-autoagent:latest`, `docker ps --filter "ancestor=cyber-autoagent:latest"`, `docker compose -f .../docker/docker-compose.yml up -d --no-recreate` | `ContainerManager.ts:490`, `:515`, `:547`, `HealthMonitor.ts:334` | Code |
| Tool commands | `dalfox ... -b https://dalfox-xss-test.com`, `feroxbuster ... -w /tmp/auth_wordlist.txt`, `curl ... -c /tmp/cookies.txt`, `go install github.com/hahwul/dalfox/v2@latest` when a tool is missing | `advanced_payload_coordinator.py:154-185`, `:319-330`, `auth_chain_analyzer.py:252-266`, `:569` | Code |
| Files | `outputs/<target>/OP_<timestamp>/cyber_operations.log`, `security_assessment_report.md`, `execution_prompt_optimized.txt`, `adaptive_prompt.json`, `outputs/<target>/memory/mem0.faiss`, `~/.cyber-autoagent/config.json`, `/tmp/auth_wordlist.txt` | see above | Code (names), config (`--output-dir`) |
| Stdout protocol | Every UI event is printed as `__CYBER_EVENT__{json}__CYBER_EVENT_END__` | `src/modules/config/environment.py:103` | Code |
| Environment | `CYBER_OPERATION_ID=OP_<timestamp>`, `CYBER_UI_MODE=react`, `CYBERAGENT_NO_BANNER=true`, `BYPASS_TOOL_CONSENT=true`, `CYBER_AGENT_PROVIDER`, `OTEL_SERVICE_NAME=cyber-autoagent` | `src/cyberautoagent.py:189`, `:389`, `:438`, `DirectDockerService.ts:213-217` | Code |
| Containers | `cyber-autoagent:latest` and the `cyber-langfuse*` container names above | `docker/docker-compose.yml` | Config |
| Langfuse traffic | `POST /api/public/otel/v1/traces` and `GET /api/public/v2/prompts/cyber/system/system_prompt?label=production` with `Authorization: Basic Y3liZXItcHVibGljOmN5YmVyLXNlY3JldA==` (`cyber-public:cyber-secret`). Plain HTTP to `langfuse-web:3000` or `localhost:3000`, so a network sensor sees it only when `LANGFUSE_HOST` points at another machine | `src/cyberautoagent.py:180-191`, `src/modules/prompts/factory.py:65-75`, `:105` | Config (keys, host) |
| Trace contents | Trace attributes `gen_ai.system=Cyber-AutoAgent`, `agent.name=Cyber-AutoAgent`, tag `Cyber-AutoAgent`, agent name `Cyber-AutoAgent OP_<timestamp>`, plus the target and objective in clear text | `src/modules/agents/cyber_autoagent.py:929-975` | Code |
| Model traffic | Bedrock runtime in `us-east-1` by default, or Ollama on 11434, or whatever LiteLLM is pointed at | `src/modules/config/manager.py` | Config |
| System prompt | `You are Ghost, an autonomous cyber operations specialist.`, visible where model traffic is inspected | `src/modules/prompts/templates/system_prompt.md:1-3` | Code (prompt) |

## An exposed console

Cyber-AutoAgent has no web console of its own: the front end is a terminal application and the agent opens no listening port (`--service-mode` only sleeps, `src/cyberautoagent.py:373-385`). What gets exposed is the observability stack its compose file starts:

| Service | Port and bind | Default credentials | Code |
|---|---|---|---|
| Langfuse 3 web (`docker.io/langfuse/langfuse:3`) | `0.0.0.0:3000` | Seeded user `admin@cyber-autoagent.com` / `changeme`, org `Cyber-AutoAgent` (`cyber-org-id`), project `penetration-tests` (`cyber-project-id`), API keys `cyber-public` / `cyber-secret`, `NEXTAUTH_SECRET: mysecret`, fixed `ENCRYPTION_KEY` and `SALT` defaults | `docker/docker-compose.yml:105-212` |
| MinIO (`docker.io/minio/minio`) | `9090` (S3 API) and `9091` (console) on all interfaces | `minio` / `miniosecret` | `docker/docker-compose.yml:330-340` |
| Postgres, ClickHouse, Redis | not published | `postgres/postgres`, `clickhouse/clickhouse`, `myredissecret` | `docker/docker-compose.yml:121`, `:139-146`, `:283-321` |

The README and `docs/deployment.md:136` print the login, and `.env.example:136` and the README suggest `LANGFUSE_ADMIN_PASSWORD`, but the compose file never reads that variable: the password stays `changeme` unless the operator edits the compose file. Sign-up is disabled (`NEXT_PUBLIC_SIGN_UP_DISABLED`), so the seeded account is the way in. Anyone who logs in reads every trace: targets, objectives, every command the agent ran and its output.

The unauthenticated Langfuse pages are stock Langfuse, so a Langfuse on port 3000 next to a MinIO console on 9091 is the most a scan can show without logging in. The strings that tie a Langfuse to Cyber-AutoAgent (`cyber-project-id`, `penetration-tests`, `admin@cyber-autoagent.com`) appear only after login or in the operator's own traffic. There is no favicon or logo of the agent to hash: the repository ships no web assets.

## What has been seen in the wild

No public report of Cyber-AutoAgent used in an intrusion was found on November 26, 2026, and no public detection rules for it existed before these. This folder is built from the source code alone.

## What the code does not contain

No implant, C2, persistence or exfiltration code. No hard-coded user agent, callback server of its own or out-of-band domain other than the dalfox callback name above. Its target-side traffic is the traffic of the Kali tools the model chooses.
