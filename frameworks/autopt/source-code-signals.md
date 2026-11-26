# What AutoPT leaves behind

AutoPT ([evenhu9/AutoPT](https://github.com/evenhu9/AutoPT); repository created December 16, 2025; no license file; no releases or tags; 2 stars and 0 forks on November 26, 2026; Python with a plain HTML/CSS/JS front end; reviewed at `e38e2086` (`e38e208612e15bce94c828c2eb919ab1171332d6`), April 18, 2026, the last push) is the code of the research paper "AutoPT: How Far Are We From the Fully Automated Web Penetration Testing?" (README:15) with a Flask web console added. A LangGraph state machine of ReAct agents (Scan, Vuln_select, Inquire, Exploit, Check) scans one target with nmap and the xray scanner, pulls a proof of concept from the vulhub repository on GitHub, and runs the exploit with shell commands and a Playwright browser until the output shows `/etc/passwd`, `uid=` or similar (`src/autopt.py:112-177`, `src/psm/state.py:38-51`).

The paper's own repository is [Dizzy-K/AutoPT](https://github.com/Dizzy-K/AutoPT) (created September 2, 2024, 51 stars, 9 forks, no license file; reviewed at `fb26e0c4`, June 1, 2026). GitHub does not list either as a fork of the other. `app.py:4` says the console was adapted to "the original engine (commit 23b4706)", and commit `23b4706` exists in Dizzy-K/AutoPT, authored by evenhu9 on March 12, 2026. So evenhu9/AutoPT is a copy of the upstream engine with a web console added. The upstream has since been rewritten as an installable `autopt` command with no web console. It adds one strong signal, a self-naming user agent, listed below with its own commit. File references without a repository name are to evenhu9/AutoPT at `e38e2086`.

AutoPT is a benchmark harness, not a general scanner. A run takes a vulnerability name and an IP address. The name must be one of the 20 entries in `bench/data.jsonl` (vulhub CVEs such as `drupal/CVE-2018-7600`), or the run fails before the first step (`src/autopt.py:182-188`). The IP address can be any host. Using it against a site outside the benchmark means adding a row to `bench/data.jsonl`.

**Fragility** says what it takes to remove a signal: *code* means editing AutoPT, *config* means a setting in `src/config/config.yml`, *operator* means a choice made at run time. *Code (prompt)* marks a string that is an example in an agent prompt: removing it means editing AutoPT, but the model can also change it on any run, so treat it as likely, not certain.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Web console | `python app.py` starts Flask's development server. Host, port and debug mode come from the `web` section of `config.yml`. The shipped values are `0.0.0.0`, `5000` and `false`, and the code falls back to the same values if the section is missing. Plain HTTP. There is no login, no token and no auth check on any route. `CORS(app)` allows every origin | `app.py:14-15,620-626`, `src/config/config.yml:25-28` |
| CLI | `cd src; python main.py --name <service/CVE> --ip_addr <IP> [--model <name>] [--config config/config.yml] [--verbose]`. Prints an `AutoPT` ASCII banner in red | `src/main.py:20-54,64-66`, `src/utils.py:175-186` |
| Upstream CLI (Dizzy-K) | `autopt run --benchmark-file <jsonl> --benchmark-name <name> --ip-addr <ip:port> [--model openai:gpt-5.2]`, plus `autopt experiment`, `inspect`, `analyze`, `doctor`, usually started through `uv run autopt ...`. The package is named `autopt` but is not on PyPI | Dizzy-K `cli/main.py:59-118`, `pyproject.toml:6,34`, `README_EN.md:51` |
| Containers | None for AutoPT itself: no Dockerfile or compose file for the agent. The console runs `docker compose pull` and `docker compose up -d` in the benchmark target folders (`bench/<OWASP category>/<service>/<CVE>/docker-compose.yml`, images such as `vulhub/drupal:8.5.0`, `vulhub/weblogic:10.3.6.0-2017`, `vulhub/confluence:7.13.6`) | `app.py:431-461`, `bench/` |
| Credentials | None. Every API route is open to anyone who can reach the port | `app.py:72-617` |
| Model | Any OpenAI-compatible API through `ChatOpenAI` with `openai_base` and `openai_key` from `config.yml`. Short names map to `gpt-4o-mini-2024-07-18` (`gpt4omini`, the console default), `gpt-4o`, `gpt-3.5-turbo-0125` and `claude-3-5-sonnet-20240620`, which is also sent to the OpenAI-compatible endpoint, not to Anthropic's API. `llama31` uses NVIDIA's endpoint (`ChatNVIDIA`, `meta/llama-3.1-70b-instruct`). Any other name is passed through unchanged. The shipped `openai_base` is `https://api.whatai.cc/v1`, a third-party OpenAI-compatible relay, and the shipped `openai_key` looks like a real key (not reproduced here) | `src/autopt.py:79-108`, `app.py:493`, `src/config/config.yml:1-5` |
| Tools | Agent tools: `EXECMD` (a shell on the local machine, described to the model as "Ubuntu 22.04 as root user"), `ReadHTML` (an HTTP GET with Python requests), and LangChain's Playwright toolkit plus three extra tools (`fill_element`, `select_option`, `wait_for_selector`). The prompts drive `nmap`, `xray` (`xray ws --url`) and `curl`. Commands run through `subprocess.run(shell=True)` in `/root` (or the user's home folder), or over SSH with Paramiko when credentials are given | `src/tools.py:21-58`, `src/terminal.py:116-184`, `src/browser_ext_tools.py:348` |
| Tool installs | `install_tools.ps1` (Windows) installs Chocolatey from `community.chocolatey.org`, nmap with winget (`Insecure.Nmap`) or choco, and xray from `github.com/chaitin/xray/releases/download/<tag>/xray_windows_amd64.exe.zip` into `xray\` | `install_tools.ps1:47,69,83,145-165` |
| Autonomy | No human approval for any command. The exploit prompt begins `ROLE: Penetration tester executing authorized security assessment.` Scope is the single IP the operator typed. There is no allow list | `src/prompt.py:104-134` |
| Output | `src/result/<4omini\|4o\|35\|claude35\|llama31\|custom>/<service>_<CVE>_<model>_FSM.jsonl`, one JSON line per run with `count`, `flag` (`success` or `failed`), `runtime`, `timestamp`, `commands` and `history` | `src/autopt.py:76-98,203-215`, `app.py:545-549` |
| Telemetry | None. LangSmith tracing is switched off in code (`LANGCHAIN_TRACING_V2=false`) | `src/autopt.py:44-47` |
| Update check and notifications | None | — |

## Signals on the target side

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Page reader user agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`, cut off before `(KHTML, like Gecko)`. No browser sends this. It is sent by Python requests, so the other headers are requests' defaults: `Accept: */*`, `Accept-Encoding: gzip, deflate`, `Connection: keep-alive` (inferred from requests, not set in AutoPT). The Exploit agent's `ReadHTML` tool uses it on target URLs, and the Inquire step uses it on GitHub. The same string is CyberStrikeAI's implant user agent and a `curl -A` example in Xalgorix's prompt, so it does not identify AutoPT alone | `src/utils.py:87-90`, `src/psm/state.py:316-318` | Code |
| Upstream page reader user agent (Dizzy-K) | `AutoPT/1.0` on every `ReadHTML` request, sent with Python's `urllib` | Dizzy-K `tools/web.py:38` at `fb26e0c4` | Code |
| Port scan | `nmap -sS -p- --min-rate 3000 -T4 <IP>` (SYN scan of all 65,535 ports at 3,000 packets per second or more), then `nmap -sV -sC -p <ports> <IP>`, then `curl -sk -o /dev/null -w '%{http_code}' http://<IP>:<port>/` | `src/prompt.py:54-58` | Code (prompt) |
| Web scan | `xray ws --url http://<IP>:<PORT>` on every HTTP port (Chaitin xray's active crawler and scanner with its default plugins) | `src/prompt.py:39,60-61,69` | Code (prompt) |
| curl requests | Every `curl` command the agent runs gets `-s` added, and JSON bodies in single quotes are rewritten to double quotes. curl sends its own `curl/<version>` user agent unless the PoC sets one | `src/terminal.py:140-147` | Code |
| Browser | The Playwright toolkit starts Chromium headless (LangChain's default), so browser steps send Playwright Chromium's own user agent, which contains `HeadlessChrome` (inferred, not set in AutoPT) | `src/tools.py:49-58` | Code |
| Exploit content | The vulhub README proof of concept for the chosen CVE, adapted to the target IP. Payloads are public vulhub PoCs, not AutoPT strings | `src/psm/state.py:290-331`, `src/prompt.py:83-100` | Code (prompt) |
| Canaries, markers, test accounts, callbacks | None in the code | — | — |

## Signals on a host that runs AutoPT

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Console process | `python app.py` (or `python3 app.py`) from the repository root, listening on TCP 5000 on every interface. On start it prints a box with `AutoPT Web Console` and `访问地址: http://<host>:<port>`, then Werkzeug's development-server warning | `app.py:620-626` | Code (banner), config (port) |
| CLI process | `python main.py --name <service>/<CVE-ID> --ip_addr <IP>` run from `src/` | `src/main.py:20-54` | Code |
| Upstream CLI (Dizzy-K) | `autopt run ... --benchmark-name <name> --ip-addr <ip:port>` or `uv run autopt run ...` | Dizzy-K `cli/main.py:91-114` | Code |
| Agent commands | Children of the Python process: `/bin/sh -c nmap -sS -p- --min-rate 3000 -T4 <IP>`, `nmap -sV -sC -p ...`, `curl -s ...`. Working folder `/root` when it exists. The model is told it is root on Ubuntu 22.04. Commands containing `nano `, `searchsploit ` or `man ` are refused before they run | `src/terminal.py:125-168`, `src/tools.py:29` | Code |
| xray | `<repo>/xray/xray_linux_amd64`, `xray_windows_amd64.exe` or `xray_darwin_amd64` (or `xray` on the PATH), run directly with `ws --url http://...`, working folder `<repo>/xray/` | `src/terminal.py:62-79,252-278` | Code |
| Browser | Playwright Chromium (headless) started by the Python process | `src/tools.py:49-50` | Code |
| Files | `src/result/<model folder>/<service>_<CVE>_<model>_FSM.jsonl`. `graph.png` in the working folder when `draw_graph` is on. `src/config/config.yml` holds the model key in clear text and is rewritten by `POST /api/config` | `src/autopt.py:81-98,173-174`, `app.py:85-92` | Code (names), config (`output_path`) |
| Docker | When the console starts a target: `docker compose pull`, `docker compose up -d`, `stop`, or `down -v --rmi all` in `bench/.../<CVE>/`. On Linux it sets `DOCKER_HOST=unix:///var/run/docker.sock` | `app.py:18-30,431-487` | Code |
| SSH mode | Paramiko `invoke_shell` to a remote Kali box with `AutoAddPolicy` when a hostname, user and password are passed. This is not reachable from the console or the CLI at this commit, because `new_terminal_tool` always creates a local shell | `src/terminal.py:26-48`, `src/tools.py:24` | Code |

## Outbound traffic from the operator host

| Destination | What it is | Code | Fragility |
|---|---|---|---|
| `api.whatai.cc` (shipped `openai_base`) or whatever the operator sets, `api.openai.com` being the documented default | Model API through LangChain's OpenAI client (user agent `OpenAI/Python <version>`, from the SDK, inferred) | `src/config/config.yml:3`, `README.md:265` | Config |
| NVIDIA API catalog (`integrate.api.nvidia.com`, from `langchain_nvidia_ai_endpoints`, inferred) | Only with model `llama31` | `src/autopt.py:100-101` | Config |
| `raw.githubusercontent.com/vulhub/vulhub/master/<service>/<CVE>/README.md` and `README.zh-cn.md` (also lower-case paths) | PoC fetch before the Inquire step, with the truncated Chrome user agent | `src/psm/state.py:302-318` | Code |
| `raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>/README.md` | `ReadHTML` on a GitHub tree URL, with requests' default user agent `python-requests/<version>` | `src/utils.py:59-78` | Code |
| `cdn.jsdelivr.net/npm/remixicon@4.1.0/`, `fonts.googleapis.com` | Loaded by the browser of whoever opens the console | `frontend/index.html:7-8` | Code |
| `community.chocolatey.org`, `api.github.com/repos/chaitin/xray/releases/latest`, `github.com/chaitin/xray/releases/download/...` | Tool install on Windows, run once by the operator | `install_tools.ps1:47,145,159` | Operator |
| Docker Hub (`vulhub/*`, `mysql`, `postgres`, `nacos/*`, `bitnami/etcd`, `fokkodriesprong/docker-druid`) | Target images pulled by the console | `bench/**/docker-compose.yml` | Operator |

No tunnels, MCP servers, telemetry or callback services are used.

## An exposed AutoPT console

The console is a single page served by Flask from `frontend/`. Every API route answers without a login, so anyone who reaches port 5000 can read the configuration (including the model key), rewrite it, start and stop vulnerable containers, and start an agent run against any IP. Because the agent runs model output as shell commands on the console host, someone who can rewrite `openai_base` to point at a model server they control can run commands on that host. Treat an exposed console as an open door to its host, not only as evidence of the tool.

| Signal | Exact value | Code | Survives a rename |
|---|---|---|---|
| Page title | `AutoPT - 自动化渗透测试平台` | `frontend/index.html:6` | No |
| Sidebar text | `<h1>AutoPT</h1><span>AI Penetration Testing</span>`, logo icon class `ri-shield-keyhole-fill` | `frontend/index.html:16-17` | Partly |
| Icon | None: no `<link rel="icon">`, no `favicon.ico` in the repository, so `/favicon.ico` returns Flask's 404. No favicon hash is possible | `frontend/` | n/a |
| Assets | `/style.css`, `/app.js`, Remix Icon 4.1.0 from jsDelivr, JetBrains Mono and Inter from Google Fonts | `frontend/index.html:7-9,307` | Yes |
| Server header | Werkzeug's development server: `Server: Werkzeug/<version> Python/<version>` (inferred from Flask's `app.run`, not set in AutoPT) | `app.py:626` | Yes |
| CORS | `Access-Control-Allow-Origin: *` on responses to requests that carry an `Origin` header (flask-cors defaults, inferred) | `app.py:15` | Yes |
| Default port | 5000, plain HTTP, all interfaces | `app.py:624`, `src/config/config.yml:25-28` | Config |
| `GET /api/config` | No login. Returns `{"data":{"ai":{"nvidia_key":...,"openai_base":...,"openai_key":...,"temperature":...},"local":{...,"xray_path":...},"psm":{...,"exp_iterations":...},"test":{...},"web":{...}},"status":"ok"}`, the whole `config.yml` with the model keys in clear | `app.py:80-83`, `src/config/config.yml` | Yes |
| `GET /api/system/info` | No login. Returns `arch`, `docker_available`, `docker_version`, `platform`, `python_version`, `xray_available` and `xray_info`, whose value starts `xray路径: ` followed by the local xray path | `app.py:598-617` | Yes |
| Other API paths | `/api/vulns`, `/api/results`, `/api/results/stats`, `/api/docker/status`, `/api/docker/envs`, `POST /api/docker/start\|stop\|destroy` (`{"compose_file": "<path>"}`; any existing path on disk is accepted), `POST /api/task/start` (`{"name","ip_addr","model"}`), `/api/task/status`, `POST /api/task/stop`, `/api/task/logs/task_<unix time>?offset=N`, `/api/task/history` | `app.py:94-596` | Yes |
| Task log lines | `[系统] 开始任务: <name> -> <ip>`, `[引擎] 初始化LLM模型: ...`, `[执行命令] $ <command>` | `app.py:519`, `src/autopt.py:73`, `src/terminal.py:150` | Yes |
| TLS | None. Any certificate belongs to a reverse proxy | `app.py:626` | n/a |

No published count of exposed AutoPT consoles was found, and none was searched for here (no scanner was run). The upstream Dizzy-K/AutoPT has no web console, so it has no exposure surface.

## Signals in model traffic

Where model traffic is inspected, AutoPT prompts are LangChain ReAct templates. They contain `ROLE: Vulnerability scanner (SCAN ONLY, NO EXPLOITATION). Complete ALL steps.`, `ROLE: Vulnerability analyst — fetch PoC and produce executable exploit commands.`, `ROLE: Penetration tester executing authorized security assessment.`, the tool names `EXECMD` and `ReadHTML`, the block `=== VULHUB PoC REFERENCE (from github.com/vulhub/vulhub) ===`, and the task text `The ip address of the target machine is <IP>` / `Final Goal : <goal>`. The model is asked to end with `Final Answer: Successfully exploited the vulnerability - [evidence]` (`src/prompt.py:17-134`, `src/psm/state.py:38-51,338-341`).

## What has been seen in the wild

- No vendor or CERT report of AutoPT used in an intrusion was found (searched November 26, 2026).
- The project is academic. The README says the paper was accepted by IEEE Transactions on Information Forensics and Security. That claim was not checked.

## What the code does not contain

AutoPT ships no implant, C2, web shell manager, persistence, callback listener or out-of-band domain. It writes nothing to the target beyond what a public vulhub PoC does. It has no telemetry or update check. Its targets are the 20 benchmark CVEs, so anything it does on a target is a known public exploit for one of them (Drupalgeddon 2, Confluence OGNL injection, WebLogic XMLDecoder, Tomcat PUT, ThinkPHP 5 RCE and the rest in `bench/data.jsonl`).

## Not verified, and inferred

- Nothing was run. Headers that Werkzeug, flask-cors, requests and Playwright add are inferred from those libraries' defaults, not observed.
- The result files committed under `src/result/gpt-4o*/` and `gpt-3.5-turbo/` are named `<service>_<CVE>.jsonl`, not `*_FSM.jsonl`. `generate_mock_data.py` writes files with that name pattern into `src/result/` (`generate_mock_data.py:16,395`), so they appear to be generated mock data, not real runs. Their commands are not used as evidence here.
- The clone was 50 commits deep. The repository has 82 commits, so history before March 18, 2026 was not read.
- The upstream Dizzy-K/AutoPT was cloned 5 commits deep. When `AutoPT/1.0` was introduced there was not checked.
- Strings marked *Code (prompt)* were not checked against real agent traffic.
