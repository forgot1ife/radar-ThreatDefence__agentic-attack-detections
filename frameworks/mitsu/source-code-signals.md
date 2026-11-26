# What Mitsu leaves behind

Mitsu ([ARCANGEL0/Mitsu](https://github.com/ARCANGEL0/Mitsu), created December 15, 2025, reviewed at `a4844932fd1bd0e7b26a442bd0cc8b4a25460521`, November 20, 2026, one commit after release v1.5.2; MIT; Python; 543 stars and 122 forks on November 26, 2026; not archived) is a terminal (Textual TUI) AI pentest agent. It is published on PyPI as `mitsu` (1.4.21 on October 22, 2026, 1.5.0 to 1.5.2 in November 2026). There is no Docker image of Mitsu itself and no hosted service. File references are to the repository at `a4844932`.

**Fragility** says what it takes to remove a signal: *code* means editing Mitsu, *config* means a value in its settings, *operator* means a choice made at run time, *code (prompt)* means the model decides, steered by Mitsu's system prompt.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Install | `pip install mitsu`; or a clone with `./scripts/install.sh` (`uv tool install --force <checkout>`, optional `go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest`, writes `~/.config/mitsu/host.json`, pre-pulls `ghcr.io/searxng/searxng:latest`); or `./mitsu`, which runs `uv run --project <checkout> mitsu` | `pyproject.toml:44-45`, `scripts/install.sh:11,20,64,74-76`, `mitsu:11` |
| Process | Python running the `mitsu` console script (`.../bin/mitsu`) or `python -m mitsu`. One instance per user: lock file `$XDG_RUNTIME_DIR/mitsu/instance.lock`, else `~/.local/state/mitsu/instance.lock` | `__main__.py`, `services/single_instance.py:14-24` |
| Modes | Recon (passive; a short allow-list of local and DNS commands), Guided (operator approves each shell, Armory or external MCP call) and AutoPwn (no per-command approval; installs and sudo still ask). New sessions start in Recon at intensity 3 of 5. At most 48 tool calls per model turn | `tui/session.py:1983-1985,2044`, `tools/agent_host.py:64-116`, `agents/runtime.py:35` |
| Model providers | About 20: OpenAI, Anthropic, OpenRouter, Ollama (local `http://localhost:11434/v1` and cloud), DeepSeek, Groq, Mistral, Google Gemini and Vertex AI, Together, Fireworks, xAI, Moonshot, Z.AI, AgentRouter, Kilo Gateway, Vercel AI Gateway, NVIDIA NIM, Cloudflare, UberLLM, LiteLLM (Bedrock and others), custom endpoints. No default model. Requests use Python `urllib` with no user agent of its own (`Python-urllib/3.x`) | `config/catalog.py:18-74`, `providers/client.py:221-268,599-641,1640-1665` |
| Codex CLI provider | Per turn: an MCP server on `127.0.0.1:<random port>` at `/<32-byte token>/mcp`, then `codex exec [resume] --json [<thread>] --ignore-user-config --skip-git-repo-check --sandbox read-only --cd <temp>/mitsu-codex-sessions/<id> --config approval_policy="never" --config developer_instructions=<system prompt> [--model <m>] --config mcp_servers.mitsu.url="http://127.0.0.1:<port>/<token>/mcp" --config mcp_servers.mitsu.enabled=true <prompt>`. The Codex sandbox does not limit Mitsu's own tools, which run in Mitsu's process | `providers/codex_cli.py:108-155,320-345` |
| Claude Code provider | Per turn: the same loopback MCP server (uuid4 hex path token), then `claude -p --output-format stream-json --include-partial-messages --model <m> --system-prompt <system prompt> --system-prompt-snapshot off --setting-sources user --disable-slash-commands --strict-mcp-config --mcp-config {"mcpServers":{"mitsu":{"type":"http","url":"http://127.0.0.1:<port>/<token>/mcp"}}} --tools "" --permission-mode dontAsk --allowedTools mcp__mitsu__<tool> ... --session-id <uuid> <prompt>` in `<temp>/mitsu-claude-sessions/<id>`. It removes `ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL` and the Claude Code provider variables from the environment and requires a claude.ai login. Default model `opus` | `providers/claude_code.py:33-45,84-86,334-410` |
| Connection checks | `codex exec ... --ephemeral ... --config developer_instructions="Reply exactly MITSU_OK and do not use tools." "Reply exactly MITSU_OK."` in `<temp>/mitsu-codex-probe-*`; `claude -p ... --no-session-persistence --strict-mcp-config --restricted --tools ... "Reply exactly MITSU_OK."` in `<temp>/mitsu-claude-probe-*`, and `claude auth status --json` in `<temp>/mitsu-claude-check-*` | `providers/codex_cli.py:223-267`, `providers/claude_code.py:57-147` |
| MCP tool host | In-process `MCPServer("Mitsu built-in tools")`. Built-in tools: `bash`, `system_info`, `list_files`, `read_file`, `artifact_search`, `surface_map`, `web_search`, `vulnsearch`, `ask_user`, `user_dialog`, `request_mode`, `show_cmd`, `armory_tool_catalog`, `armory_run`, `session_upsert`, `intel_get_map`, `intel_upsert_asset`, `intel_upsert_observation`, `intel_upsert_finding`, `record_exploit`, `intel_upsert_account`, `intel_upsert_manhunt`, `remove_exploit`; plus one `armory_<tool>` per installed Armory tool, `custom_*` CLI wrappers and external MCP servers (stdio or HTTP) from `mcp_servers.json`. The model sees them as `mitsu__<tool>` (`mcp__mitsu__<tool>` through Claude Code) | `tools/agent_host.py:240,259-779,780-873`, `tools/armory_mcp.py:232-325`, `tools/custom_mcp.py` |
| Shell tool | `/bin/bash -o pipefail -c <command>` with the session workspace as working folder, new process group, no stdin, 60-second limit, 40,000 bytes of output. With `sudo` in the command (and not root), Mitsu asks for the password in a masked dialog and runs `sudo -S -p "" -- /bin/bash -o pipefail -c <command>`, writing the password to stdin. Install commands (apt, pip, go install, `curl | sh` and others) are held for an operator Yes | `tools/agent_host.py:119-180,1516-1612` |
| Armory | 165 tools in 17 categories (nmap, masscan, nuclei, sqlmap, ffuf, nikto, hydra, netexec, impacket, certipy, evil-winrm, responder, ligolo-ng, chisel, metasploit, searchsploit and others). Each runs its executable directly with the model's argument list, no shell and no stdin, 120 s by default and 600 s at most. Missing tools are installed after an operator Yes from the system package manager, pipx, go, gem, `git clone --depth 1` into `~/.local/share/mitsu/armory/<tool>/` (with a venv for Python tools), or an official script (`curl --fail --location --proto '=https' --tlsv1.2 <url> \| sh -s -- -b ~/.local/bin`; Metasploit's `msfinstall` piped to `sudo bash`) | `armory/catalog.py`, `tools/armory_mcp.py:20-25,326-375`, `services/redteam_armory.py:319-395`, `tools/agent_host.py:1382-1465` |
| Vulnerability search | `searchsploit --json <query>` and `vulnx search <query> --limit 8 --json --silent`, plus the configured web search engines. Structured Vulnx records are saved as lead findings | `search/vulnerabilities.py:97-160`, `tools/agent_host.py:367-410` |
| Web search | Direct scraping of DuckDuckGo (html. and lite.), Google, Bing, Brave, Mojeek, Ecosia, Yahoo and Startpage, or the APIs of Exa, Tavily, Keenable, Ollama, Brave, Google Programmable Search, Serper, SerpApi and Firecrawl, or a SearXNG instance | `search/engines.py:54-76,323-440` |
| Managed SearXNG | Optional, after an operator Yes: `docker volume create mitsu-searxng-config`, a helper `docker run --rm --interactive --user 0:0 --volume mitsu-searxng-config:/etc/searxng --entrypoint sh <image> -c "umask 077; cat > /etc/searxng/settings.yml"` (random `secret_key`, `limiter: false`, JSON format on), then `docker run --detach --name mitsu-searxng-<port> --restart=no --publish 127.0.0.1:<port>:8080 --volume mitsu-searxng-config:/etc/searxng --env FORCE_OWNERSHIP=true ghcr.io/searxng/searxng:latest` (docker.io fallback). Port 8888 is the dialog default. Commands can be wrapped in `sg docker -c` right after Mitsu adds the user to the docker group | `services/searxng.py:20-23,34-56,114-135,196-276`, `tui/dialogs/search_engines.py:60,354` |
| Docker installer | When Docker is missing and the operator agrees: `apt-get install -y docker.io` (or the dnf, pacman, zypper, apk, yum equivalent), `usermod -aG docker <user>` and `systemctl enable --now docker.service` | `services/docker_installer.py:31-41,56-175` |
| Reports | `/report` writes `vulnerability-assessment-<UTC yyyymmdd-HHMMSS>.html` and `.pdf` (xhtml2pdf) with `mitsu-logo.png` and `cover.png` into `<sessions>/<id>/artifacts/`; `/map` writes `attack-surface-map.html` there | `workspace/assessment_report.py:1046-1083`, `workspace/surface_map.py:305-315` |
| Update check | Only when the operator opens the update panel: `GET https://pypi.org/pypi/mitsu/json` with user agent `Mitsu updater` for PyPI installs, or `git fetch` / `git ls-remote` against the checkout's remote | `tui/updates.py:16,185-190,226-260`, `tui/menu.py:1537-1545` |
| Web UI, API, telemetry | None. No listener except the per-turn MCP server and SearXNG, both on 127.0.0.1. No telemetry, crash reporting or webhook. The README's view counter `cnt.arcangelo.net?v=mitsu` is an image in the GitHub README, not in the program | whole repository, `README.md` |

`assets/example/cover.png` is not in the package data (`pyproject.toml:79-80`), so the report step may fail on a wheel install; this was not tested.

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Page fetch user agent | `Mitsu/0.1 (terminal assistant; public search)` with `Accept: text/html,text/plain,application/json,application/xml,*/*;q=0.5`, from the `web_search` tool when the model passes it a URL. Redirects are followed to HTTP and HTTPS only; up to 1,000,000 bytes are read; 20-second timeout. URLs with embedded credentials are refused | `search/engines.py:77,114-130`, `tools/agent_host.py:343-366` | Code |
| URL first, shell later | The system prompt tells the model: when the operator supplies a URL, open that exact URL with `mitsu__web_search` before using shell fetches, and not to use curl or wget for ordinary browsing. A target's first request from a Mitsu run is often the page fetch above | `tui/session.py:5601,5626` | Code (prompt) |
| Armory tools | Scans and attacks come from stock tools (nmap, nuclei, ffuf, sqlmap, hydra, netexec and others) with their own default user agents and fingerprints, from the operator's address. Mitsu adds no marker, header or callback domain | `tools/armory_mcp.py:326-346` | Code (prompt) |
| Pace | At most 48 tool calls per model turn; each shell command is killed after 60 seconds, each Armory tool after 120 seconds unless the model asks for up to 600 | `agents/runtime.py:35`, `tools/agent_host.py:1586`, `tools/armory_mcp.py:24-25` | Code |

## Signals on a host that runs Mitsu

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Codex command line | `codex exec ... --config mcp_servers.mitsu.url="http://127.0.0.1:<port>/<token>/mcp" --config mcp_servers.mitsu.enabled=true` and `--config developer_instructions="You are Mitsu: the operator’s cute, sharp, hands-on red-team partner. ..."` | `providers/codex_cli.py:119-151` | Code |
| Claude Code command line | `claude -p ... --mcp-config {"mcpServers":{"mitsu":{"type":"http",...}}} --permission-mode dontAsk --allowedTools mcp__mitsu__bash mcp__mitsu__intel_upsert_asset ...` with `--system-prompt "You are Mitsu: ..."` | `providers/claude_code.py:376-405` | Code |
| Connection check | `Reply exactly MITSU_OK.` on a codex or claude command line | `providers/codex_cli.py:243-245`, `providers/claude_code.py:120` | Code |
| Provider work folders | `<temp>/mitsu-codex-sessions/<thread id or 32 hex>/`, `<temp>/mitsu-claude-sessions/<uuid>/`, and short-lived `mitsu-codex-probe-*`, `mitsu-codex-complete-*`, `mitsu-claude-probe-*`, `mitsu-claude-check-*`, `mitsu-claude-complete-*` | `providers/codex_cli.py:283,334`, `providers/claude_code.py:59,110,198,407` | Code |
| Shell tool | `/bin/bash -o pipefail -c <command>`, parent the Mitsu Python process; `sudo -S -p "" -- /bin/bash -o pipefail -c <command>` when the command uses sudo | `tools/agent_host.py:1557-1572` | Code |
| Armory children | Scanners started directly by the Mitsu Python process, without a shell | `tools/armory_mcp.py:337-346` | Code |
| SearXNG container | Container `mitsu-searxng-<port>`, volume `mitsu-searxng-config`, published on `127.0.0.1:<port>:8080` | `services/searxng.py:209,237-249` | Code (names), config (port) |
| Sessions | `~/.local/share/mitsu/sessions/<32 hex>.json`, mode 0600 in a 0700 folder: conversation, agent history and the Intel record (assets, observations, findings, exploits, accounts with credentials and flags, person OSINT). Keys `title_source`, `active_target`, `intel.schema_version`. Pasted images in `<id>.images/` | `config/storage.py:220-310`, `tui/session.py:2462` | Config (`XDG_DATA_HOME`) |
| Reports and map | `<id>/artifacts/vulnerability-assessment-<stamp>.html` and `.pdf` with `mitsu-logo.png` (SHA-256 `9b76c1d35bde6eac16fca735039fa8c65f4942e26851ab00f45aee5ab99339de`) and `cover.png`; HTML strings `<strong>Mitsu</strong><span>Agentic RedTeam Framework</span>` and `Mitsu \| Assessment report \| Page`; PDF metadata title `Mitsu Vulnerability Assessment`, author `Mitsu`. `attack-surface-map.html` with title `<session> · Mitsu` and `✦ Mitsu · Session Intel` | `workspace/assessment_report.py:877-880,1022-1026,1039,1052-1067`, `workspace/surface_map.py:247-264,311` | Code |
| Configuration | `~/.config/mitsu/credentials.json` (provider profiles and API keys, plain text, 0600), `settings.json`, `mcp_servers.json`, `host.json` | `config/storage.py:57,204`, `tui/menu.py:132`, `services/host_environment.py:33-35` | Config (`XDG_CONFIG_HOME`) |
| Armory installs | `~/.local/share/mitsu/armory/<tool>/` with `.mitsu-armory-managed`, `~/.local/share/mitsu/armory/managed.json`, binaries in `~/.local/bin/` | `services/redteam_armory.py:133,166-218,389-394` | Code |
| Environment | `MITSU_IMAGE_PROTOCOL` (companion picture rendering), `KEENABLE_API_KEY`, `XDG_*`. Provider keys are kept in `credentials.json`, not in variables | `tui/widgets/mitsu.py:86`, `search/engines.py:354` | Config |

## Network signals from the host

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Model APIs | The host of the chosen provider (see How it runs), with a `Python-urllib/3.x` user agent for direct providers, or the Codex and Claude Code CLIs' own traffic | `config/catalog.py`, `providers/client.py:1646-1652` | Config |
| Prompts in model traffic | Every request carries the system prompt starting `You are Mitsu: the operator’s cute, sharp, hands-on red-team partner.` (the apostrophe is sent as `’` in JSON) and the tool list with `mitsu__intel_upsert_asset`, `mitsu__session_upsert` and the other built-in tools. Visible only where model traffic is inspected | `tui/session.py:5549`, `providers/client.py:1341-1352` | Code |
| Search engines | `Mitsu/0.1 (terminal assistant; public search)` to `html.duckduckgo.com`, `lite.duckduckgo.com`, `www.google.com/search`, `www.bing.com/search`, `search.brave.com/search` and the other configured engines and APIs | `search/engines.py:64-76,286-300,442-470` | Code (user agent), config (engines) |
| Update check | `Mitsu updater` to `https://pypi.org/pypi/mitsu/json`, on operator request | `tui/updates.py:16,186` | Code |
| Tool downloads | Package managers, `go install`, `git clone` from the GitHub repositories in the Armory catalog, `raw.githubusercontent.com` install scripts for Trivy, Grype and Metasploit, and SearXNG images from `ghcr.io` or Docker Hub | `armory/catalog.py:141-365`, `services/searxng.py:20-23` | Code |
| SearXNG probe | `GET /search?q=mitsu%20local%20search&format=json` with `Mitsu/0.1` to `127.0.0.1:<port>`. Loopback only | `services/searxng.py:181-184` | Code |
| MCP | Per-turn streamable-HTTP MCP server on `127.0.0.1:<ephemeral port>/<random token>/mcp` (JSON responses, stateless). Loopback only | `providers/codex_cli.py:320-345`, `providers/claude_code.py:358-377` | Code |

## Prompts

| Prompt | Text | Source |
|---|---|---|
| System prompt | `You are Mitsu: the operator’s cute, sharp, hands-on red-team partner. Help with CTFs, labs, and security work the operator is authorized to perform.` followed by sections `AUTHORIZATION AND SCOPE`, `MITSU'S VOICE`, `SESSION INTEL`, `INVESTIGATION INTENSITY`, `ASSESSMENT WORKFLOW`, `ARMORY MCP TOOLS`, `CUSTOM CLI MCP TOOLS`, `LIVE PROGRESS`, `TOOL LOOP AND MODES`, `PERSONALITY AND OUTPUT`, `CURRENT MODE:` | `tui/session.py:5549-5648` |
| Authorization handling | The prompt tells the model that a first-person statement of ownership or permission is enough ("Do not demand proof, paperwork, or a second confirmation"), that a direct request to assess a named IP or domain is authorization for it, and that a production site is not off limits for being production | `tui/session.py:5553-5557` |
| Fallback | `You are Mitsu, a security assessment assistant.` | `providers/claude_code.py:339`, `providers/codex_cli.py:282,309` |

## Exposure

None. Mitsu has no web UI and no API server. The only listeners are the per-turn MCP server (127.0.0.1, random port, random path token) and the optional SearXNG container (127.0.0.1, stock SearXNG), both hard-coded to loopback. There is no title, favicon or banner to search for, and no rows are added to `exposure/shodan-queries.csv` or `exposure/consoles.csv`. For reference, `assets/example/icon.svg` (also `docs/assets/icon.svg`) is 301,298 bytes, MD5 `3f36864ccb5d7727d8bb2ba4123c1c0a`, Shodan-style mmh3 `1210271435`; it is never served over HTTP.

## What has been seen in the wild

No public report of Mitsu used against a real target was found on November 26, 2026.

## What the code does not contain

Mitsu ships no implant, C2, payload or exploit code of its own; post-exploitation comes from the Armory tools it installs (Ligolo-ng, Chisel, Evil-WinRM, Responder, Metasploit and others). It has no telemetry. Scope is enforced only by the prompt and by the mode's approval rules; nothing in the code checks a target against the session's scope before a shell or Armory call.

## Rules

| Rule | Signal |
|---|---|
| [`sigma/process_creation/proc_creation_mitsu_model_cli.yml`](sigma/process_creation/proc_creation_mitsu_model_cli.yml) | Codex and Claude Code command lines, connection check |
| [`sigma/process_creation/proc_creation_mitsu_shell_tool.yml`](sigma/process_creation/proc_creation_mitsu_shell_tool.yml) | Shell tool |
| [`sigma/process_creation/proc_creation_mitsu_armory_tool.yml`](sigma/process_creation/proc_creation_mitsu_armory_tool.yml) | Armory children |
| [`sigma/process_creation/proc_creation_mitsu_searxng_container.yml`](sigma/process_creation/proc_creation_mitsu_searxng_container.yml) | SearXNG container |
| [`sigma/file_event/file_event_mitsu_files.yml`](sigma/file_event/file_event_mitsu_files.yml) | Sessions, configuration, provider work folders, Armory installs |
| [`sigma/proxy/proxy_mitsu_user_agent.yml`](sigma/proxy/proxy_mitsu_user_agent.yml) | Page fetch and update check user agents |
| [`sigma/web/web_mitsu_page_fetch_user_agent.yml`](sigma/web/web_mitsu_page_fetch_user_agent.yml) | Page fetch user agent |
| [`suricata/mitsu.rules`](suricata/mitsu.rules) 3818901-3818902 | User agents |
| [`suricata/mitsu.rules`](suricata/mitsu.rules) 3818903-3818905 | Prompts and tool names in model traffic |
| [`yara/mitsu.yar`](yara/mitsu.yar) | Source, session files, reports and map |
| [`sentinel/analytics/mitsu-model-cli-or-searxng-on-host.yaml`](sentinel/analytics/mitsu-model-cli-or-searxng-on-host.yaml) | Codex and Claude Code command lines, SearXNG container |
