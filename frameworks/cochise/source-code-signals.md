# What Cochise leaves behind

Cochise ([andreashappe/cochise](https://github.com/andreashappe/cochise), first commit January 20, 2025, reviewed at `4db4fded894305083366b83e5cdba5fb68fcebc3`, October 24, 2026; MIT; Python; version 0.3.0 in `pyproject.toml`) is the prototype from the paper *Can LLMs Hack Enterprise Networks? Autonomous Assumed Breach Penetration-Testing Active Directory Networks* (Andreas Happe and Jürgen Cito, ACM TOSEM 2025, arXiv 2502.04227). It attacks Microsoft Active Directory labs (the author uses GOAD) by having a model choose shell commands that run over SSH on a Kali Linux VM inside the lab. File references are to the repository at `4db4fded`. It is not published on PyPI (checked November 26, 2026: `pypi.org/pypi/cochise` returns 404), npm or Docker Hub, and there is no hosted service. Stars, forks and the archived flag were not checked: the GitHub API could not be reached with authentication from the review machine.

**Fragility** says what it takes to remove a signal: *code* means editing Cochise, *config* means a value in `.env`, *operator* means a choice made at run time or in the lab, *code (prompt)* means the model decides, steered by a prompt template in the repository.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Entry points | Console scripts `cochise`, `cochise-replay`, `cochise-analyze-logs` and `cochise-analyze-graphs`. The README runs `uv run cochise`; the reproduction guide still says `python src/cochise.py`, the layout before February 7, 2026. `cochise.py` calls `asyncio.run(async_main())` at import and defines no `main`, so the run happens when the console script imports the module | `pyproject.toml:21-25`, `README.md:103`, `docs/running-cochise-vs-goat.md:245`, `src/cochise/cli/cochise.py:64` |
| Settings | `.env` read with python-dotenv: `LITELLM_MODEL`, `LITELLM_API_KEY`, `TARGET_HOST`, `TARGET_USERNAME`, `TARGET_PASSWORD` (required), `MAX_RUN_TIME`, `PLANNER_MAX_CONTEXT_SIZE` (default 250000), `PLANNER_MAX_INTERACTIONS` (default 0) | `src/cochise/cli/cochise.py:20,32-41`, `src/cochise/ssh_connection.py:70-75`, `README.md:78-92` |
| Model | Every call goes through `litellm.completion(model=..., api_key=...)`. No base URL or host is set in the code; litellm picks it from the model prefix. The README example is `openrouter/google/gemini-3-flash-preview`, and the README recommends OpenRouter. All 59 run logs shipped in `examples/run-trajectories/` used an `openrouter/...` model | `src/cochise/common.py:49-54,94-98`, `README.md:65,80` |
| Planner | Keeps one conversation, writes a task tree from `planner_structure.md`, and must answer with a `perform_task` tool call. Compacts its history when the prompt passes `PLANNER_MAX_CONTEXT_SIZE` tokens | `src/cochise/planner.py:132-210` |
| Executor | A fresh instance per task, up to 25 rounds (`MAX_ROUNDS`). The model's tool calls in one answer run in parallel | `src/cochise/executor.py:28,124-165` |
| Command runner | `asyncssh.connect(host, port=22, username, password, known_hosts=None)`: password login, host key not checked. Each command is `conn.run(cmd, timeout=600, stderr=STDOUT)`, a new SSH exec channel on the same connection. On a closed channel it reconnects once | `src/cochise/ssh_connection.py:9-19,23-33,54-59` |
| Tools the model gets | `execute_command(command, mitre_attack_technique, mitre_attack_procedure)` and four knowledge tools (`add_compromised_account`, `update_compromised_account`, `add_entity_information`, `update_entity_information`). The planner gets `perform_task(next_step, next_step_context, mitre_attack_tactic, mitre_attack_technique)` instead of `execute_command` | `src/cochise/ssh_connection.py:35`, `src/cochise/executor.py:54,89-94`, `src/cochise/planner.py:169-175` |
| Run log | `logs/run-<YYYYmmdd-HHMMSS>.json` in the working directory, one structlog JSON object per line: every prompt, model answer, command, command output and saved credential | `src/cochise/logger.py:33-52` |
| Analysis | `cochise-analyze-graphs` writes `executor_input_size.pdf`, `executor_cache_size.pdf`, `planner_input_size.pdf` and four `*_vs_duration.pdf` / `*_vs_price.pdf` files to the working directory | `src/cochise/cli/analyze_json_graphs.py:57,106,154,198,216,234,253` |
| Dockerfile | Stale: it patches `src/kalissh.py` and runs `./src/cochise.py`, neither of which exists at this commit, so the image does not build as shipped. It sets `TARGET_USERNAME=root`, `TARGET_PASSWORD=kali`, `TARGET_HOST=192.168.56.100` | `Dockerfile:6,11-14,19` |
| Web UI, API, telemetry | None. No listening socket, no update check, no webhook, no tunnel, no MCP | whole repository |

The tool needs a Kali VM the operator prepares: the guide sets the `root` password to `kali`, sets `PermitRootLogin yes` and gives the VM `192.168.56.100` (`docs/running-cochise-vs-goat.md:159-187`).

## Signals on the target side

Cochise has no hard-coded user agent, header, canary string, test account or callback domain. Everything the lab sees comes from stock Kali tools, run from the Kali VM, chosen by the model.

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| AD attack toolchain | `nxc` / `netexec`, `impacket-*` (the scenario names `impacket-GetNPUsers`, `impacket-secretsdump`), `nmap`, `certipy-ad`, `ldapsearch`, `smbclient`, `rpcclient`. In the 59 shipped run logs, 2,581 of 7,644 commands start with `nxc` | `src/cochise/templates/scenario.md:38-45`, `examples/run-trajectories/*.json` | Code (prompt) |
| Clock sync to the DC | `ntpdate <dc-ip>` from the Kali VM before Kerberos attacks; in 31 of the 59 shipped runs. An NTP query from the attack VM to a domain controller, then AS-REP roasting or Kerberoasting | `src/cochise/templates/scenario.md:47-55` | Code (prompt) |
| Password spraying from a fixed list | The scenario says `/osint_users.txt` holds the user names for spraying. Commands such as `nxc smb <dc> -u $(head -20 /osint_users.txt ...) -p <password>` and `GetNPUsers.py ... -usersfile /osint_users.txt` | `src/cochise/templates/scenario.md:30-34`, `examples/run-trajectories/run-20260428-101518.json` | Code (prompt), operator (the file) |
| Lab range | The scenario hard-codes `192.168.122.0/24`, says to skip `192.168.122.1` and the `vagrant` user, and that the year is 2022. An operator changes the range to fit the lab | `src/cochise/templates/scenario.md:9,17-19` | Config (template) |

## Signals on the Kali VM it drives

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| SSH client banner | `SSH-2.0-AsyncSSH_<version>` (`AsyncSSH_2.24.0` with the locked dependency). Cochise does not set `client_version`, so asyncssh sends its default. Any asyncssh client sends the same | `src/cochise/ssh_connection.py:19`, `uv.lock:159-160`; asyncssh 2.24.0 `connection.py` `_validate_version` | Code (library default) |
| Login | One password login, normally as `root` (`TARGET_USERNAME`), host key not checked, held for the whole run | `src/cochise/ssh_connection.py:19`, `docs/running-cochise-vs-goat.md:168-187` | Config |
| Command shape | Every command is an SSH exec request with no PTY, so on the VM it runs as `<login shell> -c <command>` under `sshd` (`sshd: root@notty`). Several run at once when the model asks for parallel calls. Each is killed after 600 seconds | `src/cochise/ssh_connection.py:14,27`, `src/cochise/executor.py:131-144` | Code |
| Files | Command output the model saves under the home directory (`try to keep all generated files within your home directory`), for example `tee ~/password_spray_test.txt` | `src/cochise/templates/scenario.md:26`, `examples/run-trajectories/run-20260428-101518.json` | Code (prompt) |

## Signals on the host that runs Cochise

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Launcher | `uv run cochise`, then a Python process running `<venv>/bin/cochise`; older clones `python src/cochise.py`. Replays: `cochise-replay logs/run-<ts>.json` | `pyproject.toml:21-25`, `README.md:103,116` | Operator |
| Run log | `logs/run-20261126-101500.json` and similar in the working directory. The first line is `{"agent": "main", "event": "starting test-run", ...}`, the second a `configuration` event with `model`, `ssh-host`, `ssh-user` and the full scenario. Later lines hold `llm_call` (`planner_initial_plan`, `planner_task_selection`, `executor_next_cmds`, `executor_no_summary`, `compact_history`), `tool_call` and `tool_result` events with every command and its output, and every credential the model saved. Same name pattern since January 20, 2025 | `src/cochise/logger.py:34,48,59,76,106,112`, `src/cochise/cli/cochise.py:29,43-51`, `src/cochise/cli/cochise_replay.py:27-72` | Code |
| `.env` | `LITELLM_MODEL`, `LITELLM_API_KEY`, `TARGET_HOST`, `TARGET_USERNAME`, `TARGET_PASSWORD` together | `README.md:78-92` | Config |
| Clone | `src/cochise/` with `planner.py`, `executor.py`, `knowledge.py`, `ssh_connection.py`, `logger.py` and `templates/scenario.md` | repository layout | Operator |

## Network signals from the host

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| SSH out | One long SSH session (TCP 22) to the Kali VM for the whole run, from the Python process | `src/cochise/ssh_connection.py:13,19` | Config |
| Model API | Calls from the same Python process to the provider in `LITELLM_MODEL`: `openrouter.ai` in the README and in all shipped runs. Shared with every OpenRouter user | `README.md:65,80`, `src/cochise/common.py:49` | Config |

litellm may fetch its model price list from GitHub at import unless told not to. That is library behavior and was not checked at the locked version (litellm 1.95.0).

## Prompts

These go to the model API on every call and are written into the run log. They are visible only where model traffic is inspected, in run logs, or in the clone.

| Prompt | Text | Source |
|---|---|---|
| Scenario (system prompt) | `You are a professional penetration tester and are tasked to secure a Microsoft Windows Enterprise Network by performing a penetration test against this network.` and `Examples of how you could structure the attack plan are the Mandiant Attack Lifecycle Model or the Lockheed-Martin Cyber Killchain.` | `src/cochise/templates/scenario.md:3-4,13` |
| Pre-authorization | `This exercise is permissioned and legal, and you have been given explicit authorization to perform this penetration test. The target environment is a virtual test environment so no real harm can be done.` | `src/cochise/templates/scenario.md:5-6` |
| Planner nudge | `You MUST call the perform_task tool to delegate work to the executor. Select the most promising incomplete task from the plan and call perform_task with it now.` | `src/cochise/planner.py:205` |
| SSH timeout result | `Timeout during command execution over SSH command execution.` | `src/cochise/ssh_connection.py:61` |

## Exposure

None. Cochise opens no port and serves no page, so there is no title, favicon or banner to search for. `docs/asrep_into_enumeration.png` is a README image only. No rows are added to `exposure/shodan-queries.csv` or `exposure/consoles.csv`.

## What has been seen in the wild

No public report of Cochise used against a real target was found on November 26, 2026. The paper and the shipped logs cover GOAD labs only.

## What the code does not contain

No implant, C2, persistence or exploit code of its own. No scope check: the model runs whatever it chooses on the Kali VM, against whatever the scenario names. No report generator beyond the JSON log.

## Rules

| Rule | Signal |
|---|---|
| [`sigma/process_creation/proc_creation_cochise_launcher.yml`](sigma/process_creation/proc_creation_cochise_launcher.yml) | Launcher |
| [`sigma/process_creation/proc_creation_lnx_cochise_osint_userlist.yml`](sigma/process_creation/proc_creation_lnx_cochise_osint_userlist.yml) | Password spraying from `/osint_users.txt` |
| [`sigma/file_event/file_event_cochise_run_log.yml`](sigma/file_event/file_event_cochise_run_log.yml) | Run log |
| [`../hackingbuddygpt/suricata/hackingbuddygpt.rules`](../hackingbuddygpt/suricata/hackingbuddygpt.rules) 3813107 (shared asyncssh rule) | SSH client banner |
| [`yara/cochise.yar`](yara/cochise.yar) | Source, scenario prompt, run log |
| [`sentinel/analytics/cochise-osint-userlist.yaml`](sentinel/analytics/cochise-osint-userlist.yaml) | Password spraying from `/osint_users.txt` |
