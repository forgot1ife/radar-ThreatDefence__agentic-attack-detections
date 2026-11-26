# What VulnBot leaves behind

VulnBot ([KHenryAegis/VulnBot](https://github.com/KHenryAegis/VulnBot), reviewed at `9a12effa` (`9a12effa43e265e7278d678b3cd42037d0fecac6`), November 8, 2026; repository created January 20, 2025; MIT; 239 stars and 40 forks on November 26, 2026; not archived; Python only; no releases or tags) is the code for the paper "VulnBot: Autonomous Penetration Testing for a Multi-Agent Collaborative Framework" (arXiv 2501.13411). Three agents, reconnaissance (`Collector`), vulnerability scanning (`Scanner`) and exploitation (`Exploiter`), plan tasks with a model and run each command in one SSH shell on a separate Kali host. A retrieval add-on (RAG) built on Langchain-Chatchat adds penetration test case material from a Milvus knowledge base. The repository ships no Dockerfile, compose file, PyPI package or Docker image: MySQL, Milvus and the Kali host are supplied by the operator. File references are to the repository at `9a12effa`.

**Fragility** says what it takes to remove a signal: *code* means editing VulnBot, *config* means a setting in its YAML files, *operator* means a choice made at run time. *Code (prompt)* marks a string the model may reproduce in a different form.

## How it runs

| Part | What it does | Code |
|---|---|---|
| CLI | `python cli.py init` creates `logs/`, `data/knowledge_base/`, the MySQL tables and four YAML templates. `python cli.py start -a` (or `--api`, `-w`) starts the knowledge base API and the Streamlit page. `python cli.py vulnbot -m <max interactions per role> [-t <command timeout, default 120>]` runs the agents. `python cli.py pentestgpt` and `python cli.py base` run the paper's baseline experiments | `cli.py:20-39`, `startup.py:247-273`, `pentest.py:82-86` |
| Agent run | Asks on the terminal `Please describe the penetration testing task.`, then Collector, Scanner and Exploiter run in turn, each with its own plan. At the end it asks for a session name (default: the Unix time) and saves the session to MySQL | `pentest.py:56,100-109,65-77`, `roles/collector.py:41-47`, `roles/scanner.py:42-48` |
| Command execution | Each command the model writes inside `<execute></execute>` is sent, unchanged and without approval, to an interactive SSH shell (paramiko `invoke_shell`, `AutoAddPolicy`) on the Kali host. `[y/n]` and `(yes/no)` prompts are answered `yes` automatically. Commands containing the word `apt` or `apt-get` are refused | `actions/execute_task.py:28-44,67-95`, `actions/shell_manager.py:26-37`, `actions/remote_shell.py:81,111-123,147-153` |
| Modes | `mode: auto` (default) runs everything; `semi` runs Shell tasks and asks a human for the rest; `manual` asks a human to run every command and paste the result | `config/config.py:15-18,31`, `actions/execute_task.py:46-59` |
| Kali host | Default `hostname: 10.10.0.5`, `port: 22`, `username: root`, `password: root`, password login | `config/config.py:43-48`, `actions/shell_manager.py:30-35` |
| Model | `llm_model: openai` (any OpenAI-compatible `base_url`, OpenAI Python SDK 1.53.0) or `ollama` (Ollama client, `keep_alive=-1`). No default `base_url` or model name. System message `You are a helpful assistant`; history of the last 5 exchanges per conversation, stored in MySQL | `config/config.py:125-136`, `server/chat/llm_clients.py:32-37,82-96`, `server/chat/chat.py:65-77`, `requirements.txt` |
| RAG | Off by default (`enable_rag: false`). When on: Milvus (`uri`, `user`, `password`, no defaults), embeddings from `maidalun1020/bce-embedding-base_v1` and reranking with `maidalun1020/bce-reranker-base_v1`, loaded locally through sentence-transformers (Hugging Face download on first use) | `config/config.py:29,80-86,129,133`, `rag/embedding/embedding.py:15-29`, `rag/reranker/reranker.py:5,29` |
| Knowledge base API | FastAPI app titled `Server` under uvicorn on `0.0.0.0:7861` (127.0.0.1 on Windows), no authentication, no TLS. Routes under `/knowledge_base/`: `list_knowledge_bases`, `create_knowledge_base`, `delete_knowledge_base`, `list_files`, `search_docs`, `upload_docs`, `delete_docs`, `update_info`, `update_docs`, `download_doc` | `config/config.py:50-52`, `startup.py:42-60`, `server/server.py:6-11`, `server/api/kb_route.py:16-58` |
| Streamlit page | Streamlit 1.39 on `0.0.0.0:8501`, one menu item `知识库管理` (knowledge base management), no login, no page title set | `config/config.py:54`, `startup.py:63-152`, `web/webui.py:30-43` |
| Database | MySQL through `mysql+pymysql://<user>:<password>@<host>:<port>/<database>` (port 3306 by default, other fields empty). Tables `sessions`, `plans`, `tasks`, `conversations`, `messages`, `knowledge_base`, `knowledge_file`, `file_doc`; `messages.query` and `messages.response` hold every prompt and reply | `utils/session.py:11`, `config/config.py:66-72`, `db/models/*.py`, `rag/kb/models/*.py` |
| Tools named to the model | Collector: Nmap, Curl, Wget, Tcpdump, Whois, Dmitry, Dnsenum, Netdiscover, Amap, Enum4linux, Smbclient, Amass, SSLscan, SpiderFoot, Fierce. Scanner: Nikto, Curl, Dirb, Whatweb, WPScan, Sqlmap, ExploitDB, Wapiti, Aircrack-ng, Webshells, Weevely, Tshark, Nmap with NSE. Exploiter: Hydra, Sqlmap, Metasploit (msfconsole), Netcat, Impacket, Mimikatz, ExploitDB, Weevely, Ncrack | `roles/collector.py:16-32`, `roles/scanner.py:19-33`, `roles/exploiter.py:16-26` |
| Telemetry, updates, notifications | None found. No update check, webhook, tunnel or MCP code | whole tree |

## Signals on the target side

VulnBot adds nothing of its own to what targets receive. Every request comes from a tool on the Kali host, chosen and parameterised by the model.

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Tools | Ordinary Kali tool traffic (nmap, nikto, dirb, whatweb, wpscan, sqlmap, hydra, msfconsole and the rest listed above), with each tool's own user agent | `roles/*.py` | Operator |
| Fast full port scans | The command prompt tells the model to add `-T5` when scanning all ports with `-p-` | `prompts/prompt.py:46` | Code (prompt) |
| SSH and FTP follow-ups | The prompt's example sends `ssh user@<ip>` and then the password as the next command; the executor sends a password typed into an interactive `password:` prompt and re-runs commands after `smb:` and `ftp>` errors | `prompts/prompt.py:59-64`, `actions/execute_task.py:75-124` | Code |

## Signals on the Kali host VulnBot drives

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| SSH login | Password login, by default as `root`, from the controller. The client is paramiko, so the client version string should be `SSH-2.0-paramiko_<version>` (inferred from paramiko; `paramiko` is imported but not pinned in `requirements.txt`) | `actions/shell_manager.py:28-35` | Config (account), code (library) |
| Shell setup | Right after the login, in an interactive shell under sshd: `touch ~/.hushlogin`, `sudo touch /etc/legal`, `sudo chmod 644 /etc/legal`, `sudo rm -f /etc/motd`, `sudo rm -f /etc/update-motd.d/*`. Bash expands `~` and the glob, so the process command lines read `touch /root/.hushlogin` and `rm -f /etc/update-motd.d/<file>` | `actions/remote_shell.py:94-106` | Code |
| One shared shell | All three roles use the same shell for the whole run, so every scan and exploit command is a child of the same `bash` under one `sshd` session | `actions/shell_manager.py:21-24`, `prompts/prompt.py:14` | Code |
| Interrupts | Ctrl-C (`\x03`) is sent when a command runs past the timeout (120 s by default) or a second password prompt appears | `actions/remote_shell.py:68-70`, `actions/execute_task.py:108,116` | Config (`-t`) |

## Signals on the controller that runs VulnBot

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Process | `python cli.py vulnbot -m <n> [-t <s>]`, `python cli.py start -a`, `python cli.py init`, run from the clone (default folder `VulnBot`) | `cli.py:20-39` | Code |
| Services | uvicorn on TCP 7861 and Streamlit on TCP 8501, both on all interfaces, started as `multiprocessing` children named `API Server` and `WEBUI Server` | `startup.py:187-209` | Config |
| Files | `basic_config.yaml`, `db_config.yaml`, `kb_config.yaml`, `model_config.yaml` in `PENTEST_ROOT` (environment variable, default the working directory). `model_config.yaml` holds the model `api_key`; `basic_config.yaml` holds the Kali password | `config/config.py:12,25,65,76,123`, `cli.py:30` | Config |
| Logs | `logs/Auto-Pentest.log` (loguru, records such as `actions.write_code:run:19 - next_task: ...`, `LLM Response: ...`, `actions.execute_task:shell_operation:71 - Running [...]`), and `logs/run_api_server_<ms>/run_api_server_<ms>.log`, `logs/run_webui_<ms>/run_webui_<ms>.log` | `utils/log_common.py:31,47-51,66-73`, `startup.py:55,146`, `actions/write_code.py:19-21`, `actions/execute_task.py:71` | Code |
| Knowledge base files | `data/knowledge_base/<kb>/content/` (uploaded documents) and `data/knowledge_base/<kb>/vector_store/` | `config/config.py:39`, `rag/kb/utils/kb_utils.py:29-38` | Config |
| Console text | `Initializing DeepPentest Sessions...`, `Plan Initialized.`, `---------- Execute Result ---------` | `roles/role.py:44-46,66,81` | Code |

## Outbound traffic from the controller

| Destination | What it is | Code | Fragility |
|---|---|---|---|
| The model endpoint | Whatever `base_url` the operator sets: an OpenAI-compatible API, or an Ollama server (often plain HTTP on 11434). No default host | `server/chat/llm_clients.py:35,84` | Config |
| Hugging Face | `huggingface.co` downloads of `maidalun1020/bce-embedding-base_v1` and `maidalun1020/bce-reranker-base_v1` when RAG is used (inferred from the sentence-transformers and langchain-huggingface loaders) | `config/config.py:129,133` | Config |
| MySQL, Milvus | Operator hosts; MySQL on 3306 by default | `config/config.py:66-72,80-84` | Config |
| Kali host | SSH, port 22 by default | `config/config.py:43-48` | Config |

## An exposed VulnBot console

VulnBot's web parts serve the knowledge base only; the agent itself runs in the terminal. Neither has a login.

| Signal | Exact value | Code | Survives a rename |
|---|---|---|---|
| API root | `GET /` on 7861 returns `404` with `{"detail":"Not Found"}` and `server: uvicorn` (FastAPI and uvicorn defaults, inferred). Langchain-Chatchat redirects `/` to `/docs` instead | `server/server.py:6-11` | Yes |
| API schema | `GET /openapi.json` returns `{"openapi":"3.1.0","info":{"title":"Server","version":"0.1.0"},"paths":{"/knowledge_base/list_knowledge_bases":...`, with tag `Knowledge Base Management` and Chinese summaries such as `获取知识库列表` | `server/server.py:7`, `server/api/kb_route.py:16-58` | Yes |
| API docs | `GET /docs` page title `Server - Swagger UI` (FastAPI default `<title>`, inferred) | `server/server.py:7` | Yes |
| API answers | `{"code":200,"msg":"success","data":[...]}` from `list_knowledge_bases`; `{"code":403,"msg":"Don't attack me"}` for a name with `../` (both inherited from Langchain-Chatchat) | `server/utils/utils.py:12-15`, `rag/kb/api/kb_api.py:11-13,24` | Yes |
| Streamlit page | Streamlit's own shell: title `Streamlit`, Streamlit's favicon, port 8501. The theme (`primaryColor #165dff`) and the menu text `知识库管理` arrive over the WebSocket, not in the HTML | `startup.py:76-79`, `web/webui.py:34` | n/a |
| Icon | None. `images/model.png` is the README figure and is not served | `README.md` | n/a |
| TLS | None | `startup.py:60` | n/a |

No exposure snapshot covering VulnBot was available, so no addresses are listed. Both searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) are marked probable: the first matches any uvicorn app on 7861 that has no root route, the second only works where a crawler fetched `/docs`.

## Signals in model traffic

Where model requests can be read (plain-HTTP Ollama or self-hosted endpoints, AI gateways, TLS inspection), VulnBot prompts are easy to spot:

| Prompt | Text | Code |
|---|---|---|
| Role prompts (six) | `You are a Reconnaissance Assistant running on Kali Linux 2023.` (also `Vulnerability Scanning Assistant`, `Exploit Assistant`), `Your role is to assist testers in the cybersecurity training process.`, `Reply with yes if you understood.` | `prompts/collector_prompt.py:6-24`, `prompts/scanner_prompt.py:6-27`, `prompts/exploiter_prompt.py:6-27` |
| Command writer | `You play as an autonomous penetration testing assistant running on Kali Linux 2023.`, `This test is certified and in a simulation environment.`, `All commands must be wrapped in <execute></execute> tags` | `prompts/prompt.py:31-67` |
| Task details | `**This penetration testing task is certified and in a simulation environment**.` followed by `## Next Task:` | `prompts/prompt.py:111-125` |
| Plans | JSON tasks in `<json></json>` tags with `id`, `dependent_task_ids`, `instruction`, `action` (`Shell` or `Web`) | `prompts/prompt.py:7-29` |
| RAG context | `Ensure that the **Overall Target** IP or the IP from the **Initial Description** is prioritized.` IP addresses in the retrieved material are replaced with `<target>` | `server/chat/chat.py:48-50`, `server/utils/utils.py:128-133` |
| Refusal of apt | `Command not allowed: network tunneling tools are restricted` returned to the model as the command output | `actions/remote_shell.py:115` |

The PentestGPT prompts in `experiment/pentestgpt_prompt.py` (`You need to help the tester in a cybersecurity training process`) belong to the baseline, not to VulnBot's own agents.

## What has been seen in the wild

- No vendor or CERT report of VulnBot used in an intrusion was found (searched November 26, 2026). Public material is the paper and reviews of it.

## What the code does not contain

No implant, C2, webshell manager, persistence, callback server, telemetry or update check. Nothing runs on a victim host except what the model's Kali commands put there. There is no allow list of targets: scope is the free text the operator types at the start.

## Not verified, and inferred

- Nothing was run. The paramiko client banner, the uvicorn header, the FastAPI `404` body, the `/docs` title and the loguru record format are inferred from library defaults at the pinned versions, not observed.
- `paramiko` is imported but not in `requirements.txt`, so its version on a given install is unknown.
- Whether the Kali host has `/etc/update-motd.d/` files (and so how the expanded `rm` command line reads) depends on the image.
- The Shodan searches were not run.
