# What Hexstrike-redteam leaves behind

Hexstrike-redteam ([Yenn503/Hexstrike-redteam](https://github.com/Yenn503/Hexstrike-redteam), repository created October 17, 2025; not a GitHub fork but a copy of [HexStrike AI](../hexstrike) whose history ends at upstream commit `3326704` of September 20, 2025; no license file; 178 stars and 53 forks on November 26, 2026; no releases or tags; reviewed at `89779b7948444b88ae11600799880d6feb8e0094`, November 27, 2025) is HexStrike AI 6.0 with one addition: the BOAZ payload evasion framework ([thomasxm/Boaz_beta](https://github.com/thomasxm/Boaz_beta), vendored in the folder `BOAZ_beta/`), reachable from the server's HTTP API and from five new MCP tools. An AI assistant connected through MCP can take a Windows payload (the docs name `beacon.exe` and `mimikatz.exe`) and have the server wrap it with one of 77 BOAZ loaders and 12 encoders. File references are to the repository at `89779b7`.

This page covers only what the fork adds or changes. Everything else in HexStrike, its user agents, probe, `/health` string, `/api/command` shell, tool routes, `which` burst and `/tmp` files, is unchanged and described in [HexStrike's page](../hexstrike/source-code-signals.md). Line numbers in this fork are about 6 higher than in the HexStrike review.

BOAZ itself was not reviewed: its loader, encoder and build code in `BOAZ_beta/` and the fork's `boaz/loader_reference.py` and `boaz/encoder_reference.py` were not read. BOAZ is described here only from how the HexStrike server calls it.

**Fragility** says what it takes to remove a signal: *code* means editing the scripts, *config* means an environment variable or argument, *operator* means a value the assistant or operator picks per request.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Server | `python3 hexstrike_server.py` (via `start_server.sh`, which activates `hexstrike-env` and prints `Starting Hexstrike MCP Server on http://localhost:8888`). Flask on port 8888 (`HEXSTRIKE_PORT` or `--port`). `HEXSTRIKE_HOST` defaults to `127.0.0.1` but is never used: `app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)` is hard-coded, so it always listens on every interface. No authentication on any of its 161 routes. `GET /` has no route and returns Werkzeug's 404 page | `hexstrike_server.py:101-102,17406`, `start_server.sh:9-12` |
| BOAZ routes | Five routes added after the HexStrike ones: `POST /api/boaz/generate-payload`, `GET /api/boaz/list-loaders?category=<c>`, `GET /api/boaz/list-encoders`, `POST /api/boaz/analyze-binary`, `POST /api/boaz/validate-options` | `hexstrike_server.py:17260-17370` |
| BOAZ manager | `boaz/boaz_manager.py`, class `BOAZManager`, created at server start. BOAZ lives in `BOAZ_PATH`, by default the `BOAZ_beta` folder next to the server; if `BOAZ_beta/Boaz.py` is missing it logs `Boaz.py not found at <path>` and `BOAZ tools will not be available until BOAZ_PATH is configured` | `hexstrike_server.py:68-69,8639-8640`, `boaz/boaz_manager.py:33-52` |
| Payload build | `generate-payload` runs `python3 <BOAZ_PATH>/Boaz.py -f <BOAZ_PATH>/<input_file> -o <BOAZ_PATH>/<output_file>` plus optional flags, with `subprocess.run` (no shell), working folder `BOAZ_PATH`, a 300-second timeout and a 100 MB input limit. Input and output must be relative paths inside `BOAZ_PATH` | `boaz/boaz_manager.py:24-25,54-95,149-277` |
| Flags it passes | `-l <1-77>` loader, `-e <encoding>` (`uuid xor mac ipv4 base45 base64 base58 aes des chacha rc4 aes2`), `-c <mingw\|pluto\|akira>`, `-t <donut\|pe2sh\|rc4\|amber\|shoggoth\|augment>`, `-obf`, `-obf_api`, `-a`, `-sleep`, `-etw`, `-u`, `-g`, `-cfg`, `-d`, `-af`, `-dll`, `-cpl`, `-dream <n>`, `-entropy <n>`, `-w <n>`, `-s <cert>`, `-mllvm <args>`, `-b <binder>`, `-sgn`, `-sd`, `-j`, `-wm`, `-icon`, `-dh`, `-divide` | `boaz/boaz_manager.py:28-31,200-266` |
| MCP client | `hexstrike_mcp.py`, FastMCP server `hexstrike-ai-mcp` (unchanged), now with 137 tools; the five BOAZ tools are listed first: `boaz_generate_payload`, `boaz_list_loaders`, `boaz_list_encoders`, `boaz_analyze_binary`, `boaz_validate_options`. `boaz_generate_payload` always sends `loader`, `compiler` and `shellcode_type`, by default `16`, `mingw` and `donut` | `hexstrike_mcp.py:277-610`, `:288-291`, `:420-425` |
| Install | `install/install_all.sh` runs `install_system_deps.sh` (apt: `mingw-w64`, `gcc-mingw-w64`, `g++-mingw-w64`, `wine`, `wine64`, `wine32:i386`, `clang`, `osslsigncode`, `golang-go`, Chromium), `setup_hexstrike_venv.sh` (venv `hexstrike-env`, then `cd BOAZ_beta`, `pip install -r requirements.txt` and `bash requirements.sh`, which the script says compiles the Akira and Pluto LLVM obfuscators and installs Mangle, SysWhispers2 and pyMetaTwin) and `configure_mcp.sh` | `install/install_system_deps.sh:15-75`, `install/setup_hexstrike_venv.sh:9,46-75` |
| MCP configuration | `configure_mcp.sh` backs up and then overwrites `~/.config/Claude/claude_desktop_config.json` and `~/.config/claude-cli/config.json` with a single server `hexstrike-ai`: `<dir>/hexstrike-env/bin/python3 <dir>/hexstrike_mcp.py --server http://localhost:8888`, description `HexStrike AI v6.0 - 155+ Security Tools, BOAZ Red Team Payload Evasion`. The example `hexstrike-ai-mcp.json` uses the description `... with BOAZ Red Team Integration (155+ tools including 77+ loaders, 12 encoders) ...` | `install/configure_mcp.sh:29,37,43-58,70,78,84-99`, `hexstrike-ai-mcp.json:1-15` |
| Python packages | Adds `pyinstaller`, `pyinstaller-hooks-contrib`, `altgraph`, `cryptography` and `base58` to HexStrike's requirements for BOAZ | `requirements.txt:42-49` |
| Bundled files | `BOAZ_beta/` holds 11,947 of the repository's 11,978 files, mostly vendored Windows SDK and MinGW headers, plus `Boaz.py` (91,229 bytes), a prebuilt `Boaz` (7,645,800 bytes, git blob `4e5139991dcf4ca213df8dafb399574028f7db63`), and folders `loaders/`, `encoders/`, `evader/`, `signature/`, `obfuscate/`, `Stardust/`, `ShellcodeTemplate/`, `PIC/`. Not read for this review | `git ls-tree -r HEAD BOAZ_beta` |

## Signals on the target side

The fork adds nothing that reaches a target. BOAZ builds files on the operator's host; what the payload does when it runs is BOAZ's and the wrapped payload's behaviour, not reviewed here. HexStrike's target-side signals all remain:

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| HTTP framework | `HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)` | `hexstrike_server.py:13293` | Code |
| Browser agent | `HexStrike-BrowserAgent/1.0 (Security Testing)` | `hexstrike_server.py:13650` | Code |
| XSS probe | `<hexstrikeXSSTest123>` | `hexstrike_server.py:13825` | Code |
| Generated exploits | `Mozilla/5.0 (Compatible Exploit)` | `hexstrike_server.py:7101` | Code |

## Signals on a host that runs Hexstrike-redteam

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Payload build | `python3 <dir>/BOAZ_beta/Boaz.py -f <dir>/BOAZ_beta/<in> -o <dir>/BOAZ_beta/<out> -l 16 -c mingw -t donut ...` as a child of the Python process running `hexstrike_server.py`, working folder `BOAZ_beta`. The docs clone the repository into a folder named `hexstrike-ai` | `boaz/boaz_manager.py:194-277`, `README.md:143` | Code (path: config, `BOAZ_PATH`) |
| Build tools | The install scripts set up MinGW-w64, Wine, osslsigncode and LLVM obfuscators for BOAZ, so expect them as grandchildren of the server during a build. Which of them `Boaz.py` runs was not reviewed | `install/install_system_deps.sh:30-65`, `install/setup_hexstrike_venv.sh:55-75` | Inferred |
| Output files | Windows `.exe`, `.dll` or `.cpl` files under `BOAZ_beta/output/`. The MCP tool description and README tell the assistant to use `output/<name>.exe`, and `.gitignore` excludes `BOAZ_beta/output/*.exe`, `*.dll`, `*.bin`, `BOAZ_beta/build_*/`, `BOAZ_beta/temp/` and `BOAZ_beta/loaders/*_modified.*` | `hexstrike_mcp.py:327-334`, `README.md:424-475`, `.gitignore:38-47` | Operator (the output path is per request) |
| Input files | The payload to wrap must first be copied into `BOAZ_beta/`: the tool description tells the assistant to run `cp payload.exe BOAZ_beta/` | `hexstrike_mcp.py:321-334,399-400` | Code (prompt) |
| Log lines | In `hexstrike.log` and stdout: `BOAZ: Generating payload <in> -> <out>`, `Executing BOAZ command: python3 <path>/Boaz.py -f <in>...`, `Payload generated successfully: <out>`, `BOAZ: Listing loaders (category=<c>)`, `BOAZ: Analyzing binary <path>`. Werkzeug request lines for `/api/boaz/` should land in the same file through the root logger (inferred) | `hexstrike_server.py:82,17276,17295,17309,17331,17353`, `boaz/boaz_manager.py:159,270,281` | Code |
| MCP config | `~/.config/Claude/claude_desktop_config.json` and `~/.config/claude-cli/config.json` rewritten with the server `hexstrike-ai` and the BOAZ description; previous files kept as `<file>.backup.<YYYYmmdd_HHMMSS>` | `install/configure_mcp.sh:37,43,78,84` | Code |
| Virtual environment | `<dir>/hexstrike-env/bin/python3` running `hexstrike_server.py` or `hexstrike_mcp.py` | `install/setup_hexstrike_venv.sh:9`, `start_server.sh:9` | Code |
| Listener | Python on `0.0.0.0:8888`, whatever `HEXSTRIKE_HOST` says | `hexstrike_server.py:101-102,17406` | Config (port only) |

## Signals in model traffic

The assistant's model requests carry the BOAZ tool definitions. In Claude Code, with the server configured as `hexstrike-ai` as `configure_mcp.sh` writes it, they are named `mcp__hexstrike-ai__boaz_generate_payload`, `mcp__hexstrike-ai__boaz_list_loaders` and so on. The tool descriptions name BOAZ, `BOAZ_beta/output/`, `beacon.exe` and `mimikatz.exe`.

## The server API and an exposed server

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Requests | `POST /api/boaz/generate-payload` with a JSON body holding `input_file`, `output_file`, `loader`, `compiler`, `shellcode_type` and boolean options; `GET /api/boaz/list-loaders?category=all`; `GET /api/boaz/list-encoders`; `POST /api/boaz/analyze-binary` with `file_path`; `POST /api/boaz/validate-options` with `loader`, `encoding`, `compiler` | `hexstrike_server.py:17263-17370`, `hexstrike_mcp.py:420-470` | Code |
| Loader list | JSON with `"output": "# BOAZ Loaders\n\n**Loader <n>**: ..."` and `"count"` | `boaz/boaz_manager.py:334-348` | Code |
| Encoder list | `"output": "# BOAZ Encoding Schemes\n\n..."` | `boaz/boaz_manager.py:354-366` | Code |
| Build result | Success: `"output_path": "<abs>/BOAZ_beta/<out>"`, `"file_size"`, `"message": "✅ Payload generated successfully at <abs path>"`. Failure: `BOAZ execution failed (exit code <n>)`, `BOAZ reported success but output file not found at <path>`, `Operation timed out after 300 seconds` | `boaz/boaz_manager.py:286-318` | Code |
| BOAZ missing | Any `generate-payload` request to a server without `BOAZ_beta/Boaz.py` returns `BOAZ framework not found at <path>/Boaz.py. Please set BOAZ_PATH environment variable.` | `boaz/boaz_manager.py:162-166` | Code |
| Binary analysis | `"output": "# Binary Analysis: <path>\n\n📁 Size: ... 📊 Entropy: <x> (0-8 scale)"` with `HIGH ENTROPY`, `MEDIUM ENTROPY` or `LOW ENTROPY - Good for evasion` and a recommendation such as `Use -entropy 1 or 2 to reduce entropy` | `boaz/boaz_manager.py:392-406` | Code |
| Root page | No route for `/`; Flask's stock 404 page with `Server: Werkzeug/<v> Python/<v>` | `hexstrike_server.py` (no `/` route) | Code |
| Health | `GET /health` returns HexStrike's unchanged JSON, `"message": "HexStrike AI Tools API Server is operational"`, `"version": "6.0.0"`. Nothing in it names BOAZ, so the fork cannot be told apart from HexStrike by `/` or `/health` | `hexstrike_server.py:9029-9140` | Code |

The server has no web console, no favicon and no page title of its own. An exposed Hexstrike-redteam server looks like any HexStrike server to a scanner that fetches `/` and `/health`; only a request to an `/api/boaz/` route tells them apart. Like HexStrike, an exposed server gives anyone unauthenticated command execution through `POST /api/command`, and with this fork also a payload builder.

## What it shares with HexStrike

These HexStrike rules fire on Hexstrike-redteam unchanged, because the strings and routes are the same at `89779b7`:

- Suricata 3803001 (`HexStrike-HTTP-Framework/`), 3803002 (`HexStrike-BrowserAgent/`), 3803003 (`Mozilla/5.0 (Compatible Exploit)`), 3803004 (`hexstrikeXSSTest123`), 3803010 (`POST /api/command` on 8888), 3803011 (`POST /api/tools/` on 8888), 3803012 (health response from port 8888). The 8888 port condition in 3803010-3803012 misses a server moved with `--port`.
- Sigma `web_hexstrike_user_agent_or_xss_probe`, `proc_creation_lnx_hexstrike_server_or_mcp_client`, `proxy_hexstrike_tool_api`.
- Sentinel analytics `hexstrike-user-agent-or-xss-probe` and `hexstrike-server-on-host`, and the four HexStrike hunts.
- YARA `HexStrike_Server_Or_Client` (server and MCP client) and `HexStrike_MCP_Client_Config` (the example `hexstrike-ai-mcp.json` contains `mcpServers`, `hexstrike_mcp.py` and `:8888`; the files `configure_mcp.sh` writes use `http://localhost:8888`, which also contains `:8888`), and `HexStrike_Generated_Exploit`.
- The Zeek script in `frameworks/hexstrike/zeek/hexstrike`.

## What has been seen in the wild

No vendor or CERT report of Hexstrike-redteam in a real intrusion was found on November 26, 2026. HexStrike itself has been reported in intrusions; see [HexStrike's page](../hexstrike/source-code-signals.md#what-has-been-seen-in-the-wild).
