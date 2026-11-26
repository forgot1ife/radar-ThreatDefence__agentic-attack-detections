# Decepticon Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Decepticon** ([BitterSecurity/Decepticon](https://github.com/BitterSecurity/Decepticon), reviewed at `6b15092d`, November 20, 2026, after release `v2.2.2`), an autonomous red team agent built on LangGraph. Its agents run commands in a Kali sandbox and can start Sliver or Havoc C2, BloodHound CE and a reverse-engineering service on demand; it installs with a Go launcher and runs as a Docker Compose stack. Its open web console was removed on November 11, 2026 (`02864fbd`, "remove OSS web dashboard in favor of the SaaS UI"); consoles still online run older builds. No vendor or CERT report of Decepticon in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds Decepticon running on a host, reporting from your network, its consoles exposed, and the few marks it leaves on a target.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What Decepticon leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax, Suricata rules against test flows, YARA against the Decepticon source tree. Baseline every rule on your own data before alerting |

## What Decepticon leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Telemetry | `POST https://decepticon-telemetry-gateway.purpleailab.workers.dev/v1/telemetry` with `User-Agent: decepticon-telemetry/1.0`. The launcher's setup wizard defaults to sharing, although `TELEMETRY.md` calls it opt-in | `clients/launcher/internal/config/env.example:200`, `clients/launcher/cmd/onboard.go:280`, `packages/decepticon/decepticon/telemetry/exporter.py:35` |
| Host | Installer `curl -fsSL https://decepticon.red/install \| bash`; `~/.local/bin/decepticon` and `~/.decepticon/`; images `ghcr.io/bittersecurity/decepticon-*` and containers `decepticon-<service>` | `scripts/install.sh`, `docker-compose.yml` |
| Sandbox | `python3 -m decepticon_sandbox.server` on port 9999 (no token by default); every agent command runs in tmux with the prompt `[DCPTN:<status>:<cwd>]` and a hook that calls `tmux ... set-option ... @dcptn_completion`; logs in `<workspace>/.sessions/<session>.log` | `packages/decepticon/decepticon_sandbox/` |
| C2 | Sliver operator `decepticon` saved to `/workspace/.sliver-configs/decepticon.cfg`; Havoc operator `decepticon` with password `decepticon-havoc-c2` | `containers/c2-sliver-entrypoint.sh`, `containers/c2-havoc-entrypoint.sh` |
| Own clients | `decepticon-roe/1` to crt.sh, `decepticon-http-sandbox/1` to the sandbox daemon, `codex_cli_rs/0.0.0 (Unknown 0; unknown) unknown` to chatgpt.com on a ChatGPT login | `passive_discovery.py:40`, `backends/http_transport.py:139`, `config/codex_chatgpt_handler.py:54` |
| Target side | Web fetches with `Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7` and an impersonated browser; user agent templates with `<CHROME_VER>` left unfilled; `X-Decepticon-Eng: <slug>` on phishing lures. The rest is ordinary Kali tool traffic | `decepticon_sandbox/web/transport.py:156`, `skills/shared/opsec/SKILL.md`, `skills/standard/phisher/SKILL.md:66` |
| Console (removed build) | Port 3000, no login, title `Decepticon — Autonomous Red Team Platform`, icon with Shodan hash `-1814445533` (recomputed from the file), `/api/health` listing langgraph, litellm, neo4j and postgres | `clients/web/` at `d26ddaa1` |

## Exposed consoles

3 hosts on port 3000, 1 seen in the seven days to November 25, 2026, and 4 services behind Basic authentication with a realm that starts with `Decepticon`. A title search for "Autonomous Red Team Platform" alone also finds "Jed | The Autonomous Red Team Platform", another product, so the title search uses the full title. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `decepticon`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Decepticon on a host, the watchlist sweep, and its markers in web and proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | Scheduled rule: Decepticon on a host or sending telemetry |
| [`sigma/`](sigma) | 6 Sigma rules: install and containers, sandbox and C2 processes, files, telemetry and installer lookups, its clients in proxy logs, markers in web logs |
| [`suricata/`](suricata) | Rules for its telemetry, own clients, exposed services and console, and target-side markers; address rules generated from the CSV |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the package, the launcher, sandbox session logs, the Sliver and Havoc configs, and the scope file |

Out-of-band lookups, attack tools started by an agent, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `decepticon`.

## Limits

- Most of Decepticon's target traffic comes from Kali tools and curl_cffi browser impersonation, so target-side rules catch little. The host and network rules are the strong part.
- The tools with the most distinctive user agents (`detect_tech_stack`, `ai_surface_scan`, `http_recon`) are in the package but not bound to any agent at `6b15092d`; they are documented, not relied on.
- The phishing header and the user agent templates are instructions in skill text. The model can leave them out or fill them in.
- Processes inside the containers are visible only where your EDR sees container processes (Linux hosts, not Docker Desktop on macOS or Windows).
- The web console is gone from the current code, so the exposed count will fall as operators update.
- A match means Decepticon, not an attacker: it is used by red teams and researchers. Check who runs it and whether the test was agreed.
