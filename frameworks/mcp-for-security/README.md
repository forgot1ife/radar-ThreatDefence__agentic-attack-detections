# MCP for Security Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **MCP for Security** (Cyprox), a collection of 23 small Node.js MCP servers that each wrap one offensive or recon tool (nmap, masscan, nuclei, sqlmap, ffuf, httpx, katana, amass, commix, smuggler, wpscan, gowitness, ScoutSuite, MobSF and others) so that an AI assistant in an MCP host can run them (the main README names the Cyprox platform as one MCP client; the per-tool READMEs say "your MCP client"). Every server talks MCP over stdio only: there is no listener, no web console and no model of its own. The assistant decides what to run. The repository is no longer maintained; its README points to a rewrite called Bolt (`cyberstrikeus/bolt`), which was not reviewed here. No public report of MCP for Security used in an intrusion was found.

| | |
|---|---|
| Tool | [cyproxio/mcp-for-security](https://github.com/cyproxio/mcp-for-security), reviewed at `51dd537f` (March 30, 2026, the last commit, "deprecate: migrate to Bolt"). MIT. Docker Hub image `cyprox/mcp-for-security` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What MCP for Security leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Written from every TypeScript source, build script, the Dockerfile and the Docker workflow. Baseline every rule on your own data before alerting |

## What MCP for Security leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Wrapper processes | `node <path>/<tool>-mcp/build/index.js <tool binary>`, one per tool, started by the MCP host; in the image the path is `/app/<tool>-mcp/build/index.js` | `*/build.sh`, `Dockerfile:4,46` |
| Tool runs | The wrapper is the parent of the tool, with fixed argument shapes: `nuclei -u <url> -silent`, `scout aws --force --no-browser`, `assetfinder -subs-only`, `gowitness scan single --url ... --write-none`, `python3 /opt/commix/commix.py -u <url> <url>` (URL twice) | `nuclei-mcp/src/index.ts:29`, `scoutsuite-mcp/src/index.ts:38`, `commix-mcp/src/index.ts:24-25` |
| Container | `cyprox/mcp-for-security` (Debian bullseye with Go 1.24, nmap, masscan, sqlmap in `/opt/sqlmap`, commix in `/opt/commix`, smuggler in `/opt/smuggler`), `CMD ["bash"]`, no ports | `Dockerfile`, `.github/workflows/docker.yml:24` |
| Model requests | The MCP host sends the tool descriptions to its model, some with typos and copy-paste errors only this code has: `Run nmap with specified taget`, `do-commix` described as `Run Smuggler to detect HTTP Request Smuggling vulnerabilities` | `nmap-mcp/src/index.ts:19-20`, `commix-mcp/src/index.ts:18-19` |
| MobSF client | axios requests to the operator's MobSF with the key in both `Authorization` and `X-Mobsf-Api-Key` | `mobsf-mcp/src/mobsf.ts:26-27` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: wrappers and their tools on a host, the watchlist sweep, and the wrappers' own requests in proxy and web logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: the Docker image or a wrapper with its tool argument started on a host |
| [`sigma/`](sigma) | 3 Sigma rules: a wrapper started, a tool run by a wrapper, and the nuclei wrapper's tag lookup in proxy logs |
| [`suricata/`](suricata) | Rules for the wrappers' tool descriptions in model requests (TLS inspection) and the MobSF client's requests |
| [`yara/`](yara) | Rules for the wrapper sources and builds, and the generated `mcp-config.json` |

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `mcp-for-security`. There are no exposure searches: nothing in the project listens on a port.

## Limits

- What a target sees is the stock tools. The wrappers add no user agent, header or marker of their own, apart from the HTTP header check, which is a plain axios GET (`User-Agent: axios/1.8.4` in the lock file). The cross-framework rules in `behaviors/` cover the tools.
- MCP over stdio never reaches the network. The tool descriptions are only visible in the MCP host's model traffic, with TLS inspection, or in the MCP host's own logs.
- Folder names such as `nmap-mcp` are common among unrelated MCP projects, and anyone can rename the checkout. The descriptions with typos, the Docker image name, the `/app/<tool>-mcp/` paths and the generated `mcp-config.json` are the stronger signals.
- A match means MCP for Security, not necessarily an attacker: it is published for authorized testing. Check who started it and against what.
