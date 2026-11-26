# AutoPT Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **AutoPT** ([evenhu9/AutoPT](https://github.com/evenhu9/AutoPT), reviewed at `e38e2086`, April 18, 2026), the code of the research paper "AutoPT: How Far Are We From the Fully Automated Web Penetration Testing?" with a Flask web console added. A LangGraph state machine of ReAct agents scans one IP with nmap and xray, takes a proof of concept from the vulhub repository and runs it with shell commands and a headless browser, with no approval step. The paper's own repository, [Dizzy-K/AutoPT](https://github.com/Dizzy-K/AutoPT) (reviewed at `fb26e0c4`), has no web console and adds one signal, the user agent `AutoPT/1.0`. No vendor or CERT report of AutoPT in a real intrusion was found on November 26, 2026, so this folder is built from the source code alone: it finds AutoPT testing you, AutoPT running on a host, and its console exposed.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, YARA, STIX 2.1 |
| Docs | [What AutoPT leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Suricata rules tested against flows written from the source, YARA against both AutoPT source trees, a synthetic run result and this repository (no matches). Baseline every rule on your own data before alerting |

## What AutoPT leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Page reader | `User-Agent: AutoPT/1.0` (upstream). In evenhu9/AutoPT, `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`, cut off before `(KHTML, like Gecko)` and shared with CyberStrikeAI and Xalgorix | Dizzy-K `tools/web.py:38`; `src/utils.py:87-90` |
| Scans | `nmap -sS -p- --min-rate 3000 -T4 <IP>`, then `nmap -sV -sC`, then `xray ws --url http://<IP>:<PORT>`. Prompt examples | `src/prompt.py:54-61` |
| Exploits | Public vulhub PoCs for 20 benchmark CVEs, fetched from `raw.githubusercontent.com/vulhub/vulhub/master/<service>/<CVE>/README.md`. No canary, marker or callback of its own | `src/psm/state.py:290-331`, `bench/data.jsonl` |
| Host | `python main.py --name <service/CVE> --ip_addr <IP>` or `python app.py`; upstream `autopt run --benchmark-name ... --ip-addr ...`; results in `src/result/<model>/<service>_<CVE>_<model>_FSM.jsonl` | `src/main.py:20-54`, `app.py:620-626`, `src/autopt.py:76-98` |
| Console | Flask development server, plain HTTP on `0.0.0.0:5000`, **no login on any route**. Title `AutoPT - 自动化渗透测试平台`. No favicon. `GET /api/config` returns the model keys; `POST /api/task/start` starts an agent run | `app.py:14-15,80-83,490-512,620-626`, `frontend/index.html:6` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: AutoPT on a host, the watchlist sweep, and its user agents and console paths in web and proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: the AutoPT CLI or a run result on a host |
| [`sigma/`](sigma) | 4 Sigma rules: the agent's processes, its result file, its user agents in web logs, its console API and vulhub fetch in proxy logs |
| [`suricata/`](suricata) | Rules for its user agents and for an exposed console |
| [`yara/`](yara) | Rules for the source and for its run results |

Out-of-band lookups, attack tools started by an agent, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `autopt`.

## Limits

- AutoPT is a benchmark harness. A run must name one of the 20 CVEs in `bench/data.jsonl`; only the IP is free. Its traffic on a target is nmap, xray, curl and a public vulhub exploit, so most of it looks like any scanner.
- The scan command lines are examples in the prompt. The model can change them on any run.
- The truncated Chrome user agent is used by other agents too. Do not attribute on it alone.
- A match means AutoPT, not an attacker: it is academic code. Check who ran it and whether the test was agreed. An exposed console, though, is a risk to its owner: anyone who reaches it can read the model key and make the host run commands.
