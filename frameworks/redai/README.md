# RedAI Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **RedAI** ([kpolley/redai](https://github.com/kpolley/redai), reviewed at `3ba2a98f`, April 26, 2026, npm `@kpolley/redai` 0.1.3), a terminal workbench that has Claude Code or Codex agents threat-model and scan a source tree, then has validator agents try to prove each finding against a running copy of the application: a real Chrome profile driven through `agent-browser`, or a cloned iOS Simulator. No vendor or CERT report of RedAI in a real intrusion is known to this project, so this folder is built from the source code alone. RedAI leaves no marker of its own in the traffic it sends to an application: this folder finds RedAI running on a host, the browser and simulators it drives, and the files it writes. It has no web console or listener to find on the internet.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, YARA, STIX 2.1 |
| Docs | [What RedAI leaves behind](source-code-signals.md), with a file and line for every signal, [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| Status | Experimental. Sigma rules tested against synthetic events written from the source. Baseline every rule on your own data before alerting |

## What RedAI leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Launcher | `redai` (a Bun script, `#!/usr/bin/env bun`), so the process is `bun <...>/bin/redai`; from a checkout `bun run redai`. Installed with `bun install -g @kpolley/redai` | `package.json:2,6-11`, `src/tui/main.tsx:1` |
| State folder | `~/.redai/` (or `REDAI_HOME`): `runs/<runId>/` with `run.json`, `events.ndjson`, `state.json`, `report.md`, `report.json`, `report.html`, `artifacts/transcripts/*.jsonl`, `artifacts/validation/<jobId>/`; `validator-environments/<id>/environment.json` | `src/paths.ts:10-30`, `src/pipeline/filesystem-run-store.ts:91-101`, `src/reporting/filesystem-report-writer.ts:43-49` |
| Browser | Environment setup starts Chrome with `--user-data-dir=~/.redai/validator-environments/<name>/browser-profile <appUrl>`; validation copies that profile to `~/.redai/runs/<runId>/validation/browser-profile` and hands it to `agent-browser` | `src/pipeline/validator-environments/environment-setup.ts:28-48`, `src/validators/web-agent-browser/index.ts:197-230,308-323` |
| iOS Simulator | `xcrun simctl create redai-template-<name>-<base36 time>` and `xcrun simctl clone <template> redai-<8 hex>-<8 hex>` per validation job, deleted afterwards | `src/pipeline/validator-environments/environment-setup.ts:99-100`, `src/validators/ios-simulator/index.ts:57`, `src/validators/ios-simulator/simctl.ts:16,52` |
| Agents | Claude Agent SDK sessions (Claude Code) or Codex SDK threads with `sandboxMode: "danger-full-access"` and `approvalPolicy: "never"`; validator agents are told to save PoCs and helper scripts under `~/.redai/runs/<runId>/artifacts/validation/<jobId>/` | `src/agents/codex/codex-agent-session.ts:34-41`, `src/validators/web-agent-browser/prompt.ts:6,20` |
| Prompts | Every agent prompt starts `You are RedAI's ...` (threat-modeling agent, micro vulnerability scanner, web validation agent and five more) | `src/scanner/prompts/*.ts`, `src/validators/*/prompt.ts:7` |
| Reports | `report.md` starts `# RedAI Report: <run name>`, `report.html` has `<title>RedAI Report: <run name></title>` | `src/reporting/report-builder.ts:55-60`, `src/reporting/filesystem-report-writer.ts:40` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: RedAI on a host, the watchlist sweep, and the network traffic of RedAI's browser and agents (which applications it tested) |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled rule: RedAI's browser, simulators or agent commands on a host |
| [`sigma/`](sigma) | 2 Sigma rules: RedAI's processes (launcher, install, the Chrome profile, the simulators, commands that use its run folder) and its files |
| [`yara/`](yara) | Rules for the source tree or npm package, its reports, its run state, and agent session logs that carry its prompts |

There are no Suricata rules and no exposure queries: RedAI has no listener, and its validators send whatever requests the model writes from a normal Chrome profile. Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `redai`.

## Limits

- Nothing RedAI sends to the application under test carries a RedAI string. Payloads, PoC scripts and helper servers are written by the model for each finding; the browser is the operator's own Chrome with the operator's sign-in.
- The paths assume the default `~/.redai`. `REDAI_HOME` moves every file and every path in a command line.
- RedAI is a white-box tool: it needs the source code of the application, and its README asks for authorized use only. A match usually means an application security test by someone with access to that code. Check who ran it and against which App URL.
