# What Cain leaves behind

Cain ([cdxiaodong/cain-agent](https://github.com/cdxiaodong/cain-agent), reviewed at `2e3f4f1c` (`2e3f4f1c0c630264d8b6ed3f89d36aa5d900543c`), October 14, 2026; first commit March 18, 2026; Apache-2.0; 953 stars and 213 forks on November 26, 2026; not archived; Python, with a small Node.js bridge; package `cain-agent` 0.2.0, tag `v0.2.0`, not on PyPI) is a command line agent that points a model with a shell at one target. `cain-agent run --target <host or URL>` writes the target into `scope.yaml`, then runs three fixed stages, recon, test and report, each a model session whose prompt is built from the stage's skills, the scope and the previous stage's files. The default engine is the Claude Agent SDK; `--backend pi` uses a Node bridge on the `@earendil-works/pi-agent-core` and `pi-ai` packages for Anthropic, OpenAI, Google, DeepSeek, GitHub Copilot or OpenRouter models. A finding is checked by a second model session that never shares context with the one that found it. The package also holds a cloud misconfiguration library (AWS, Azure, GCP, Alibaba Cloud, Tencent Cloud, Huawei Cloud, Kubernetes RBAC, Docker images), which `cain-agent run` does not call at this commit. File references are to the repository at `2e3f4f1c`.

**Fragility** says what it takes to remove a signal: *code* means editing Cain, *config* means a setting or flag, *operator* means a choice made at run time. *Code (prompt)* marks a string the model is given and may reproduce in a different form.

## How it runs

| Part | What it does | Code |
|---|---|---|
| CLI | Console script `cain-agent` (`cain_agent.cli:main`). One subcommand, `run`, with `--target` (required), `--workspace` (default `./workspace`), `--idle-timeout` (300 s), `--total-budget`, `--dry-run`, `--scout`, `--coverage-gate`, `--backend claude\|pi`, `--pi-provider` (default `anthropic`), `--pi-model`, `--pi-validation-provider`, `--pi-validation-model`, and per-stage `--recon-backend/-provider/-model`, `--test-backend/-provider/-model`. `--version` prints `cain-agent 0.2.0` | `pyproject.toml:26-27`, `src/cain_agent/cli.py:124-238,593`, `src/cain_agent/__init__.py:3` |
| Scope | The target, reduced to its host, is the only `in_scope` entry. A `PreToolUse` hook parses every Bash command (curl, wget, nmap and the other tools it knows), denies any target outside scope and denies a network command whose target it cannot extract. Loopback, private and `.local` targets need no confirmation | `src/cain_agent/cli.py:56-118`, `src/cain_agent/scope.py:574-626` |
| Model tools | `Bash`, `Read`, `Grep`, `Glob` for the recon and test sessions; none for the validation session | `src/cain_agent/cli.py:43`, `src/cain_agent/executor.py:8,121-128` |
| claude backend (default) | `claude-agent-sdk` `query()` with `allowed_tools`, the scope hook and `max_turns`. The SDK runs the model and the tools; it starts the Claude Code CLI as a child process and uses its credentials (`ANTHROPIC_API_KEY` or a login). The child process and its transcript files are SDK behavior, inferred, not in this repository | `pyproject.toml:9`, `src/cain_agent/executor.py:23-33,121-128` |
| pi backend | `node <clone>/toolchain/pi/bridge.mjs`, a stdio JSON protocol (`run`, `verdict`, `tool_request`, `tool_result`, `text`, `done`). The bridge asks Python for a verdict before each tool call, then runs Bash as `bash -c <command>` (120 s timeout) and Grep/Glob with `rg`. Needs `npm ci --prefix toolchain/pi` and Node 20+. `PI_BASE_URL` points it at an Anthropic Messages gateway | `src/cain_agent/pi_executor.py:48-50,153-160`, `toolchain/pi/bridge.mjs:1-13,81-92,126-173,178-185,232-245`, `README.md` (pi backend section) |
| Skills | Markdown under the clone's `skills/` with `phase: recon` or `phase: test` front matter, pasted into the stage prompt: recon gets `webpack-js-analysis`; test gets `csrf`, `file-inclusion`, `open-redirect`, `sqli`, `ssrf`, `ssti`, `xss`, `xxe`. The root is found relative to the source (`parents[2]`), so a run from a clone (`pip install -e .`) has them and a non-editable install or the Docker image does not, and falls back to a prompt without skills | `src/cain_agent/handlers.py:77-81,154-213`, `skills/web/*/SKILL.md:1-6` |
| Docker | `python:3.11-slim`, user `cain` (uid 1000), `pip install .` of `src/` only, workdir and volume `/workspaces/cain`, `ENTRYPOINT ["cain-agent"]`, `CMD ["--help"]`. Built locally as `cain-agent:latest`; no published image | `Dockerfile:14-45`, `docs/docker.md:6,34-51` |
| Benchmark lab | `bench/docker-compose.yml` runs OWASP Juice Shop (`cain-bench-juice-shop`, 127.0.0.1:3000) and DVWA (`cain-bench-dvwa`, 127.0.0.1:8080) as practice targets | `bench/docker-compose.yml:23-24,51-52` |
| Telemetry, updates, notifications, listeners | None found. No HTTP server, update check, webhook, tunnel or MCP server | whole tree |

## Signals on the target side

Cain has no HTTP code of its own on the web path. Every request comes from a command the model runs (curl, httpx, nuclei, sqlmap, nmap and the 46 tools its registry names) with that tool's own user agent. What Cain adds is in the skills it gives the model, so it depends on the model following them.

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| XSS echo marker | The XSS skill tells the model to send "a unique marker such as `cainxss7f3a`" and grep the response for it | `skills/web/xss/SKILL.md:31` | Code (prompt) |
| CSRF marker value | For state-changing checks, a marker value such as user name `csrf_test_<timestamp>` | `skills/web/csrf/SKILL.md:220` | Code (prompt) |
| SSRF checks | Cloud metadata URLs for seven providers with their headers (`X-aws-ec2-metadata-token-ttl-seconds: 60`, `Metadata: true`, `Metadata-Flavor: Google`, `X-aliyun-ecs-metadata-token-ttl-seconds: 60`, `Authorization: Bearer Oracle`, `http://metadata.tencentyun.com/...`, `http://100.100.100.200/...`) and a callback on an operator host (`https://callback.example.com/ssrf/<nonce>` is the skill's placeholder). Generic SSRF material; covered by the shared rules | `skills/web/ssrf/SKILL.md:24,37-43` | Code (prompt) |
| Webpack recon | `curl -s` for `/`, `/webpack-manifest.json`, `/asset-manifest.json` and `<script>.js.map` | `skills/web/webpack-js-analysis/SKILL.md:30-45` | Code (prompt) |
| Recon scope | The recon prompt forbids subdomain enumeration and range scans: activity stays on the one target host | `src/cain_agent/handlers.py:296-312` | Code (prompt) |

## Signals on the host that runs Cain

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Process | `python3 <venv>/bin/cain-agent run --target <host or URL> [--backend pi] ...`; from Docker, `docker run ... -v <dir>:/workspaces/cain cain-agent:latest run --target ...` | `pyproject.toml:27`, `Dockerfile:44`, `docs/docker.md:34-51` | Code (name), operator (Docker tag) |
| pi bridge | Child `node <clone>/toolchain/pi/bridge.mjs` (stderr discarded), and its children `bash -c <model command>`, `rg --line-number --color never ...`, `rg --files --color never --glob ...` | `src/cain_agent/pi_executor.py:153-160`, `toolchain/pi/bridge.mjs:86,126-173` | Code |
| Workspace | `./workspace/` (or `--workspace`, `/workspaces/cain` in Docker): `scope.yaml`, `assets.json`, `findings.json`, `state.json`, `recon/endpoints.json`, `recon/recon-output.txt`, `recon/gate.json`, `test/test-output.txt`, `test/gate-skipped.txt` (only when the coverage gate blocks), `report/validation-summary.json`, `report/aggregated-report.json`, `report/report.md`, and `report/report-placeholder.json` when the central report fails. JSON files at the root and the report files are written to `.<name>.<random>.tmp` and renamed | `src/cain_agent/workspace.py:26-31,57-63,85-98`, `src/cain_agent/handlers.py:65-74,370-416,541,575,613`, `src/cain_agent/pipeline.py:66-69,289`, `src/cain_agent/multi_agent/orchestration.py:64-65,352-361,412-418` | Config (path), code (names) |
| `scope.yaml` | First line `# scope.yaml — generated by \`cain-agent run\``, then `# Target: <target>`, a Chinese authorization warning, `in_scope:` with the target host and `out_of_scope: []` | `src/cain_agent/cli.py:108-118` | Code |
| `recon/gate.json` | `{"recon_gate": "off"\|"pass"\|"blocked", "reasons": [...], "endpoint_count": n}`, written on every run | `src/cain_agent/handlers.py:396-416` | Code |
| Stage answers | `recon/recon-output.txt` and `test/test-output.txt` hold the model's JSON answers (`{"endpoints": [...]}`, `{"findings": [...]}`), with secrets replaced by `<REDACTED:<type>:<8 hex>>` (types `aliyun_ak`, `aws_ak`, `aws_sk`, `api_key`, `jwt`, `bearer`, `pem_private_key`, `password`) | `src/cain_agent/handlers.py:316-327,368-371,476-492,612-614`, `src/cain_agent/redact.py:43,86-130` | Code |
| Reports | `report/report.md` starts `# Cain 渗透测试报告` and ends with a legal notice that starts `本报告由 Cain 在`; `report/aggregated-report.json` has `"schema_version": 1`, `"route": "multi_agent"` and per finding `"memory_hits"`, `"solver"`, `"model_dissent"`; evidence is kept as hashes only | `src/cain_agent/report_markdown.py:491-521`, `src/cain_agent/multi_agent/orchestration.py:316-347` | Code |
| Console | `Cain dry-run — 执行计划`, `Cain run 完成`, `中断: 用户取消 (partial results in workspace)` | `src/cain_agent/cli.py:496,568,576` | Code |
| Model session transcript | With the default backend the Claude Code CLI keeps the session, so the recon and test prompts (and the scope.yaml they quote) should be in its transcript files under the user's `~/.claude/projects/` (inferred from the SDK, not in this repository) | `src/cain_agent/executor.py:23-33` | Code |
| Environment | `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` with `PI_BASE_URL`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY`; cloud library: `ALIBABA_CLOUD_ACCESS_KEY_ID`/`SECRET`, `OSS_*`, `AZURE_STORAGE_CONNECTION_STRING`, `GOOGLE_APPLICATION_CREDENTIALS` | `README.md` (backend section), `toolchain/pi/bridge.mjs:199-203,232`, `src/cain_agent/cloud/aliyun_oss.py:63-65`, `src/cain_agent/cloud/azure_blob.py:27`, `src/cain_agent/cloud/gcp_gcs.py:43` | Operator |

## Outbound traffic from the host

| Destination | What it is | Code | Fragility |
|---|---|---|---|
| Model provider | claude backend: Anthropic, through the Claude Code CLI (inferred). pi backend: the provider's default API host, or `PI_BASE_URL`. Generic hosts, covered by `behaviors/` | `src/cain_agent/cli.py:173-186`, `toolchain/pi/bridge.mjs:178-185,232-245` | Config |
| Target | Only the `--target` host; the scope hook blocks commands aimed elsewhere | `src/cain_agent/scope.py:574-605` | Code |
| npm | `npm ci --prefix toolchain/pi` fetches `@earendil-works/pi-agent-core` and `@earendil-works/pi-ai` 0.84.x | `toolchain/pi/package.json:6-9` | Operator |

## Signals in model traffic

Where model requests can be read (a plain-HTTP gateway set with `PI_BASE_URL`, an AI gateway, TLS inspection), Cain's prompts are easy to spot. They are Chinese, sent as UTF-8 by the Node clients.

| Prompt | Text | Code |
|---|---|---|
| Recon stage | `你是 Cain 的侦察 Agent,当前处于 recon 阶段(DESIGN §3.1 主线第一步)。`, then `## 授权范围(硬约束,逐字复述自 scope.yaml)` with the scope file quoted | `src/cain_agent/handlers.py:296,308-311` |
| Test stage | `你是 Cain 的测试 Agent,当前处于 test 阶段(DESIGN §3.1 主线第二步)。`, the recon endpoints inside `[UNTRUSTED_DATA]` ... `[/UNTRUSTED_DATA]`, the same scope block | `src/cain_agent/handlers.py:451-470` |
| Validation | `你是独立的漏洞校验 Agent,与发现方 Agent 分属不同 session。` with the finding inside `[UNTRUSTED_DATA]` | `src/cain_agent/validator.py:42-45,128-151`, `src/cain_agent/multi_agent/orchestration.py:98-116` |
| pi system prompt | `You are the execution engine of an authorized security-testing pipeline. Answer with precise, structured output. Use Bash for shell commands and Read, Grep, or Glob for read-only filesystem inspection.` | `toolchain/pi/bridge.mjs:266-268` |

## An exposed Cain console

None. Cain has no web interface, API server or listening socket; the pi bridge talks over stdio. `exposure/shodan-queries.csv` gets no row.

## What has been seen in the wild

- No vendor or CERT report of Cain used in an intrusion was found (searched November 26, 2026).

## What the code does not contain

No implant, C2, persistence, callback listener, telemetry or update check. The README describes the toolchain as read-only; a separate guard (`src/cain_agent/toolchain/readonly_guard.py`) blocks write flags of the tools it knows, but the test prompts ask the model to send injection payloads, so targets see live testing.

## Not verified, and inferred

- Nothing was run. The Claude Code child process, its command line and its transcript location come from the Claude Agent SDK, not from this repository.
- Whether a model sends `cainxss7f3a` or `csrf_test_<timestamp>` literally is up to the model; both are examples in the skill text.
- The prompt rules assume UTF-8 request bodies (JSON.stringify). A client that writes `\uXXXX` escapes would not match them.
- The repository creation date was taken from the first commit; the GitHub API was not reachable for this review (rate limit).
