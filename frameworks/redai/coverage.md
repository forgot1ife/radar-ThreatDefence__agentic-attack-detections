# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| `redai` launcher run by Bun, `bun install -g @kpolley/redai` | EDR | S | N | | | |
| Chrome started with a profile under `~/.redai/` (environment setup and validation) | EDR | S | N | | | |
| iOS simulators `redai-template-<name>-<time>` and `redai-<run>-<job>` created, cloned and deleted with `xcrun simctl` | EDR (macOS) | S | N | | | |
| Agent commands on PoCs and scripts in `~/.redai/runs/<runId>/` | EDR | S | N | | | |
| Run, report, transcript and environment files under `~/.redai/` | EDR, disk | S | N | | | Y |
| Reports `report.md` and `report.html` (`RedAI Report: <name>`), run state with RedAI's settings keys | Disk | | | | | Y |
| RedAI prompts (`You are RedAI's ...`) in Claude Code or Codex session logs | Disk | | | | | Y |
| Applications reached by RedAI's browser and agents | EDR network events | | N | | | |
| Source tree or npm package | Disk | | | | | Y |
| Requests to the application under test | Web server, WAF, network | | | | | |
| Model API traffic (Anthropic, OpenAI, Bedrock, Vertex) | Proxy | behaviors | behaviors | | | |
| Exposed console | Internet scan | | | | | |

S = Sigma rule, N = Sentinel hunt or analytics rule, Y = YARA rule. RedAI adds nothing to requests it sends to an application, so web, WAF and network rules cannot single it out; it has no listener, so there is nothing to find on the internet. It has no address or domain of its own, so it adds no Zeek intel or Suricata address rules.
