# Where to start

1. **Look for the agent windows on your hosts** with hunt 01 or the analytics rule. A command line with `DRIVE_PANE_EXITED`, a tmux session named `sapper-cmd`, `sapper-tui` or `sapper-fleet`, or one of its mission prompts means sapper-v2 ran there. Nothing else uses these strings.
2. **Look for its files**: `.sapper/` folders with `project.json`, `facts/` and `intents/`, `sapper-graph.html`, and `/opt/sapper/` or `/work/runs/` in containers. Scan with the YARA rules. The graph files list the targets, credentials and flags the agents recorded.
3. **Check model traffic from servers** (behaviors hunt 02): sapper-v2 runs Claude Code against `open.bigmodel.cn` or `api.deepseek.com` by default.
4. **Check web and proxy logs** with hunt 03 for `/__sapper_graph__/` (someone viewing a board) and for TSecBench API calls.
5. **On the target side** there is no sapper-v2 marker. Use the behaviors hunts for Kali tools and parallel scanning from one source.
