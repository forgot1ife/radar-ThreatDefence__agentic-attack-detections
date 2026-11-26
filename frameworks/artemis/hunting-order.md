# Where to start

ARTEMIS has no console to find on the internet and sends nothing fixed to a target, so start on your own hosts.

1. **Look for the sub-agents.** A process with `--wait-for-followup`, `--instance-id` and `--log-session-dir` on one command line is the ARTEMIS fork of Codex; nothing else uses those options (hunt 01, the analytics rule). Several at once, with different `--instance-id` and `--mode` values, is one supervisor running tasks in parallel.
2. **Scope the run from its children.** Everything started by those processes is what the model did: group by the `--instance-id` value to see each task's scanners, exploits and shells (hunt 01).
3. **Find the supervisor and its folder.** `python -m supervisor.supervisor --config-file ...` and a `logs/supervisor_session_<unix time>/` folder next to it. The task YAML named on the command line holds the scope, and `vulnerabilities_found.log` lists what it reported (hunt 01, YARA).
4. **Look for the Slack posts.** A `curl` command line with `vuln_type`, `repro_steps` and `cleanup` is a finding leaving the host (hunt 01).
5. **On your web servers,** look for `s:11:"injection"` or `attacker.site` in requests (hunt 02, Suricata 3813321 to 3813324). These come from prompt examples, so treat them as leads; then check for model traffic from servers (behaviors) and scan code folders and build outputs with the YARA rules.
