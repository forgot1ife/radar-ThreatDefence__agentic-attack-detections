# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Codex sub-agent with `--wait-for-followup --instance-id --log-session-dir` | EDR | S | N, analytics | | | |
| Commands run by a sub-agent (children of that process) | EDR | S | N | | | |
| Supervisor `python -m supervisor.supervisor` or `codex-supervisor`; `codex autonomous -f` | EDR | S | N | | | |
| Finding posted to Slack with curl (`vuln_type`, `repro_steps`, `cleanup`) | EDR | S | N | | | |
| Session folder, sub-agent workspace and autonomous backup files | EDR file events, disk | S | N | | | Y |
| Compiled Codex fork with the specialist prompts | Disk | | | | | Y |
| Supervisor source and specialist prompt files in a clone | Disk | | | | | Y |
| Prompt PHP object `s:11:"injection"` in a request | Web, WAF, IDS | S | N | S | | |
| Prompt redirect target `attacker.site` in a request | Web, WAF, IDS | S | N | S | | |
| Model traffic from the ARTEMIS host (OpenRouter or OpenAI) | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Kali tools against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
| Exposed console | none: ARTEMIS has no web UI or API | | | | | |
