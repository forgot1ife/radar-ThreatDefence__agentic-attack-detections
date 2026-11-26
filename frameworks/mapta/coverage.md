# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Sandbox Python runner `source .venv/bin/activate && python3 /home/user/temp_script_<hex>.py` | EDR (local sandbox only) | S | N | | | |
| Sandbox script written to `/home/user/temp_script_<hex>.py` | EDR (local sandbox only) | S | N | | | |
| Run log `scan_usage.log` and `<site>_usage_log_<time>.json` next to `targets.txt` | EDR, disk | S | N | | | Y |
| Per-target report `<target>.md` | EDR, disk | | N | | | |
| Clone of the repository on disk (`main.py`, `analyze_logs.py`, `ctf-logs/`) | EDR, disk | | N | | | Y |
| Model traffic to `api.openai.com` `/v1/responses` with `security_scan` metadata | Proxy, TLS inspection | | N (host and path only) | | | |
| Slack webhook posts as `Security Scanner Bot` | Proxy, TLS inspection | | N (host only) | | | |
| curl and stock web scanners against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
| Exposed console | none: MAPTA has no web UI or API | | | | | |
