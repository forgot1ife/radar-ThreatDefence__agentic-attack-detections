# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| CTFd client user agent (`... AppleWebKit/537.36` with nothing after it) on a CTFd platform | Web server, WAF, IDS | S | N | N | | |
| Same client leaving through a proxy | Proxy | S | N | N | | |
| Default `admin` / `admin` CTFd login | IDS (request body) | | | N | | |
| pull_challenges.py Chrome 45 user agent on `/api/v1/` (shared with Eruditus) | Web, proxy, IDS | S | N | N | | |
| Launcher `ctf-solve`, `codex app-server` under it, Claude CLI with its prompt | EDR | S | N, analytics | | | |
| Claude solver `docker exec -i <64 hex> bash -c` | EDR | S | N | | | |
| Sandbox wrapper `timeout --signal=KILL --kill-after=5 ... bash -c`, start command `uname -m` | EDR (container processes) | S | N, analytics | | | |
| `ctf-workspace-<random>` folders and `logs/trace-*.jsonl` | EDR file events | S | N | | | Y (traces) |
| Source files on disk | Disk | | | | | Y |
| `webhook.site` callbacks | DNS, proxy, TLS | behaviors | behaviors | | behaviors | |
| Model traffic from the host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Exposed console | none: CTF Agent has no web UI, and its message endpoint is bound to 127.0.0.1 | | | | | |
