# Where to start

CTF Agent has no console to find on the internet. Its one fixed network signal is its CTFd client; the rest is on the host that runs it.

1. **If you run a CTFd platform, look at its user agents.** `Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36` with nothing after it, polling `/api/v1/challenges?per_page=500` every 5 seconds and posting to `/api/v1/challenges/attempt`, is CTF Agent (hunt 02, Suricata 3813341, Sigma web rule). A `POST /login` with `name=admin&password=admin` from it means no token was configured (Suricata 3813342).
2. **On hosts you manage, look for the sandbox start.** `timeout --signal=KILL --kill-after=5 10 bash -c 'uname -m'` runs once per solver container (hunt 01, the analytics rule). Bursts of the same wrapper, or of `docker exec -i <64 hex id> bash -c` from a shell under the Claude Code CLI, are the solver loop.
3. **Check for the launcher and its model CLIs**: `ctf-solve` with `--ctfd-url` or `--coordinator`, and `codex app-server` started by it (hunt 01).
4. **Check file events** for `ctf-workspace-` folders and `logs/trace-<challenge>-<model>-<timestamp>.jsonl` files, and scan code folders and logs with the YARA rules.
5. **Check proxy logs** for the CTFd client user agent leaving your network (Sigma proxy rule), and for `webhook.site` and model API traffic from servers (behaviors).
