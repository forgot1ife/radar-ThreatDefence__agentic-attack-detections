# Where to start

1. **Search your web, WAF and proxy logs for the edge probe** (hunt 03): user agent `dm-edge`, a query string with `dmcb=DM1`, a manifest tag `darkmoon-proof-`. The edge-proxy agent sends `dm-edge` as its first request to a target, so it is the most likely DarkMoon string to reach a web server.
2. **Look for `/tmp/.dm_proof` on database and cache servers** (hunt 04). It is the file the database agents write to prove command execution through PostgreSQL, MySQL or Redis. Finding it means an attack worked.
3. **Check your mail servers** for `EHLO dm-test.local`, `VRFY dm-nosuchuser-9182` and messages titled `DM RELAY TEST` or `DM SPOOF TEST`.
4. **Check your own hosts** for the `ascit/darkmoon` and `ascit/opencode-darkmoon` containers, `darkmoon.sh`, and `darkmoon-settings` or `pentest_report_*.md` files (hunt 01), and scan with the YARA rules. The stack mounts the Docker socket into both containers.
5. **Check for model traffic from servers** (behaviors hunt 02). DarkMoon has no telemetry to find, so the model API is the network signal that stays when the prompt strings are changed.
