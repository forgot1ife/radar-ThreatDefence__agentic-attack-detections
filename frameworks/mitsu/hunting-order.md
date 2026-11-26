# Where to start

Mitsu has no console to find on the internet, so start with your web logs and your own hosts.

1. **Search web server and WAF logs for its user agent.** `Mitsu/0.1 (terminal assistant; public search)` on a request to your site is Mitsu's web_search tool reading the page, often the first request of a run (hunt 02, Sigma web rule, Suricata 3818901). Then look at the same source address for scanner traffic in the minutes after.
2. **Look for the model CLI it drives.** A `codex exec` with `mcp_servers.mitsu.url=` or a `claude -p` with `"mcpServers":{"mitsu":` in its command line is Mitsu running a turn on that host (hunt 01, the analytics rule).
3. **Look under the Mitsu process.** `/bin/bash -o pipefail -c ...` and scanners such as nmap, nuclei or sqlmap whose parent is python running `.../bin/mitsu` show what the agent did; `sudo -S -p "" -- /bin/bash -o pipefail -c` means the operator gave it root (hunt 01).
4. **Check for its files.** `~/.local/share/mitsu/sessions/*.json` holds the whole engagement: targets, findings and any credentials it found. Reports are in `<session id>/artifacts/` (hunt 01, Sigma file rule, YARA).
5. **Check proxy and AI-gateway logs** for the user agents (`Mitsu/0.1 (...)`, `Mitsu updater`) and, where model traffic is decrypted, for `You are Mitsu: the operator` and `mitsu__intel_upsert_asset` in requests (Suricata 3818902-3818905). Model traffic from servers (behaviors hunt 02) catches Mitsu whatever provider it uses.
