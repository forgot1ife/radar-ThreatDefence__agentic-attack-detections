# Where to start

1. **Search your web and proxy logs** with hunt 03 or the analytics rule. A request with the user agent exactly `cyber` (or `aiscan`) or `Mozilla/5.0 (compatible; cyber/1.0; +https://github.com/chainreactors/cyber-harness)` is cyber-harness. After a `cyber` probe, look for Basic-auth password guessing against the same URL.
2. **Run the cross-framework hunts** in `behaviors/` against your internet-facing applications. Most cyber-harness scanning comes from its scanner libraries and shell tools, which carry no marker of their own.
3. **Check your own hosts** with hunt 01: the `cyber-scan`, `cyber-harness` and `cyber-audit` binaries, `--server-url http://<key>@...` command lines, the Quick Connect installer, `cyber-agent.pid` and the `.cyber/` folders. Scan with the YARA rules. A node command line holds the Hub access key; rotate it.
4. **Look for Hub traffic** (`/api/aop/node/ws`, `/cyber.rpc.`) with the Suricata rules and hunt 03: a node in your network reporting to a Hub elsewhere is a host under someone's remote control.
5. **Look for exposed Hubs** with the Shodan queries in `exposure/shodan-queries.csv` (title `Cyber` with `cyber-theme`, the CORS header set, the older `AIScan` page).
