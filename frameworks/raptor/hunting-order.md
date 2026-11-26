# Where to start

1. **Search your web and WAF logs for the scanner's user agent** `RAPTOR Security Scanner (Authorized Testing)` and its probe values (hunt 03, the analytics rule). It is in the code, so every request from the scanner's HTTP client carries it unless someone edits the source.
2. **Look for the fixed probes** if the user agent is missing: `/this-path-does-not-exist-raptor-probe`, `/raptor-<16 hex>-does-not-exist`, `raptornosuchparam=`, `raptorcb=`, `evil-raptor-probe.example.com`, `raptor_pp_probe_value_8472`. A WAF that keeps request bodies also sees the login probes `raptor_nonexistent_user_xyzzy_9291` and `raptor_probe_password_<n>`.
3. **Check your own hosts** for RAPTOR (hunt 01): the Claude Code session named `RAPTOR`, `libexec/raptor-*` helpers, `raptor.py` pipelines, `.raptor-run.json` and the `autonomous/exploits/` and `autonomous/patches/` folders. Scan checkouts with the YARA rules.
4. **Sweep the indicators** with the watchlist hunt (02). The rows are user agents, probe strings and file paths; RAPTOR has no infrastructure of its own to block.
5. **Check proxy logs for its client user agents** (`raptor/0.1 (+https://github.com/gadievron/raptor)`, `raptor-sca/0.1 ...`), which show a host that runs RAPTOR's dependency and advisory lookups, if you inspect TLS.
