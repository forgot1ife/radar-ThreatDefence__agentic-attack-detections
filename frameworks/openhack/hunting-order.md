# Where to start

1. **Look for your servers resolving or calling `oob.openhack.com`** (hunt 02, analytics rule). Only a payload the v0.x agent sent makes a target do that, so a match from a server means a blind SSRF, command or XXE payload ran there.
2. **Search web logs for `__openhack_test_` and `oob.openhack.com` in requests** (hunt 02). The first is the canary row the agent writes to prove write access; the second is an SSRF or callback parameter.
3. **Check your own hosts** for the `openhack` command line, the `claude --settings {"disableAllHooks":true,...}` and `codex ... openhack-subscription-` children, v0.2.4's scanner arguments and `~/.openhack/` (hunt 01). Scan reports under `~/.openhack/projects/*/scans/` hold the vulnerabilities found in the code that was scanned.
4. **Check proxy and DNS logs for the vendor hosts** (`api.openhack.com`, `app.openhack.com`, `install.openhack.com`) to find hosts that run or installed it.
5. **Check for model traffic from servers** (behaviors hunt 02), which catches OpenHack whatever model it uses.
6. **Sweep the watchlist** (hunt 03) once the indicators are loaded.
