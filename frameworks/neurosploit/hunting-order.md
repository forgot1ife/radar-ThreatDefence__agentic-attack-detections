# Where to start

1. **Search web and WAF logs for the user agent `NeuroSploit/` and the path `/nrsplt_baseline_404_check_9x7`** (hunt 03, the analytics rule). Both are on by default; the path is sent at the start of every run.
2. **Check your servers for out-of-band callbacks** (hunt 03). A server that resolves or fetches a name starting with `neurosploit` ran a payload; look at the request that carried it just before.
3. **If a scan reached you, look for what followed it** (hunt 04): web shells that start with `NeuroSploit WebShell`, requests with the `NeuroSploit-WebShell/1.0` user agent or `pass=ns_pass`, beacons to `/api/beacon` with `X-Implant-Token`, and `NSUpdate` tasks, Run values and `nsupdate.service` units.
4. **Check your own hosts** for the `neurosploit` binary, its containers and the `.neurosploit/` store (hunt 01), and scan with the YARA rules. The `vault/` folder holds the credentials of test accounts it created on targets.
5. **Look for exposed consoles** on port 4173 with the Shodan queries: the console has no login, so anyone who reaches it can start scans, read API keys and drive the C2.
