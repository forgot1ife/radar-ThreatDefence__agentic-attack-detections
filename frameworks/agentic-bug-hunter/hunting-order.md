# Where to start

1. **Search sign-in logs for the spray user agent** (hunt 04, the analytics rule). `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Bug-Bounty-Research` on failed sign-ins for many users, in bursts about 30 minutes apart, is its password spray. Check for a success from the same address and reset that account.
2. **Search web, WAF and proxy logs for its user agents and probe strings** (hunt 03). `agentic-bug-hunter/<tool>`, `/?_waftest=`, `Set-Cookie:crlftest=1`, `window.__cbbx` and `/saml-control-` mark a scan; hunt 03 also lists what the same source sent within a day, since its shell scanners use curl and nuclei user agents.
3. **Check DNS logs of your servers for out-of-band markers** (Sigma `dns_query`, Suricata 3819716 to 3819720). A server that resolved `rce-<12 hex>.` or `log4j-<12 hex>.` ran an injected payload; treat it as a confirmed vulnerability.
4. **Ask whether the test was agreed.** The toolkit is promoted to bug bounty hunters. Compare the source with your program's rules and researcher headers; a spray is outside most programs' rules.
5. **Check your own hosts** for the CLI, scanner scripts, spray orchestrator, `~/.bughunter/` and the skills a coding assistant loaded (hunt 01), and look for a Hunt Dashboard listening on 8777 beyond loopback. Its `/api/state` and `/file` routes hand out every finding without a login.
