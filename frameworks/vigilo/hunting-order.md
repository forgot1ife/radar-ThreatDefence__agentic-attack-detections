# Where to start

1. **Search web, WAF and proxy logs for the user agents `Vigilo-Greybox/` and `Vigilo-Preflight/`** (hunt 03, the analytics rule). Every grey-box request carries the first; every white-box run with a target starts with the second. Note the source address and the time range.
2. **Ask the application owner whether the assessment was agreed.** Vigilo is meant for systems the operator is responsible for. Confirm the run came from the declared test source; a Vigilo user agent from an unknown address is worth a closer look.
3. **For a white-box run, look at what followed the preflight from the same address** (hunt 03): its agents then use curl, a headless browser, WhatWeb and schemathesis with their own user agents.
4. **Check your own hosts** for the platform processes, `claude -p` children with `authorised security assessment run by Vigilo` in the command line, and the `.vigilo/` run folders (hunt 01). These hold findings and proof scripts for your applications.
5. **Look for exposed instances** with the Shodan queries: the UI title `Vigilo` with nginx's CSP, or the API's CSP with uvicorn on port 8080. An exposed instance needs a login, but its findings and test-account vault are worth protecting behind a VPN or loopback binding.
