# Where to start

1. **Look for the probe prompts on your model and agent endpoints** (Suricata 3819201 to 3819210). Each request carries a canary `ZX<8 hex>` and is POSTed with no `User-Agent`. A burst of about 20 such requests from one source, 200 to 300 ms apart, is one `0 probe` run. Check whether the endpoint answered with the canary: that is the finding the operator now has.
2. **Check for exposed consoles on your networks** (Suricata 3819216 to 3819227, the Shodan queries). A local console behind a proxy serves `<meta name="0-control-token">`, which gives anyone who reads the page the whole console API and its shell-running agents. A Docker console answers `/healthz` without sign-in and `/` with the host refusal or the sign-in page.
3. **Check your own hosts** for `0security`, `node /app/dist/0.js --server-mode`, `/tmp/zero-engine` and `0-nuclei-` scans (hunt 01, the analytics rule, Sigma). A probe or target scan of an endpoint you do not own is the case to chase.
4. **Look for the playbook canaries and the method `ZERO` in web logs** (hunt 03, Sigma `web_zerosecurity_playbook_canaries`). They are examples, so a miss proves nothing.
5. **Sweep the watchlist** (hunt 02) for the user agents, the cloud host and the file names.
