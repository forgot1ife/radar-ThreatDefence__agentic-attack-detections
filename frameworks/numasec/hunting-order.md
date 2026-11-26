# Where to start

1. **Search your web and WAF logs for its probes** (hunt 02). `numasec-appsec-probe/1.2`, `/numasec_404_check_` and `numasec-xss` are hard-coded and do not appear in normal traffic. A hit tells you the source address and, for the login probe, which form was tried.
2. **Look for numasec on your own hosts** (hunt 01): the `numasec` binary, `.numasec/operation/` folders and `~/.local/share/numasec/numasec.db`. A server started with `--hostname 0.0.0.0` or `--mdns` and no `NUMASEC_SERVER_PASSWORD` gives a shell to anyone who reaches it.
3. **Check proxy logs for its operator-side user agents** if you inspect TLS: `numasec-knowledge-broker/1.2` and `numasec/` to model APIs show which machine runs it.
4. **Run the watchlist sweep** (hunt 03) for the CSV indicators.
5. **Check for model traffic from servers and out-of-band lookups** (behaviors hunt 02 and general hunt 05), which catch numasec whatever tools the model runs.
