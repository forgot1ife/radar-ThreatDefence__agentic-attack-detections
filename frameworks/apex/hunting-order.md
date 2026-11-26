# Where to start

Apex has no console to find on the internet, but it marks the requests it sends, so start with your web logs and then look at your own hosts.

1. **Search web, WAF and proxy logs for the user agents.** `pensar-apex` (its default) or `Mozilla/5.0 (compatible; PensarBot/1.0; +https://pensar.dev)` means Apex tested that site (hunt 03, Sigma `web_apex_user_agents`, Suricata 3813241 and 3813242). Look at what the same source sent with a browser user agent around the same time: its browser does not carry the marker.
2. **Look for its test account.** A sign-up with `testuser-` and 13 digits, `test-<13 digits>@example.com` or the password `TestPassword123!@#` (Suricata 3813243; hunt 03 for query strings).
3. **Check outbound answers from callback listeners.** A response body `apex-callback <32 hex>` to a request from one of your servers means a payload made that server call an Apex listener (Suricata 3813245): look for the SSRF or command injection that caused it.
4. **On your hosts,** look for curl or wget commands with `User-Agent: pensar-apex`, the `node -e "eval(Buffer.from('InVzZSBzdHJpY3Qi...` listener, and `pensar pentest` (hunt 01, the analytics rule), and for `~/.pensar/sessions/` folders.
5. **Check for model traffic from servers** (behaviors hunt 02) and run the watchlist sweep (hunt 02), which also covers `gateway.pensar.dev` and the npm update check.
