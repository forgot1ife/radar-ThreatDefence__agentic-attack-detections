# Where to start

1. **Look for exposed servers.** Ask your scanners for port 5000 answering `GET /health` with `Kali Linux Tools API Server is running`, on your own ranges and on hosts that reach you. Such a server runs any command it is sent, with no login. Internet search engines rarely index `/health`, so a direct scan is the reliable check.
2. **Check your own hosts** (hunt 01, the analytics rule, the Sigma rules): the Kali package (`/usr/bin/kali-server-mcp`, `/usr/share/mcp-kali-server/`, user `_mcp-kali`), `client.py --server http://<ip>:5000`, `msfconsole -q -r /tmp/mks_msf_resource.rc`, and the four `which` lookups a `/health` call starts. Then read the `Executing command:` lines in the journal or Syslog: they list every command the assistant ran.
3. **Check who talks to it** (hunt 03 and the Suricata rules): calls to `/api/command` or `/api/tools/*` on port 5000 from another host mean the server is exposed or in use across the network.
4. **Check for model traffic** from the hosts that run the MCP client (behaviors hunts). With TLS inspection, the Suricata rules name MKS's tool descriptions in model requests.
5. **Check what reached your targets** with the cross-framework rules: MKS's own requests are stock Kali tools.
