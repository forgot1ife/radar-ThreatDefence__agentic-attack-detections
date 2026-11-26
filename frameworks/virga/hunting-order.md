# Where to start

1. **Look for beacon check-ins** (hunt 03, Suricata 3818401 to 3818403): a host that POSTs a Base64 body to `/api/updates` every few seconds, or fetches `/api/updates/stage2`. If you capture the traffic, try decrypting it with the default key (SHA-256 of `change-this-key-in-production-environment` as the AES-256-GCM key, the first 12 bytes of the decoded body as the nonce): a default beacon probably uses it, and the plaintext names the host, user and task output.
2. **Look for very large executables that talk on the network** (hunt 04). A Virga beacon with its model is one file of about 2.5 GB. Confirm with the YARA rule `Virga_Beacon_With_Appended_GGUF_Model` if your scanner reads files that large.
3. **Check for Virga's MCP servers and admin API on your networks** (Suricata 3818406 to 3818414). The shipped config binds the MCP servers on 8444 and 50012 to every interface with no authentication, and anyone who reaches them or the admin API on 8443 controls every beacon.
4. **Check your own hosts** for `virga-server`, `virga-cli`, beacon builds with `...implant/config.BuildC2Host=`, `data/virga.db` and `/tmp/virga/extensions/` (hunt 01, the analytics rule), and scan with the YARA rules.
5. **Sweep the watchlist** (hunt 02) for the beacon user agents, file names and paths.
