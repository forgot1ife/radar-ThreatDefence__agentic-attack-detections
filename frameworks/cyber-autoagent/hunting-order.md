# Where to start

1. **Search your web and proxy logs for `dalfox-xss-test.com`** (hunt 03). It is the one fixed string Cyber-AutoAgent's default module puts in requests to a target. A DNS lookup of the name from your own network means a stored payload ran there.
2. **Check whether you expose a Cyber-AutoAgent Langfuse.** A Langfuse on port 3000 with a MinIO console on 9091 on the same host, started from this compose file, accepts `admin@cyber-autoagent.com` / `changeme` and shows every target, objective and command. On your own hosts, change the password and the API keys or stop publishing the port. Look for logins with that account and requests to `/project/cyber-project-id` (Suricata 3815013 to 3815015, hunt 03).
3. **Check your own hosts** for `cyberautoagent.py`, the `--objective via environment` placeholder, the `cyber-autoagent:latest` image and `outputs/<target>/OP_<timestamp>/` folders (hunt 01, the analytics rule), and scan with the YARA rules.
4. **Look for threat emulation markers** (hunt 04) on hosts an intruder may have reached: `.emulation_marker_` files and `HKLM\SOFTWARE\EmulationMarkers\` keys.
5. **Check for model traffic from servers** (behaviors hunt 02), which catches Cyber-AutoAgent whatever model it runs on.
