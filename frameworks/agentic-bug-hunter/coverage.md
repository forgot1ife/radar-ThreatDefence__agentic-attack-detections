# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Scanner and verifier requests to your sites (`agentic-bug-hunter/<tool>`) | Web, WAF, proxy, network | S | N | N | I | |
| Password spray (HTTP form, OAuth password grant) and wordlist crawl (`Bug-Bounty-Research` user agent) | Web, WAF, Entra ID sign-in logs, network | S | N | N | I | |
| Microsoft 365 and Okta spray through TREVORspray | Sign-in logs | | behaviors | | | |
| Probe strings (`_waftest`, CRLF canary, DOM XSS hook, LLM canary, upload check, SAML and catch-all probes, NoSQL baseline) | Web, WAF, network | S | N | N | | |
| Out-of-band marker lookups (`<class>-<12 hex>.`) from your servers | DNS | S | | N | | |
| Out-of-band lookups to public interactsh servers | DNS, EDR | behaviors | behaviors | behaviors | behaviors | |
| CLI, agent, MCP server, scanner scripts, spray orchestrator | EDR | S | N | | | |
| Configuration, memory, spray audit log, session files, skills copied into a coding assistant | EDR, disk | S | N | | | Y |
| Source or pip package on disk | Disk | | | | | Y |
| Exposed Hunt Dashboard (title, footer, Host-guard 403) | Network, internet scan | | | N | | |
| Model gateway requests with its attribution headers | Proxy with TLS inspection | | | N | | |
| Model traffic from the host, nuclei, sqlmap and other tools against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | | |
