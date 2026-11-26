# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Active scanner payload markers (XSS-BURP-AI, burp-ai-test, evil-burp-ai) reaching your sites | Web, WAF, proxy, network | S | N | N | | |
| Your servers looking up or fetching the evil-burp-ai test domains | DNS, proxy, EDR | S | N | N | I | |
| SSTI arithmetic probes (1337*73, 31337*3) | Network | | | N | | |
| MCP server with external access (CN=burp-mcp certificate) | TLS | | | N | | |
| MCP health route, initialize answer and client name | Network (cleartext or decrypted) | | | N | | |
| Extension JAR and ~/.burp-ai-agent files | EDR, disk | S | N | | | Y |
| MCP certificate creation (keytool CN=burp-mcp) and MCP bridge (supergateway to 9876) | EDR | S | N | | | |
| Burp listening on 9876, CLI backends started by Burp | EDR | | N | | | |
| Model traffic from the host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Burp Collaborator lookups from your servers | DNS, EDR | behaviors | behaviors | behaviors | behaviors | |
| Requests an MCP client sends through Burp | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
