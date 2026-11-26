# Where to start

1. **Search web and WAF logs for its payload markers** (hunt 03). `XSS-BURP-AI-1337` is in every reflected XSS payload and reflected XSS is tested on every insertion point, so an active scan with this extension almost always leaves it. `burp-ai-test` and `evil-burp-ai` add the header, CRLF, OAuth and cache tests.
2. **Check your servers for lookups of the test domains.** A server that resolves or fetches `evil-burp-ai.com`, `evil-burp-ai-test.com` or `evil-burp-ai-cache.com` followed a payload: find the request that carried it.
3. **Check your servers for Burp Collaborator lookups** (behaviors hunt 09). The extension uses Collaborator when the operator turns it on.
4. **Look for an exposed MCP server.** A certificate with subject and issuer `CN=burp-mcp` on any port means someone turned on external access to Burp through MCP. Anyone with its token can drive that Burp.
5. **Check your own hosts** for the extension JAR, `~/.burp-ai-agent/`, the `keytool ... CN=burp-mcp` command and Burp listening on 9876 (hunt 01), and scan with the YARA rules.
