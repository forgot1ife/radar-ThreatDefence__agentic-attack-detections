# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Guardian CLI started with an engagement command | EDR | S | N | | | |
| Scanners and curl started directly by the Guardian process | EDR | S | N | | | |
| Fixed tool command-line values (ffuf fallback wordlist, Prowler output name, dependency-check project) | EDR | S | N | | | |
| Session checkpoint, AI audit log and `~/.guardian/` files | EDR (file events) | S | N | | | |
| Session checkpoint, reports and AI audit log on disk | Disk | | | | | Y |
| Guardian source (clone or local Docker image) | Disk | | | | | Y |
| Screenshot user agent on your web servers | Web, WAF | S | N, analytics | N | | |
| Screenshot user agent from your network | Proxy (TLS inspection for HTTPS) | S | N, analytics | N | | |
| Prompt fuzzer payload against an LLM endpoint | Network sensor in front of the endpoint, or a TLS-terminating proxy | | | N | | |
| OpenRouter and Requesty attribution headers | TLS-inspecting proxy, AI gateway | | | N | | |
| System prompts in model requests | TLS-inspecting proxy, AI gateway, local model server | | | N | | |
| Model traffic from the Guardian host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Scanner traffic against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
| Exposed console | none: Guardian is a CLI with no listener | | | | | |
