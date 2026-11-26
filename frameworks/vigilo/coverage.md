# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Grey-box requests to your sites (user agent, echo header) | Web, WAF, proxy, network | S | N | N | I | |
| Grey-box probes (reflection canary, `.invalid` probe host and origin, soft-404 path, login baseline, callback token, upload boundary, GraphQL and JSON-RPC markers) | Web, WAF, network | S | N | N | | |
| Network-mode identification greeting (`EHLO vigilo.invalid`) | Network, mail server logs | | | N | | |
| White-box preflight (`Vigilo-Preflight/1.0`) | Web, WAF, proxy, network | S | N | N | I | |
| White-box agents after the preflight (curl, Chromium, WhatWeb, schemathesis) | Web, WAF, proxy | behaviors | behaviors | behaviors | | |
| Platform processes, agent CLIs and helper commands | EDR | S | N | | | |
| Run folders, deliverables and Git delivery state | EDR, disk | S | N | | | Y |
| Vigilo source or installed code | Disk | | | | | Y |
| Exposed UI (title and nginx CSP) or API (8080, uvicorn and API CSP) | Network, internet scan | | | N | | |
| Model traffic from the Vigilo host | Proxy, TLS | behaviors | behaviors | | behaviors | |
