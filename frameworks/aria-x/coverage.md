# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| ARIA-X user agent on target requests (`http_request`, `web_probe`) | Web, WAF, proxy | S | N, A | N | | |
| `web_probe` default path list, port scan, TLS probe | Web, firewall | | N (lead) | | | |
| Shell tools the model runs (curl, nmap, sqlmap, msfconsole) | Web, EDR | behaviors | behaviors | behaviors | | |
| Engine, console and sandbox command lines (`python -m aria_x`, `aria-x run`, `docker run ... --name aria-x-<hex>`, `bash -lc` children) | EDR | S | N | | | |
| Database, run evidence, reports, configuration and temp folders | EDR, disk | S | N | | I | Y |
| Console page, Server header, API realm and configuration answering | Network | | | N | | Y |
| Engagement created and run started through the API | Network, proxy | S | N | N | | |
| Research search to html.duckduckgo.com with the ARIA-X user agent | Proxy with TLS inspection | S | N | | | |
| Model traffic to api.deepseek.com and other model APIs | Proxy, DNS | | N (watchlist, low) | | I | |
| Exposed console | Internet scan | | | N | | |

S = Sigma rule here, N = hunting query or Suricata rule here, A = analytics rule here, I = Zeek intel from the indicator CSV, Y = YARA rule here, behaviors = cross-framework rules in `behaviors/`.
