# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Shannon CLI, worker container, browser sessions or report renderer on a host | EDR | S | N | | | Y |
| Shannon workspace, deliverables and browser config files | EDR, disk | S | N | | | Y |
| Shannon PDF and Markdown reports | Disk, mail, file shares | | N | | | Y |
| php2shell crash probe against your PHP sites | Network, web, WAF, EDR (operator host) | S | N | N | | |
| Agents' browser user agent (Chrome 124 on Linux, context only) | Web, WAF, proxy | S | N | N | | |
| Shannon scans listed in a Temporal Web UI | Network | | | N | | |
| Model traffic from the Shannon host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Out-of-band lookups from your servers | DNS, EDR | behaviors | behaviors | behaviors | behaviors | |
| Shell and browser requests against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
