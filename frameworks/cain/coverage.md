# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| `cain-agent run --target` on a host or in Docker | EDR | S | A, N | | | |
| pi backend bridge and the shell commands it runs | EDR | S | A, N | | | |
| Workspace stage files (`recon-output.txt`, `gate.json`, `test-output.txt`, reports) | EDR, disk | S | N | | | Y |
| `scope.yaml` and reports with Cain's header and title | Disk | | | | | Y |
| Source tree, Docker image layer, model session transcript | Disk | | | | | Y |
| XSS echo marker `cainxss7f3a` against your sites | Web, WAF, proxy, network | S | N | N | | |
| `csrf_test_<timestamp>` marker | Web, proxy | | N | | | |
| Prompts in model requests | AI gateway, TLS inspection, plain-HTTP gateways | | | N | | |
| Model traffic from the host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Tools its model runs against your sites (curl, nuclei, sqlmap, nmap) | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |

S = Sigma rule, A = analytics rule, N = hunting query, Y = YARA rule.
