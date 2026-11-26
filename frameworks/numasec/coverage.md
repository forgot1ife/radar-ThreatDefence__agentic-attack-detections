# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| AppSec probe: user agent, XSS marker, login probe | Web, WAF, proxy | S | N | N | | |
| Directory fuzzer baseline path | Web, WAF, proxy | S | N | N | | |
| Service prober `Host: target` request | Web, network | S | N | N | | |
| Page fetch `numasec` user agent | Web, proxy | S | N | N | I | |
| Knowledge broker and model-call user agents from the operator's host | Proxy (TLS inspection) | S | N | | I | |
| numasec binary, install or container on a host | EDR | S | N | | | Y |
| API server bound to all interfaces | EDR | S | N | | | |
| API server answers (`/path`, `/agent`) and client header | Network | | | N | | |
| Operation folders, database, replay exports, out-of-band sessions | EDR, disk | S | N | | | Y |
| Exposed API server on the internet | Exposure search | | | | | |
| Kali-style tools the model runs, out-of-band lookups, model traffic from servers | Web, DNS, proxy | behaviors | behaviors | behaviors | behaviors | |
