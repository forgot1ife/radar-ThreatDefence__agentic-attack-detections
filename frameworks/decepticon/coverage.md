# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Decepticon installed, launcher run, images pulled or containers started | EDR | S | N | | | Y |
| Sandbox daemon, tmux completion hook, web and browser runners, LangGraph server | EDR with container visibility | S | N | | | Y |
| Session logs, install folder, scope files, Sliver and Havoc configs | EDR, disk | S | N | | | Y |
| Decepticon usage telemetry | DNS, TLS, proxy, EDR | S | N | N | I | Y |
| Passive discovery on crt.sh, sandbox transport, ChatGPT gateway user agent | Proxy with TLS inspection, network | S | N | N | | |
| Exposed web console (removed build), sandbox daemon, LangGraph routes | Network, proxy, web | S | N | N | behaviors | |
| Web fetch engine headers, unfilled user agent templates, `Decepticon/` token | Web, WAF, proxy | S | N | N | | |
| Phishing lure engagement header | SMTP | | | N | | |
| Console addresses from exposure snapshots | Firewall, proxy, sign-in | | N | N (generated) | I | |
| Model traffic from the Decepticon host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Kali tools and out-of-band lookups against your sites | Web, WAF, DNS | behaviors | behaviors | behaviors | behaviors | |
| Basic auth realm naming Decepticon | Network | | | behaviors (3801043) | behaviors | |

S = Sigma rule, N = network or Sentinel rule or hunt, I = Zeek intel, Y = YARA rule.
