# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| hackingBuddyGPT CLI, benchmark launcher or container on a host | EDR | S | N, A | | | Y |
| Local shell mode: tmux send-keys with command markers | EDR (Linux) | S | N | | | Y |
| Run logs, web-API report and generated spec, benchmark traces | EDR, disk | S | N | | | Y |
| Shell framing on a Linux target (markers in history, id -u / id -un after each command) | EDR (Linux), disk | | N | | | Y |
| lse.sh download and run on a Linux target | EDR (Linux) | S | N | | | |
| SSH login from asyncssh | Network | | | N | | |
| Web-API discovery values and joined path | Web, WAF, proxy | S | N | N | | |
| Web-API test payloads (OTP guesses, SQL injection with x field, XSS2) | Network (cleartext or decrypted HTTP) | | | N | | |
| Windows privilege escalation over psexec | EDR, Windows events | behaviors | behaviors | | | |
| Model traffic from the operator host | Proxy, TLS | behaviors | behaviors | | behaviors | |

S = Sigma rule, N = hunting query or Suricata rule, A = analytics rule, Y = YARA rule.
