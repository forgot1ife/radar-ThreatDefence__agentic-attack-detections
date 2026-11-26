# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| AD attack commands reading `/osint_users.txt` on the Kali VM | EDR, auditd on the VM | S | N, analytics | | | |
| Burst of AD attack tools run by `sshd` exec sessions with no PTY | EDR on the VM | | N | | | |
| Launcher `uv run cochise`, `<venv>/bin/cochise`, `python src/cochise.py`, `cochise-replay` | EDR | S | N | | | |
| Run log `logs/run-<YYYYmmdd-HHMMSS>.json` written by Python | EDR, disk | S | N | | | Y |
| Run log contents (commands, outputs, credentials) | Disk | | | | | Y |
| Clone of the repository and the scenario prompt | Disk | | N | | | Y |
| asyncssh client banner `SSH-2.0-AsyncSSH_` to an internal SSH server | Network, sshd debug log | | N | S | | |
| One Python process talking to OpenRouter and holding an SSH session | EDR network events | | N | | | |
| Model traffic from the Cochise host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| `ntpdate` from the attack VM to a DC, then Kerberos attacks | Network, DC logs | | | | | |
| Exposed console | none: Cochise has no web UI or API | | | | | |
