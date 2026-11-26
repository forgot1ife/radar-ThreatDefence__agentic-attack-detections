# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Attackbox setup command (`kali-linux-headless sshpass curl`, OverTheWire `ssh-keyscan`) | EDR (container processes) | S | N, analytics | | | |
| Launcher `run_bench.py -b ... -c ...` | EDR | S | N | | | |
| Command wrapper `timeout 10s /bin/bash -c` from the container runtime | EDR (container processes) | S | N | | | |
| Clone of the repository on disk | EDR, disk | | N | | | Y |
| Run configurations with the HackSynth prompts | Disk | | | | | Y |
| `kali-linux-headless` package download over plain HTTP | Proxy, network | S | N | N | | |
| One short SSH password login per step on a target | Target syslog | | N | | | |
| Model traffic from the HackSynth host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Kali tools against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
| Exposed console | none: HackSynth has no web UI or API | | | | | |
