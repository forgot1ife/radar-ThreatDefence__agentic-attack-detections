# Where to start

HackSynth has no console to find on the internet and sends nothing fixed to a target, so start on your own hosts.

1. **Look for the attackbox setup.** A process `apt -y install kali-linux-headless sshpass curl`, or `ssh-keyscan -p 2220 bandit.labs.overthewire.org`, inside a container means HackSynth built its Kali attackbox there (hunt 01, the analytics rule). It runs once per container, so look back as far as your data goes.
2. **Look for the command wrapper.** Many `timeout 10s /bin/bash -c ...` processes started by `containerd-shim` or `runc` in a few minutes, each followed by a stock Kali tool, is the agent loop (hunt 01).
3. **Check proxy and IDS logs** for `kali-linux-headless` in a package download URL from a host that should not be building Kali containers (hunt 02, Suricata 3812401).
4. **On SSH servers you expose,** look for one source making many password logins in a row, each session over within about 10 seconds (hunt 02). That is the shape of the OverTheWire prompt, and of many other scripted tools.
5. **Check for model traffic from servers** (behaviors hunt 02), which catches HackSynth whatever model it runs on, and scan code folders with the YARA rules.
