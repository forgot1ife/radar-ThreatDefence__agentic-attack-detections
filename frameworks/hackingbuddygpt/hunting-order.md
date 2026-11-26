# Where to start

1. **Check the hosts that may run it** with hunt 01: `wintermute <UseCase>`, `python -m hackingBuddyGPT.cli.wintermute`, `benchmark_privesc.py`, the image `ghcr.io/ipa-lab/hackingbuddygpt`, and tmux `send-keys` with `echo 'CMDSTART<hex>'`. Scan working folders with the YARA rules for `logs/log-*.jsonl` run logs: they hold every command the model ran and its output.
2. **Check your Linux servers** with hunt 02 for one SSH shell that runs `id -u` and `id -un` after every command, and for lse.sh run with `-c -i -l 0`. On a hit, read the account's `~/.bash_history` (and root's) for `__CMDSTART_` and `__CMDEND_` lines with the YARA rule `HackingBuddyGPT_Shell_Markers`, and look for an SSH login from an `AsyncSSH` client (Suricata 3813107) just before.
3. **Check your web and proxy logs** with hunt 03 for `api_key=YourAPIKeyHere`, `access_token=YourAccessToken` and `/products/1/users/profile` from a `python-requests` client. Where HTTP bodies are visible, the Suricata rules add the OTP, SQL injection and XSS test payloads.
4. **Check for model traffic from servers** (behaviors hunt 02), which catches hackingBuddyGPT whatever model it uses.
