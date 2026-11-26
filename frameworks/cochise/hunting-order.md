# Where to start

Cochise has no console to find on the internet and sends nothing fixed to a target, so start on the hosts you monitor.

1. **Look for `/osint_users.txt` in command lines.** `nxc`, `netexec` or impacket commands that read a user list from the root of the file system, run as `root` from an SSH session, are the Cochise scenario prompt at work (hunt 01, the analytics rule, Sigma `proc_creation_lnx_cochise_osint_userlist`).
2. **Look for the run log.** A Python process writing `logs/run-<YYYYmmdd-HHMMSS>.json`, or a `cochise` / `cochise-replay` process, marks the host that runs the agent (hunt 01). Scan that folder with the YARA rules: the log holds every command and every credential the run found.
3. **Look at the Kali side.** Many AD attack tools in an hour started by `sshd` without a terminal, from one source address that logged in once with a password, is the Executor loop (hunt 01, hunt 02).
4. **Check the SSH banner.** `SSH-2.0-AsyncSSH_` from an internal host to an internal SSH server (Suricata 3813107, the shared asyncssh rule in the hackingBuddyGPT folder, on port 22, or sshd at `LogLevel DEBUG`) narrows it down; on its own it is any asyncssh client.
5. **Check for model traffic from servers** (behaviors hunt 02). A Python process that talks to `openrouter.ai` and holds an SSH session at the same time is the shape of Cochise (hunt 02).
