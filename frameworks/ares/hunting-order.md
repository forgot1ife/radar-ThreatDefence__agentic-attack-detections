# Where to start

Ares has no console to find on the internet. Its own code leaves fixed names in Active Directory and on SQL Servers, so start with your domain controllers.

1. **Look for `ARES-` machine accounts.** Event 4741 with a target name of `ARES-` plus eight uppercase hex digits and `$` is the account Ares adds for its RBCD chain (hunt 02, the analytics rule, Suricata 3813441). Then look for the same name in 4768 and 4769 to see which hosts it was used against (Suricata 3813442). Also list current computer objects: an account left behind means the operation was killed before teardown.
2. **Look for the GPO probe task.** `ARES_GPO_Probe_` in event 4698, in Defender `ScheduledTaskCreated` events or in a GPO's `ScheduledTasks.xml` means Ares had write access to that GPO (hunt 02, Suricata 3813443). Check which computers the GPO applies to: each one ran `cmd /c whoami` as SYSTEM.
3. **Check SQL Servers with linked servers.** The fixed `-EncodedCommand JABFAHIAcgBv...` under `sqlservr.exe`, `reg save` to `a.hive`, `b.hive` and `c.hive` in TEMP, or `___ARES_HIVE_` in PowerShell script block logs means Ares took the local hashes of that server through a link (hunt 02, Sigma, Suricata 3813444 and 3813445).
4. **On ADCS web enrollment servers,** look for `HEAD /certsrv/certfnsh.asp` with no user agent (hunt 03, Suricata 3813446). It comes before an ESC8 relay; on its own it is a weak signal.
5. **On Linux hosts you run,** look for the attack box itself: `ares-shadow-cred`, `ares-hc-` and `ares-jtr-` sessions, `/tmp/ares-tickets/`, an `ares` process starting impacket and NetExec, and the `ares@` units (hunt 01, Sigma). Scan disks with the YARA rules.
6. **Run the watchlist sweep** (hunt 04) and the cross-framework hunts in `behaviors/` for the attacks themselves.
