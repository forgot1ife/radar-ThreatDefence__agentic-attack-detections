# Where to start

1. **Sweep the indicators** from August 1, 2026, the earliest malicious use GTIG reports. The console addresses are leads, not verdicts.
2. **Check your applications.** Run the twice-fetched page hunt and the cross-framework toolchain and proxy hunts in `behaviors/` against your internet-facing applications.
3. **Check for callbacks.** Run `general/sentinel/hunting/04-server-calls-back-to-the-address-that-probed-it.kql`. A server connecting out to TCP 28000 to 29999 on an address that was probing it is the moment a probe became a shell.
4. **Check your own hosts.** Run the host hunt and the update check analytics rule. A PentAGI installation on your network calls update.pentagi.com every three hours and wraps every agent command in the same shell line.
