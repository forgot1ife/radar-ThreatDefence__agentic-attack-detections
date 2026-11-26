# Where to start

1. **Look for Strix telemetry.** DNS or TLS to `strix.gateway.scarf.sh` from any machine you own means Strix ran there. It is on by default, so most operators leave it on.
2. **Sweep the Gambit campaign indicators** with the watchlist hunt. If you run an online store, also run the Cairn hunts: Strix found the flaws and Cairn exploited them.
3. **Check your servers for out-of-band lookups** (general hunt 05). A server resolving `*.oast.fun` or a similar name ran a payload.
4. **Check for model traffic from servers** (behaviors hunt 02), which catches Strix whatever model it runs on.
5. **Check your own hosts** for the Strix CLI, sandbox container and `strix_runs` folders, and scan with the YARA rules.
