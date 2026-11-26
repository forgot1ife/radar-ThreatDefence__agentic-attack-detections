# Where to start

1. **Run the HexStrike hunts first.** Hexstrike-redteam keeps every HexStrike string, so HexStrike's user agent, probe, server-on-a-host and assistant-wiring hunts find it testing you or running on your hosts.
2. **Check your own hosts** with hunt 01 (and the analytics rule): `Boaz.py` from a `BOAZ_beta` folder under `hexstrike_server.py`, payloads in `BOAZ_beta/output/`, and the install scripts. A build means someone is preparing a Windows payload meant to get past antivirus and EDR; find the input file in `BOAZ_beta/` and where the output went.
3. **Search web, proxy and network logs** with hunt 03 for `/api/boaz/` requests. Requests from an address that does not belong to the operator mean someone else is using an exposed server, which also gives them a shell through `/api/command`.
4. **Look for exposed servers** with the HexStrike rows in `exposure/shodan-queries.csv`; nothing on `/` or `/health` separates this fork from HexStrike. On your own network, Suricata 3817901 to 3817915 tell them apart.
