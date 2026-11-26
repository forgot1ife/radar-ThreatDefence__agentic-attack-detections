# Where to start

1. **Search your web, proxy and sign-in logs** for NyxStrike's user agents and probes with hunt 03 (and the analytics rule). `NyxStrike/1.0`, `Security-HTTP-Framework/` and `Security-BrowserAgent/` are code defaults, so a hit is close to certain. Also run the HexStrike hunts: NyxStrike's generated exploits keep HexStrike's user agent.
2. **Run the cross-framework hunts** in `behaviors/` against your internet-facing applications. Most of NyxStrike's scanning is stock tools.
3. **Check your own hosts** with hunt 01: the server, the MCP client under an AI assistant, the `which` burst and `.nyxstrike_data/`. A NyxStrike server reachable without a token lets anyone run commands on it.
4. **Look for exposed servers** with the Shodan queries in `exposure/shodan-queries.csv` (title `NyxStrike`, icon hash `-1255721562`, and the 401 text of a token-protected server).
