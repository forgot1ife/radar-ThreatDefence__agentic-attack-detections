# Where to start

1. **Search web, WAF and proxy logs for a user agent containing `blitzstrike`** (hunt 03, the analytics rule). `run_engagement` sends `blitzstrike/1.0` 27 times by default, with a `BS<base36 time><random>` value in `q`, `search`, `query`, `s`, `id`, `url`, `redirect`, `name` and `page`.
2. **Search the query strings for its fixed markers** (hunt 03): `evil-blitz.example.com`, `blitzstrike-ssrf-canary`, `X-BlitzStrike`, `bs-nonexistent-`, `__blitz_xss__`, `zzblitz`, and `bs-marker.example.com` as the host. These come from the same run and from single tools, and they carry the runtime's user agent (`node`), not a Blitz Strike one. Group by source address to see the whole run.
3. **Check whether one of your servers requested `http://httpbin.org/anything/blitzstrike-ssrf-canary`** (proxy Sigma rule, Suricata 3819006). That means the SSRF probe worked: fix the parameter the request before it carried.
4. **Check your servers for out-of-band lookups and callbacks** (general hunt 05). With `interactsh-client` installed Blitz Strike uses its public servers; otherwise your server calls an address and random port that answers `oob-ok` (Suricata 3819015).
5. **Check your own hosts** for `blitzstrike serve --mcp` under an AI coding client, the tools it starts, `~/.blitzstrike/` and the OpenCode personas (hunt 01), and scan with the YARA rules.
