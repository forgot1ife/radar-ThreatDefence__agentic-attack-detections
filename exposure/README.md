# Exposed agent consoles

Addresses where Shodan has seen the web console of one of the frameworks in this repository. The list is built from the fingerprints the rules here already use: favicons, page titles, page text that survives a rename, and certificates.

**This is not a detection feed.** Nothing in this folder goes into the Suricata address rules, the WAF lists, the STIX bundle or the plain feeds. Those hold addresses that a named report tied to attacks. An address here means a console was reachable from the internet, and nothing more:

- Researchers, students and security teams run these tools, and some of the listed consoles are decoys. The ones the scan data tags as honeypots are marked; others may not be.
- Hermes Agent and Agent Zero are general-purpose agents. An exposed dashboard is an exposed agent, not an attack console.
- Hosting addresses are reassigned. `last_seen` is the date Shodan last saw the console, and Shodan's index covers about the last 30 days.

Use it to check whether one of your own addresses is on it, to see where consoles are hosted, or as context when an address already has your attention for another reason.

## Files

| File | Contents |
|---|---|
| [`consoles.csv`](consoles.csv) | One row per address and port: `address`, `port`, `framework`, `matched_on` (the fingerprint that found it), `page_title`, `asn`, `country`, `last_seen`, and `honeypot` (`yes` when the scan data tags the service as a honeypot) |
| [`history.csv`](history.csv) | Hosts per framework at each snapshot: `date`, `framework`, `active_hosts` (seen in the seven days to that date), `hosts` (every host in the snapshot) and `honeypots` (hosts left out because every service on them is flagged). The row `all` counts each host once |
| [`shodan-queries.csv`](shodan-queries.csv) | The Shodan searches, in the order they run. A service found by an earlier search is not listed again |
| [`registry-writes.csv`](registry-writes.csv) | Open container registries that list repositories named after ARTEX: where agents pushed test images. Not consoles ([below](#container-registries-that-artex-agents-wrote-to)) |
| [`registry-queries.csv`](registry-queries.csv) | The Shodan search for those registries |
| [`artex-proxy-pool.csv`](artex-proxy-pool.csv) | Services that send the ARTEX proxy pool header `X-Artex-Proxy`. Context, not an indicator feed |

## Snapshot of November 25, 2026

| Framework | Services | Addresses | Flagged as honeypot | Most common ports |
|---|---|---|---|---|
| ARTEX and AntiFox | 3,754 | 3,273 | 0 | 8787, 443, 80 |
| Hermes Agent, port 9119 only | 2,226 | 2,226 | 0 | 9119 |
| CyberStrikeAI | 1,401 | 1,182 | 679 | 8444, 8080, 443 |
| PentAGI | 503 | 493 | 0 | 8443, 8666, 443 |
| AutoCVE | 267 | 256 | 0 | 3000, 8000, 13000 |
| Agent Zero | 184 | 173 | 0 | 5080, 443, 50080 |
| RedAmon | 38 | 38 | 0 | 3000, 443, 80 |
| HexStrike | 35 | 35 | 0 | 8888 |
| Cairn | 33 | 32 | 0 | 8000, 8001, 8090 |
| Vulnerator AI | 21 | 21 | 0 | 9100 |
| Strix | 14 | 13 | 0 | 8080, 443, 7777 |
| Xalgorix | 12 | 12 | 0 | 9137, 443, 8443 |
| CyberStrike | 8 | 8 | 0 | 4096, 7777, 5555 |
| AIDA | 5 | 5 | 0 | 31337, 443, 8443 |
| BugTraceAI | 4 | 3 | 0 | 6869, 8000 |
| Chufeng Agent Core | 4 | 4 | 0 | 8765, 8080 |
| Z3r0 | 4 | 4 | 0 | 8000, 18089 |
| Decepticon | 3 | 3 | 0 | 3000 |
| AIRecon | 2 | 2 | 0 | 8080 |
| LuaN1aoAgent, open-kritt, REDCELL, T3MP3ST, WormXGPT | 1 each | 1 each | 0 | 8787, 80, 80, 3333, 3000 |
| Pentest Swarm AI | 0 | 0 | 0 | |
| All | 8,523 | 7,495 | 679 | |

- A service is one address and port. 679 services carry the scanner's honeypot tag, all pages titled CyberStrikeAI, on 528 addresses. They have `honeypot` set to `yes` and are left out of the host counts in the root README and in `history.csv`.
- Of the 7,844 services that are not flagged, 5,211 were seen in the seven days before the snapshot.
- Fourteen frameworks are new in this snapshot. Each has a folder with what its console and its requests look like and where in its code each signal comes from: [AutoCVE](../frameworks/autocve), [CyberStrike](../frameworks/cyberstrike), [Vulnerator AI](../frameworks/vulnerator-ai), [Decepticon](../frameworks/decepticon), [AIDA](../frameworks/aida), [BugTraceAI](../frameworks/bugtraceai), [Z3r0](../frameworks/z3r0), [AIRecon](../frameworks/airecon), [LuaN1aoAgent](../frameworks/luan1aoagent), [open-kritt](../frameworks/open-kritt), [REDCELL](../frameworks/redcell), [T3MP3ST](../frameworks/t3mp3st), [WormXGPT](../frameworks/wormxgpt) and [Chufeng Agent Core](../frameworks/chufeng). AutoCVE is the largest, with 256 hosts. Chufeng Agent Core has no public code, so its folder is built from what its servers answer.
- One network, AS398823, holds 432 of the services: 236 pages titled CyberStrikeAI on port 8444 and 195 titled PentAGI on port 8666, on addresses that also serve a write-up of PentAGI's prompts. It is not flagged as a honeypot, but it looks like one mass deployment or a set of decoys, not that many operators. Leave it out before quoting a count. See [#21](https://github.com/ThreatDefence/agentic-attack-detections/issues/21).
- 714 ARTEX services were found without the ARTEX favicon: by title, title ending or page text (485), or by the Basic auth realm and proxy header in front of the console (229, see below). Renamed builds include Pojun (破军), whose console is titled only `Console` and is found by its description `Authorized operations console` (22 services), and builds published as their own projects such as FORANG, 月落 and WSARTEX, which have their own searches.
- Renamed builds show up for the newer frameworks too: CyberStrike consoles titled `HiveHack` and `HB-Red-team`, found by their theme script, and a Cairn server titled `Zero`, found by an animation name in its page.
- 58 addresses are also in [`iocs/indicators.csv`](../iocs/indicators.csv), where a named report ties them to attacks.
- Most unflagged services are in the United States (3,037), China (1,036), Hong Kong (839), Germany (464) and Singapore (351).
- Searches that were tried and dropped because they matched other things: the AutoCVE, CyberStrike, AIDA, Z3r0, NeuroSploit and REDCELL favicons (NeuroSploit now has title and page-text searches) and the T3MP3ST settings key (no host on Shodan), and the title `Autonomous Red Team Platform` without the Decepticon icon, which found 7 pages of another product titled `Jed | The Autonomous Red Team Platform`.

### ARTEX behind Basic authentication

A search for `artex` across whole banners found consoles that answer `401 Unauthorized` before any page is shown, so the title and favicon searches never see them.

- 244 services answer with a Basic auth realm that starts with ARTEX: `ARTEX`, `ARTEX Gateway`, `ARTEX Console`, `ARTEX Admin`, `ARTEX Restricted` or `artex`. They are on ports 8787 (the ARTEX default), 443 and 80, which points to nginx Basic auth in front of the console. The ARTEX code has no Basic auth, so the realm is the operator's choice.
- 40 more services, 29 of them on port 8787, answer with the header `X-Artex-Auth: basic` and the realm `Restricted`.
- 229 of these services, on 217 addresses, were not in this list before. They are now in `consoles.csv` as `basic auth realm (probable)` and `auth header X-Artex-Auth`, and Suricata rules 3800042 and 3800084 and the ARTEX Zeek script (`ARTEX::Console_Auth`) match them on your own network. This snapshot holds the 189 realm services and 40 header services that the `artex` search returned; the realm search alone counts 244, so the next full run will add the rest.
- Treat the realm match as probable, not certain: Artex is also an ordinary company name.
- Not consoles: 10 services send `X-Artex-Proxy: artex-0.4.6`, the ARTEX proxy pool, and 6 company hosts send `X-ARTEX-Platform-Control`, a header that asks ARTEX agents not to target them. Neither is in the list.

### Container registries that ARTEX agents wrote to

The same search returns 380 Docker registries, all but one on port 5000, that answer without authentication and list repositories named after ARTEX: `artex-i127739`, `artex-test-133420`, `artex-exploit-i137302`, `artex-rce`, `artex_rce_141840`, `artex-push-probe` and others, next to `csai-push-probe`, `gh0st/…`, `fsociety/…`, `backdoor` and `backdoor-persist`. When an attack agent finds a registry open to pushes it proves it by pushing a small image named after itself, so these are registries that ARTEX agents (and CyberStrikeAI and others) wrote test images to. 364 of them sit on one hosting network (CloudRadium) and list the same repositories, which also fits a decoy fleet built to collect those pushes.

They are not consoles and not attacker infrastructure, so they stay out of `consoles.csv` and out of every indicator feed. They are kept in [`registry-writes.csv`](registry-writes.csv): `address`, `port`, `asn`, `org`, `country`, `last_seen`, `repositories` (space separated, as the registry lists them) and `honeypot`. The search that finds them is in [`registry-queries.csv`](registry-queries.csv). 246 were seen in the seven days to November 25, 2026.

For defenders: list the repositories of your own registries (`GET /v2/_catalog`) and look for these names. The pushes themselves are what the shared rule [`web_container_registry_agent_write_test.yml`](../behaviors/sigma/web/web_container_registry_agent_write_test.yml) and Suricata 3801041 and 3801042 match: a `PUT /v2/<name>/manifests/<tag>` that completes every push. They already match every `artex-` name in the list that carries a probe word (`i<id>`, `test`, `exploit`, `rce`, `push`, `probe`, `poc`, `retest`), and test cases with `artex-rce`, `artex_rce_<id>`, `artex-exploit-i<id>` and `artex-push-probe` were added. Names such as `artex-ui` and `artex-runtime` look like real images and are left alone. Do not add a bare `artex` search to `shodan-queries.csv`: more than half of what it returns is these registries.

### Two more ARTEX headers

- `X-Artex-Proxy: artex-0.4.6` is sent by 10 services on one hosting network (Zillion Network), on ports 80, 443, 8080 and 8888. It belongs to the ARTEX proxy pool that agents send their traffic through, not to a console. They are listed in [`artex-proxy-pool.csv`](artex-proxy-pool.csv) for context, and kept out of the indicator feeds until a report ties them to an intrusion.
- `X-ARTEX-Platform-Control: [ARTEX Platform Control & Non-Target Defense]` is sent by 6 company web servers. It reads as a header that asks ARTEX agents not to target the site. These are defenders, not consoles, and are not listed.

### Plain-word searches

A bare word on Shodan searches the banner: response headers, certificates and registry listings, not the page itself. So plain-word searches for every framework and fork name find what the title and page searches cannot: consoles behind Basic auth and the places agents wrote to. Counts on November 25, 2026 (free count searches with facets; the banners themselves were looked at for `artex` only):

| Word | Hits | What they are |
|---|---|---|
| `artex` | 688 | 380 registries agents wrote to (above), 244 realms that start with ARTEX and 40 `X-Artex-Auth` headers (consoles behind auth, now listed), 10 proxy-pool and 6 platform-control headers, a few consoles that are already listed |
| `cairn` | 87 | 63 Basic auth realms named Cairn (consoles behind auth, now a search), 2 with the `Cairn auto-generated TLS certificate`, Synology NAS boxes named Cairn |
| `cyberstrikeai` | 24 | 14 realms named CyberStrikeAI (now a search), 2 pages titled CyberStrikeAI, 2 of the realm hosts with an `artex.local` certificate |
| `pentagi` | 15 | 8 realms named PentAGI (now a search); the rest are on registry ports (5000, 51000, 55000) and were not checked |
| `cyberstrike` | 13 | 5 realms named CyberStrike on 8080, 80 and 8443 (could be CyberStrike or CyberStrikeAI, so no search), 5 Synology NAS boxes |
| `pojun`, `破军` | 9, 5 | 5 realms named Pojun (now a search), a registry, and 5 HiNet hosts with no page title (unknown) |
| `antifox` | 26 | 3 realms named AntiFox (now a search) and 23 nginx `301` redirects on port 80, all on Alibaba Cloud. The word is somewhere in their headers, most likely the redirect target; their banners were not fetched, so what they point to is still open |
| `decepticon` | 8 | 4 realms named Decepticon (now a search), unrelated sites |
| `hexstrike`, `redamon`, `kritt`, `t3mp3st` | 3, 3, 3, 1 | All realms named after the tool (now searches) |
| `xalgorix` | 2 | A registry and the hosted Xalgorix scanner (`scanner1.xalgorix.com`), not consoles |
| `hermes` | 3,274 | About 1,000 realms that start with Hermes, 91 of them `Hermes Agent` and 30 `Hermes WebUI`, plus model gateways (New API) and unrelated products. Not added: Hermes is counted on its default port only |
| `aida`, `sapper` | 6, 8 | Realms that name other companies and products, not added |
| `月落`, `diting`, `谛听`, `baize`, `白泽`, `z3r0`, `wormgpt` | 5, 3, 1, 11, 7, 5, 1 | Unrelated: NAS boxes, model gateways, other products called BaiZe, a WormGPT sales page |
| `opx`, `luck`, `strix`, `agent-zero` | 12,334, 339, 129, 274 | Common words, mostly unrelated |
| `scopeweaver`, `qisha`, `七杀`, `forang`, `yueluo`, `wsartex`, `aegisloop`, `4zreco`, `"bob research"`, `autocve`, `pentestswarm`, `vulnerator`, `bugtraceai`, `airecon`, `luan1ao`, `luanniao`, `redcell`, `wormxgpt`, `楚锋`, `neurosploit`, `nyxstrike` | 0 | Their names appear only in page titles and bodies, which the title and page searches already cover |

The realm searches are marked probable: the realm is chosen by whoever set up the web server. They are in `shodan-queries.csv`; the services they find are not yet in `consoles.csv`, because fetching them costs query credits and this snapshot was built without any. The next full run adds them. On your own network, Suricata 3801043 and the Zeek behavior `AgenticBehaviors::Agent_Console_Realm` match these realms.

## Rebuild it

```bash
SHODAN_API_KEY=... python3 tools/exposure_snapshot.py --count   # totals only, no query credits
SHODAN_API_KEY=... python3 tools/exposure_snapshot.py           # one query credit per 100 results
python3 tools/exposure_snapshot.py --summary                    # recount from consoles.csv, no key needed
```

Every run that writes `consoles.csv` adds the day's counts to `history.csv` and rewrites the table in the root README.

The searches run against Shodan only. Nothing connects to a listed address.

## What it misses

- Consoles served by host name only, such as the ones behind `sslip.io` names on port 443. Shodan scans addresses, so it does not see them.
- Consoles on ports Shodan has not scanned yet, and consoles that were down when it looked.
- Renamed builds that changed the favicon, the title and the page text.
- Hermes dashboards on ports other than 9119, which are left out on purpose: the stock port keeps the list to default installs.

To add a search, add a row to `shodan-queries.csv` and say in the pull request which fingerprint in the framework's `source-code-signals.md` it comes from.
