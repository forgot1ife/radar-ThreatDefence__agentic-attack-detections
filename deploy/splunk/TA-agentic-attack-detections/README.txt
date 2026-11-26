Agentic Attack Detections for Splunk, version 2.11.1

https://github.com/ThreatDefence/agentic-attack-detections

272 saved searches, all disabled, and the Agentic Attack Activity dashboard.

Searches per framework:
  ARTEX: 46
  CyberStrikeAI: 7
  PentAGI: 3
  Cairn: 3
  Hermes Agent: 3
  Strix: 3
  HexStrike: 3
  Agent Zero: 1
  RedAmon: 3
  Xalgorix: 3
  Pentest Swarm AI: 3
  Shannon: 3
  PentestGPT: 3
  Cyber-AutoAgent: 8
  CAI: 6
  HackSynth: 4
  VulnBot: 3
  AutoPT: 4
  PentestAgent (paper): 3
  PentestAgent (GH05TCREW): 3
  Dark Moon: 4
  Decepticon: 6
  sapper-v2: 3
  NyxStrike: 4
  NeuroSploit: 9
  H-Pentest: 3
  Hexstrike-redteam: 4
  Vigilo: 4
  CHYing-agent: 3
  Incalmo: 5
  Pentest Copilot: 4
  Virga: 4
  pentest-ai: 5
  cyber-harness: 4
  LazyOwn: 5
  MCP Kali Server: 5
  ARIA-X: 4
  Mitsu: 7
  Custom AI Agent (burp-ai-agent): 5
  RAPTOR: 4
  Blitz Strike: 5
  Nebula: 5
  Clearwing: 5
  BreachWeave: 5
  numasec: 5
  Pentest Harness: 4
  Agentic Bug Hunter: 6
  0security: 7
  Sage (Mythic): 7
  PentestCode: 6
  Shared behaviors: 6
  Indicator searches: 4 (addresses, domains, file hashes, user agents)

Lookups: aad_indicators.csv has all 1515 rows of iocs/indicators.csv. aad_ioc_ip, aad_ioc_domain,
aad_ioc_hash and aad_ioc_user_agent hold the rows the indicator searches match on.

Set up:
  1. Install the app (Apps > Manage Apps > Install app from file).
  2. Settings > Advanced search > Search macros: point aad_indexes at your indexes. The data source macros
     (aad_process, aad_file, aad_registry, aad_dns, aad_proxy, aad_web, aad_aws_cloudtrail, aad_azure_*,
     aad_okta) use CIM tags and sourcetypes; change one if your data is tagged differently.
  3. Run a search over 30 days to baseline it, then enable it.
  4. Enabled searches write their results to the summary index; the dashboard reads them from there.
