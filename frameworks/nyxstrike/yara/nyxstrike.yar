/*
   Agentic attack detections by ThreatDefence: NyxStrike
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the NyxStrike source code (CommonHuman-Lab/nyxstrike at 3ac7449), tested against the
   NyxStrike source tree, the CommonHuman-Lab scanner packages it installs, and the HexStrike source tree (no match).
   HexStrike_Generated_Exploit in frameworks/hexstrike also matches NyxStrike's exploit generator and its output.
*/

rule NyxStrike_Server_Or_Source
{
    meta:
        description = "NyxStrike server, MCP client or dashboard bundle: its health and ping messages, user agents, update URL, token variable or session storage key"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/CommonHuman-Lab/nyxstrike"
        confidence = "high"
    strings:
        $health = "NyxStrike Tools API Server is operational" ascii
        $ping = "Pong! NyxStrike Tools API Server is responsive" ascii
        $ua_http = "Security-HTTP-Framework/1.0 (Advanced Security Testing)" ascii
        $ua_browser = "Security-BrowserAgent/1.0 (Security Testing)" ascii
        $ua_engine = "\"User-Agent\": \"NyxStrike/1.0\"" ascii
        $update = "CommonHuman-Lab/nyxstrike/master/config.py" ascii
        $token = "NYXSTRIKE_API_TOKEN" ascii
        $storage = "nyxstrike_token" ascii
    condition:
        filesize < 10MB and any of them
}

rule NyxStrike_MCP_Client_Config
{
    meta:
        description = "MCP client configuration (OpenCode, Claude Desktop, Cursor, VS Code and similar) that wires an assistant to a NyxStrike server"
        mitre_att = "T1588.002, T1588.007"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/CommonHuman-Lab/nyxstrike"
        confidence = "high"
    strings:
        $client = "nyxstrike_mcp.py" ascii
        $server = "--server" ascii
        $m1 = "mcpServers" ascii
        $m2 = "\"mcp\"" ascii
        $m3 = "[mcp_servers" ascii
    condition:
        filesize < 256KB and $client and $server and any of ($m*)
}

rule NyxStrike_CommonHuman_Scanner_Packages
{
    meta:
        description = "StingXSS or BreachSQL scanner code (CommonHuman-Lab, installed into nyxstrike-env by NyxStrike): their probe markers and canary hosts"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/CommonHuman-Lab/stingxss"
        confidence = "medium"
    strings:
        $sx1 = "X-StingXSS-Crlf" ascii
        $sx2 = "stingxss-crlf-detected" ascii
        $sx3 = "stingxss-canary.example.com" ascii
        $sx4 = "evil.stingxss-probe.example.com" ascii
        $sx5 = "CONFIRM_MARKER_PREFIX = \"StingXSS_\"" ascii
        $bs1 = "BREACH_MARKER_PREFIX = \"BreachSQL_\"" ascii
    condition:
        filesize < 2MB and any of them
}
