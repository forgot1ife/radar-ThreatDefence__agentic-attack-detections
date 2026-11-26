/*
   Agentic attack detections by ThreatDefence: Hexstrike-redteam
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the Hexstrike-redteam source code (Yenn503/Hexstrike-redteam at 89779b7), tested against
   its server, MCP client, BOAZ integration module and install scripts. The HexStrike rules in
   frameworks/hexstrike/yara also match this fork's hexstrike_server.py and hexstrike_mcp.py.
*/

rule HexStrike_RedTeam_BOAZ_Integration
{
    meta:
        description = "Hexstrike-redteam server, MCP client or BOAZ integration module: the code that lets an AI assistant build BOAZ evasive payloads through HexStrike"
        mitre_att = "T1587.001, T1027.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Yenn503/Hexstrike-redteam"
        confidence = "high"
    strings:
        $r1 = "/api/boaz/generate-payload" ascii
        $r2 = "api/boaz/list-loaders" ascii
        $r3 = "/api/boaz/analyze-binary" ascii
        $r4 = "/api/boaz/validate-options" ascii
        $m1 = "BOAZ Manager - Integration layer for BOAZ evasion framework" ascii
        $m2 = "BOAZ tools will not be available until BOAZ_PATH is configured" ascii
        $m3 = "BOAZ framework not found at " ascii
        $m4 = "BOAZ RED TEAM PAYLOAD GENERATION ENDPOINTS" ascii
        $m5 = "BOAZ PAYLOAD EVASION FRAMEWORK (5 TOOLS)" ascii
        $m6 = "boaz_manager = BOAZManager()" ascii
    condition:
        filesize < 5MB and 2 of them
}

rule HexStrike_RedTeam_MCP_Client_Config
{
    meta:
        description = "MCP client configuration (Claude Desktop, Claude CLI and similar) written by Hexstrike-redteam's configure_mcp.sh or copied from its example, wiring an assistant to a HexStrike server with BOAZ tools"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Yenn503/Hexstrike-redteam"
        confidence = "high"
    strings:
        $m = "mcpServers" ascii
        $h = "hexstrike_mcp.py" ascii
        $b1 = "BOAZ Red Team Payload Evasion" ascii
        $b2 = "BOAZ Red Team Integration" ascii
    condition:
        filesize < 256KB and $m and $h and 1 of ($b*)
}

rule HexStrike_RedTeam_Install_Scripts
{
    meta:
        description = "Hexstrike-redteam install scripts that set up the HexStrike venv, the BOAZ toolchain (MinGW, Wine, osslsigncode, Akira and Pluto LLVM) and the MCP configuration"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Yenn503/Hexstrike-redteam"
        confidence = "medium"
    strings:
        $a1 = "Installing BOAZ Mandatory System Dependencies" ascii
        $a2 = "BOAZ mandatory system dependencies (MinGW, Wine, compilers)" ascii
        $a3 = "IMPORTANT: BOAZ System Dependencies" ascii
        $a4 = "Configuring MCP for Hexstrike Red Team" ascii
        $a5 = "Hexstrike Red Team - Start MCP Server" ascii
    condition:
        filesize < 256KB and 1 of them
}
