/*
   Agentic attack detections by ThreatDefence: Custom AI Agent (six2dez/burp-ai-agent, formerly Burp AI Agent)
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from the repository at b1738c0e (October 21, 2026, version 1.1.0).
*/

rule BurpAiAgent_Extension_Jar
{
    meta:
        description = "Custom AI Agent Burp extension JAR (full or BApp Store build): zip entries under com/six2dez/burp/aiagent/, which the build does not relocate"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/six2dez/burp-ai-agent"
        confidence = "high"
    strings:
        $pkg = "com/six2dez/burp/aiagent/" ascii
        $scanner = "com/six2dez/burp/aiagent/scanner/PayloadGenerator" ascii
        $mcp = "com/six2dez/burp/aiagent/mcp/KtorMcpServerManager" ascii
        $ext = "com/six2dez/burp/aiagent/BurpAiAgentExtension" ascii
    condition:
        uint32(0) == 0x04034b50 and filesize < 200MB and $pkg and 1 of ($scanner, $mcp, $ext)
}

rule BurpAiAgent_Source_Or_Classes
{
    meta:
        description = "Custom AI Agent source or unpacked classes: its payload markers, MCP identity header, takeover proof header and message prefix, CLI marker variable and MCP client name"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/six2dez/burp-ai-agent"
        confidence = "medium"
    strings:
        $xss = "XSS-BURP-AI-1337" ascii
        $dom = "DOM-XSS-BURP-AI" ascii
        $cache = "evil-burp-ai-cache.com" ascii
        $hdr = "X-Burp-AI-Agent" ascii
        $proof = "X-Mcp-Takeover-Proof" ascii
        $prefix = "burp-ai-agent/mcp-takeover|v1|" ascii
        $env = "BURP_AI_AGENT_EMBEDDED" ascii
        $client = "burp-ai-agent-ext" ascii
    condition:
        filesize < 50MB and 2 of them
}
