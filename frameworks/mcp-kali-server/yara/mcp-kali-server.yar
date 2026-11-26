/*
   Agentic attack detections by ThreatDefence: MCP Kali Server
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from Wh0am123/MCP-Kali-Server at 00154c05 and from the Kali packaging
   (gitlab.com/kalilinux/packages/mcp-kali-server at 15136e98). Tested against synthetic samples built from those strings
   (no matches on the near misses), not against a full checkout of the repository.
*/

rule MCPKaliServer_API_Server
{
    meta:
        description = "MCP Kali Server API server (server.py, or /usr/share/mcp-kali-server/server.py from the Kali package): an unauthenticated Flask API that runs any command and ten Kali tools"
        mitre_att = "T1588.002,T1059.004"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Wh0am123/MCP-Kali-Server"
        confidence = "high"
    strings:
        $health = "Kali Linux Tools API Server is running" ascii
        $start = "Starting Kali Linux Tools API Server on" ascii
        $rc = "/tmp/mks_msf_resource.rc" ascii
        $argp = "Run the Kali Linux API Server" ascii
        $route1 = "@app.route(\"/api/command\", methods=[\"POST\"])" ascii
        $route2 = "@app.route(\"/mcp/tools/kali_tools/<tool_name>\", methods=[\"POST\"])" ascii
    condition:
        filesize < 1MB and 2 of them
}

rule MCPKaliServer_MCP_Client
{
    meta:
        description = "MCP Kali Server MCP client (client.py, or /usr/share/mcp-kali-server/client.py): a FastMCP stdio server named kali_mcp that forwards tool calls to the API server"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Wh0am123/MCP-Kali-Server"
        confidence = "high"
    strings:
        $name = "FastMCP(\"kali_mcp\"" ascii
        $class = "class KaliToolsClient" ascii
        $desc = "Execute an arbitrary command on the Kali server." ascii
        $argp = "Run the MCP Kali client" ascii
        $log = "Starting MCP Kali server" ascii
    condition:
        filesize < 1MB and 2 of them
}

rule MCPKaliServer_Kali_Package_Units
{
    meta:
        description = "systemd units, defaults or wrapper scripts of the Kali package mcp-kali-server (kali-server-mcp.service, mcp-server.service, /usr/bin/kali-server-mcp, /usr/bin/mcp-server)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://gitlab.com/kalilinux/packages/mcp-kali-server"
        confidence = "high"
    strings:
        $api_desc = "Description=Kali Linux MCP API Server" ascii
        $bridge_desc = "Description=Kali Linux MCP Bridge" ascii
        $api_exec = "ExecStart=/usr/bin/kali-server-mcp" ascii
        $bridge_exec = "ExecStart=/usr/bin/mcp-server --server" ascii
        $wrapper = "cd /usr/share/mcp-kali-server/" ascii
        $default = "# Defaults for kali-server-mcp (API Server)" ascii
    condition:
        filesize < 64KB and any of them
}
