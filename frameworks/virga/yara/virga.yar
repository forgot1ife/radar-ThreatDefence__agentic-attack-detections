/*
   Agentic attack detections by ThreatDefence: Virga
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from r74tech/virga at 43773ffe. Tested for syntax and against synthetic files; the implant
   source was not reviewed, so the beacon rules rest on what the generator builds, not on the implant's own strings.
*/

rule Virga_Server_CLI_Or_Source
{
    meta:
        description = "Virga C2 server, operator CLI, MCP stdio server or their source: MCP server name, listener decoy page, default key, generator temp folder"
        mitre_att = "T1587.001,T1071.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/r74tech/virga"
        confidence = "high"
    strings:
        $mcp = "Virga MCP Server" ascii
        $start = "Virga C2 Server started" ascii
        $pkg_server = "github.com/r74tech/virga/internal/server" ascii
        $pkg_cli = "github.com/r74tech/virga/internal/cli" ascii
        $gen = "virga-generator-" ascii
        $ldflag = "internal/implant/config.BuildC2Host" ascii
        $key = "change-this-key-in-production-environment" ascii
        $decoy = "<html><body><h1>404 - Page Not Found</h1></body></html>" ascii
    condition:
        filesize < 200MB and ($mcp or $start or $pkg_server or $pkg_cli or $gen or $ldflag or ($key and $decoy))
}

rule Virga_Beacon_Go_Binary
{
    meta:
        description = "Go executable built from Virga's implant packages (function names keep the package path even with -s -w)"
        mitre_att = "T1071.001,T1573.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/r74tech/virga"
        confidence = "high"
    strings:
        $pkg = "github.com/r74tech/virga/internal/implant/" ascii
    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe) and $pkg
}

rule Virga_Beacon_With_Appended_GGUF_Model
{
    meta:
        description = "Executable with a GGUF model appended and its size as a little-endian uint64 in the last 8 bytes, the layout Virga's generator writes for a beacon with a local model (internal/cli/generator/binary.go:394-407). Checks models under 4 GB; scanners that skip files over a size limit will not see these beacons (about 2.5 GB with the default model)"
        mitre_att = "T1587.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/r74tech/virga"
        confidence = "medium"
    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe)
        and filesize > 1048576
        and uint32(filesize - 4) == 0
        and uint32(filesize - 8) > 1024
        and uint32(filesize - 8) < filesize - 8
        and uint32(filesize - 8 - uint32(filesize - 8)) == 0x46554747
}

rule Virga_Config_Files
{
    meta:
        description = "Virga server.yaml (listener with uri_path and MCP sse/streamable ports) or beacon.yaml (c2 block with the model's autonomous task prompts)"
        mitre_att = "T1587.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/r74tech/virga"
        confidence = "medium"
    strings:
        $s1 = "sse_base_path:" ascii
        $s2 = "streamable_port:" ascii
        $s3 = "uri_path:" ascii
        $s4 = "anti_etw:" ascii
        $b1 = "[TASK_COMPLETE]" ascii
        $b2 = "amsi_bypass:" ascii
        $b3 = "system_reconnaissance" ascii
        $b4 = "uri_path:" ascii
    condition:
        filesize < 1MB and (all of ($s*) or all of ($b*))
}
