/*
   Agentic attack detections by ThreatDefence: MCP for Security
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from cyproxio/mcp-for-security at 51dd537f. The wrappers are TypeScript compiled with tsc, so
   the same strings are in src/*.ts and in the committed or locally built build/*.js. Tested against synthetic samples
   built from those strings (no matches on the near misses) and against the repository's text files at that commit.
   The amass, arjun, crt.sh, ffuf, sqlmap and wpscan wrappers have no string distinctive enough and are not matched.
*/

rule MCPForSecurity_Tool_Wrapper
{
    meta:
        description = "MCP for Security tool wrapper (src/index.ts or build/index.js of one of its 23 stdio MCP servers), which lets an AI assistant run nmap, masscan, nuclei, commix, smuggler, ScoutSuite, gowitness and other tools"
        mitre_att = "T1588.002,T1046,T1595.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/cyproxio/mcp-for-security"
        confidence = "high"
    strings:
        $id_nmap_typo = "Run nmap with specified taget" ascii
        $id_masscan = "Run masscan with specified target MASSCAN is a fast port scanner." ascii
        $id_commix = "Usage: commix-mcp [python path] [commix.py path]" ascii
        $id_smuggler = "Usage: smuggler-mcp [python path] [smuggler.py path]" ascii
        $id_mobsf = "Usage: mobfs <baseUrl> <apiKey>" ascii
        $id_shuffledns = "Usage: shuffledns-mcp <shuffledns binary> <massdns binary>" ascii
        $id_gowitness = "Enhanced gowitness MCP Server running on stdio" ascii
        $id_headers = "Perform security analysis of HTTP response headers for a web application." ascii
        $id_scout = "\"aws\", \"--force\", \"--no-browser\"" ascii
        $id_alterx = "Execute Alterx, a tool that generates domain wordlists using pattern-based permutations" ascii
        $id_cero = "Execute Cero, a high-performance certificate-based subdomain enumeration tool." ascii
        $id_sslscan = "Execute SSLScan, a comprehensive SSL/TLS scanner" ascii
        $id_wayback = "Execute Waybackurls, a tool that fetches known URLs from the Wayback Machine archive" ascii
        $sdk = "StdioServerTransport" ascii
        $usage = /Usage: [a-z]{3,12}(-mcp)? <[a-z]{3,12} binary/ ascii
        $silent = "\"-silent\"" ascii
        $nuclei_tags = "nuclei-templates/refs/heads/main/TEMPLATES-STATS.json" ascii
    condition:
        filesize < 200KB and (any of ($id_*) or ($sdk and $usage and ($silent or $nuclei_tags)))
}

rule MCPForSecurity_MobSF_Client
{
    meta:
        description = "MCP for Security MobSF client (mobsf-mcp src/mobsf.ts or build/mobsf.js): axios requests that send the MobSF API key in both Authorization and X-Mobsf-Api-Key"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/cyproxio/mcp-for-security"
        confidence = "medium"
    strings:
        $auth = "'Authorization': this.apiKey" ascii
        $key = "'X-Mobsf-Api-Key': this.apiKey" ascii
        $upload = "/api/v1/upload" ascii
        $report = "/api/v1/report_json" ascii
    condition:
        filesize < 100KB and $auth and $key and ($upload or $report)
}

rule MCPForSecurity_Setup_And_Config
{
    meta:
        description = "MCP for Security setup files: start.sh, a wrapper's build.sh, the Dockerfile, or the mcp-config.json they generate (node <dir>/<tool>-mcp/build/index.js entries with dockerContainer)"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/cyproxio/mcp-for-security"
        confidence = "high"
    strings:
        $jq = "with_entries(.value += {dockerContainer: \"\"})" ascii
        $cfg = "CONFIG_FILE=\"$SERVICE_PATH/../mcp-config.json\"" ascii
        $mgr = "npm install -g @cyproxio/mcp-manager" ascii
        $image = "cyprox/mcp-for-security" ascii
        $docker_container = "\"dockerContainer\": \"\"" ascii
        $wrapper = /\/[a-z-]{4,30}-mcp\/build\/index\.js/ ascii
    condition:
        filesize < 256KB and ($jq or $cfg or $mgr or $image or ($docker_container and $wrapper))
}
