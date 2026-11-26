/*
   Agentic attack detections by ThreatDefence: Blitz Strike
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings are from the Blitz Strike source at 9d7a6ecb (shinthink/blitzstrike). They are also in the
   bundled npm package (dist/index.js) and the compiled binary (bun build --compile), which carry the same source text.
*/

rule BlitzStrike_Source_Or_Package
{
    meta:
        description = "Blitz Strike MCP server source, npm bundle or compiled binary: its probe markers and user agents"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/shinthink/blitzstrike"
        confidence = "high"
    strings:
        $pollution = "blitzstrike_pollution_canary_9f3a" ascii
        $ssrf = "blitzstrike-ssrf-canary" ascii
        $crlf = "X-BlitzStrike%3A%20injected" ascii
        $redirect = "evil-blitz.example.com" ascii
        $host = "bs-marker.example.com" ascii
        $xss = "__blitz_xss__" ascii
        $control = "/bs-nonexistent-" ascii
        $ua1 = "Mozilla/5.0 (blitzstrike " ascii
        $ua2 = "Mozilla/5.0 (compatible; BlitzStrike/" ascii
        $home = "BLITZSTRIKE_HOME" ascii
    condition:
        filesize < 150MB and 2 of them
}

rule BlitzStrike_Report_Or_Log
{
    meta:
        description = "Report, SARIF file or audit log written by Blitz Strike"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/shinthink/blitzstrike"
        confidence = "medium"
    strings:
        $report1 = "Blitz Strike \xE2\x80\x94 Security Assessment Report" ascii
        $report2 = "Blitz Strike \xE2\x80\x94 Engagement Report (" ascii
        $report3 = "Blitz Strike \xE2\x80\x94 Live Engagement (" ascii
        $version = "- **Blitz Strike version:** " ascii
        $sarif = /"informationUri":\s{0,4}"https:\/\/github\.com\/shinthink\/blitzstrike"/
        $audit = /"event":"(tool_started|tool_finished|finding_created|finding_updated|evidence_created|validation_started|validation_finished)","actor":"[^"]{1,40}","tool":"blitzstrike"/
    condition:
        filesize < 50MB and any of them
}
