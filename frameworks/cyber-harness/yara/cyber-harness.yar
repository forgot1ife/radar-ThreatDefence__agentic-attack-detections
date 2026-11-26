/*
   Agentic attack detections by ThreatDefence: cyber-harness
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the cyber-harness source code (chainreactors/cyber-harness at 02ac8ecf, and v0.4.0 for the
   AIScan strings), tested against its source files and the other agent code bases in this repository.
   The release binaries for Windows amd64 are UPX-packed: unpack them (upx -d) before scanning, or the strings are not visible.
*/

rule cyber_harness_Binary_Or_Source
{
    meta:
        description = "cyber-harness (cyber-scan, cyber-harness, cyber-audit; formerly AIScan) binary or source: its fetch user agent, system prompt, MCP client name, session cookie derivation, proxy route prefix or Hub paths"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/chainreactors/cyber-harness"
        confidence = "high"
    strings:
        $ua = "(compatible; cyber/1.0; +https://github.com/chainreactors/cyber-harness)" ascii
        $ua_old = "(compatible; aiscan/1.0; +https://github.com/chainreactors/aiscan)" ascii
        $prompt = "You are the agent operating inside Cyber, a Cyber Harness" ascii
        $scanner_prompt = "analysis agent inside Cyber, a Cyber Harness for realistic cybersecurity benchmarks" ascii
        $session = { 63 79 62 65 72 2D 77 65 62 2D 73 65 73 73 69 6F 6E 00 }  // "cyber-web-session\x00" in a Go binary
        $session_src = "cyber-web-session\\x00" ascii                           // the same constant in source
        $route = "cyber-route-" ascii
        $mcp_id = "cyber-mcp-%d" ascii
        $node_ws = "/api/aop/node/ws" ascii
        $rpc = "cyber.rpc.aop.AOPService" ascii
        $pid = "cyber-agent.pid" ascii
        $module = "github.com/chainreactors/cyber/" ascii
    condition:
        filesize < 300MB and (
            any of ($ua, $ua_old, $prompt, $scanner_prompt, $session_src) or
            ($module and 2 of ($session, $route, $mcp_id, $node_ws, $rpc, $pid))
        )
}

rule cyber_harness_Hub_Page
{
    meta:
        description = "cyber-harness Web Hub page (web/frontend/index.html as built, title Cyber or, before September 2026, AIScan) saved or served"
        mitre_att = "T1071.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/chainreactors/cyber-harness/blob/02ac8ecfa6435610cbe7ee2f3e4deeb5481702c5/web/frontend/index.html"
        confidence = "high"
    strings:
        $title = "<title>Cyber</title>" ascii
        $theme = "localStorage.getItem('cyber-theme')" ascii
        $title_old = "<title>AIScan</title>" ascii
        $theme_old = "localStorage.getItem('aiscan-theme')" ascii
    condition:
        filesize < 1MB and (($title and $theme) or ($title_old and $theme_old))
}

rule cyber_harness_Hub_Database
{
    meta:
        description = "cyber-harness Web Hub SQLite store (cyber-harness.db): sessions, AOP events and the request ledger of every connected scan or audit node"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/chainreactors/cyber-harness/blob/02ac8ecfa6435610cbe7ee2f3e4deeb5481702c5/pkg/web/service/store_schema.go"
        confidence = "medium"
    strings:
        $events = "chat_aop_events" ascii
        $ledger = "aop_request_ledger" ascii
        $sessions = "chat_sessions" ascii
        $raw = "raw_artifacts" ascii
    condition:
        uint32be(0) == 0x53514C69 and $events and $ledger and ($sessions or $raw)  // "SQLi" of "SQLite format 3"
}
