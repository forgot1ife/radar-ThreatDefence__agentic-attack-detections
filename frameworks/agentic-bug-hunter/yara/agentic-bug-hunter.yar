/*
   Agentic attack detections by ThreatDefence: Agentic Bug Hunter
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Strings from awarexone/Agentic-Bug-Hunter at 82f4512e (6.0.1), checked against its source files.
*/

rule AgenticBugHunter_Source_Or_Package
{
    meta:
        description = "Agentic Bug Hunter source, pip package or installed copy: its scanner user agents, canaries, dashboard guard or agent prompt"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/awarexone/Agentic-Bug-Hunter"
        confidence = "medium"
    strings:
        $verifier = "agentic-bug-hunter/verifier" ascii
        $guard = "unrecognized Host (DNS-rebinding guard)" ascii
        $prompt = "You are an elite autonomous bug bounty hunter operating within an authorized bug bounty program" ascii
        $cbbx = "window.__cbbx" ascii
        $spray_ua = "Intel Mac OS X 10_15_7) Bug-Bounty-Research" ascii
        $waf_ua = "waf-response-analyzer/1.0" ascii
        $rt = "RT_PWNED_" ascii
        $nosqli = "definitely-wrong-pw" ascii
        $waftest = "/?_waftest=" ascii
        $title = "\"X-Title\": \"BugHunter\"" ascii
    condition:
        filesize < 5MB and (any of ($verifier, $guard, $prompt, $cbbx, $spray_ua) or 2 of ($waf_ua, $rt, $nosqli, $waftest, $title))
}

rule AgenticBugHunter_Output_Files
{
    meta:
        description = "Files Agentic Bug Hunter writes: the password spray audit log, the PoC evidence HAR and the exported Hunt Dashboard"
        mitre_att = "T1110.003"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/awarexone/Agentic-Bug-Hunter"
        confidence = "medium"
    strings:
        $spray_round = "{\"round\": " ascii
        $spray_pwd = "\"pwd_sha256_prefix\": \"" ascii
        $spray_hit = "\"looks_like_success\": " ascii
        $har_name = "\"name\": \"agentic-bug-hunter\"" ascii
        $har_ver = "\"version\": \"poc_bundler\"" ascii
        $dash = { 41 67 65 6E 74 69 63 20 42 75 67 20 48 75 6E 74 65 72 20 C2 B7 20 6C 6F 63 61 6C 20 64 61 73 68 62 6F 61 72 64 }
    condition:
        filesize < 200MB and ((all of ($spray_*)) or (all of ($har_*)) or $dash)
}
