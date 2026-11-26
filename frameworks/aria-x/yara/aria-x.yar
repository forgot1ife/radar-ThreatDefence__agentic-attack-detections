/*
   Agentic attack detections by ThreatDefence: ARIA-X
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the ARIA-X source code (01NGVI-QINGYI/ARIA-X at 015e197, v0.3.0). The middle dot in the
   console title is U+00B7, written as UTF-8 bytes.
*/

rule ARIA_X_Source_Or_Console
{
    meta:
        description = "ARIA-X source, console or deployment files: its target user agent, console title, API realm and token header, prompt heading, tagline and environment variables"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/01NGVI-QINGYI/ARIA-X"
        confidence = "high"
    strings:
        // src/aria_x/tools/net.py:40
        $ua = " (authorized security research)\"" ascii
        // ARIA-X · Engagement Console (src/aria_x/web/index.html:8)
        $title = { 41 52 49 41 2D 58 20 C2 B7 20 45 6E 67 61 67 65 6D 65 6E 74 20 43 6F 6E 73 6F 6C 65 }
        $realm = "Bearer realm=\"ARIA-X\"" ascii
        $token_header = "X-ARIA-X-Token" ascii
        $doctrine = "# ARIA-X OPERATING DOCTRINE" ascii
        $tagline = "Autonomous Reasoning & Investigation Agent, eXtended" ascii
        $env_token = "ARIA_X_AUTH_TOKEN" ascii
        $env_sandbox = "ARIA_X_SANDBOX" ascii
        $container = "\"aria-x-\" + os.urandom(6).hex()" ascii
        $meta_desc = "autonomous security engagement control plane" ascii
    condition:
        filesize < 2MB and 2 of them
}

rule ARIA_X_Run_Evidence_Or_Report
{
    meta:
        description = "Files an ARIA-X run writes: HTTP evidence records (runs/run_<id>/work/evidence/http_<date>_<time>_<n>.json) that carry the ARIA-X user agent, and its engagement reports"
        mitre_att = "T1595.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/01NGVI-QINGYI/ARIA-X"
        confidence = "high"
    strings:
        $ev_kind = "\"kind\": \"http\"" ascii
        $ev_run = "\"run_id\": \"run_" ascii
        $ev_ua = "\"User-Agent\": \"ARIA-X/" ascii
        // report footer licence part, same in all three languages: " · AGPL-3.0-or-later · " (src/aria_x/report/i18n.py:192,326,461)
        $rep_lic = { 20 C2 B7 20 41 47 50 4C 2D 33 2E 30 2D 6F 72 2D 6C 61 74 65 72 20 C2 B7 20 }
        // report eyebrows (src/aria_x/report/i18n.py:182,316,451): English, Simplified Chinese (the default language), Japanese
        $rep_eye_en = { 41 52 49 41 2D 58 20 C2 B7 20 41 75 74 68 6F 72 69 7A 65 64 20 53 65 63 75 72 69 74 79 20 41 73 73 65 73 73 6D 65 6E 74 }
        $rep_eye_zh = { 41 52 49 41 2D 58 20 C2 B7 20 E6 8E 88 E6 9D 83 E5 AE 89 E5 85 A8 E8 AF 84 E4 BC B0 }
        $rep_eye_ja = { 41 52 49 41 2D 58 20 C2 B7 20 E8 AA 8D E5 8F AF E6 B8 88 E3 81 BF E3 82 BB E3 82 AD E3 83 A5 E3 83 AA E3 83 86 E3 82 A3 E8 A9 95 E4 BE A1 }
        // fallback report title "ARIA-X Engagement Report —" (src/aria_x/engine/orchestrator.py:1367,1385)
        $rep_title = { 41 52 49 41 2D 58 20 45 6E 67 61 67 65 6D 65 6E 74 20 52 65 70 6F 72 74 20 E2 80 94 }
    condition:
        filesize < 20MB and (all of ($ev_*) or ($rep_lic and 1 of ($rep_eye_*)) or $rep_title)
}
