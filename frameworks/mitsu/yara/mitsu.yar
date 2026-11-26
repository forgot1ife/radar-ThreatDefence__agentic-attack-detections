/*
   Agentic attack detections by ThreatDefence: Mitsu
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the Mitsu source code (ARCANGEL0/Mitsu at a4844932, v1.5.2 plus one commit).
*/

rule Mitsu_Source
{
    meta:
        description = "Mitsu AI pentest agent source (the PyPI package mitsu or a clone), or a fork that keeps its strings"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/ARCANGEL0/Mitsu"
        confidence = "high"
    strings:
        $ua = "Mitsu/0.1 (terminal assistant; public search)" ascii
        $s1 = "mcp_servers.mitsu.url" ascii
        $s2 = "mitsu-codex-sessions" ascii
        $s3 = "mitsu-claude-sessions" ascii
        $s4 = "Reply exactly MITSU_OK" ascii
        $s5 = "You are Mitsu: the operator" ascii
        $s6 = "You are Mitsu, a security assessment assistant." ascii
        $s7 = "mitsu-searxng-config" ascii
        $s8 = ".mitsu-armory-managed" ascii
        $s9 = "MCPServer(\"Mitsu built-in tools\")" ascii
        $s10 = "Mitsu updater" ascii
    condition:
        filesize < 500KB and ($ua or 2 of ($s*))
}

rule Mitsu_Session_File
{
    meta:
        description = "Mitsu session file (~/.local/share/mitsu/sessions/<32 hex>.json): conversation and Intel record of one engagement, including targets, findings and saved credentials"
        mitre_att = "T1552.001"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/ARCANGEL0/Mitsu/blob/a4844932fd1bd0e7b26a442bd0cc8b4a25460521/config/storage.py#L283-L298"
        confidence = "medium"
    strings:
        $k1 = "\"title_source\":" ascii
        $k2 = "\"active_target\":" ascii
        $k3 = "\"schema_version\":" ascii
        $k4 = "\"observations\":" ascii
        $k5 = "\"exploits\":" ascii
        $k6 = "\"provider_id\":" ascii
        $m1 = "\"mode\": \"Investigate\"" ascii
        $m2 = "\"mode\": \"Recon\"" ascii
        $m3 = "\"mode\": \"Guided\"" ascii
        $m4 = "\"mode\": \"AutoPwn\"" ascii
        $m5 = "mitsu__" ascii
    condition:
        uint8(0) == 0x7b and all of ($k*) and 1 of ($m*)
}

rule Mitsu_Report_Or_Attack_Surface_Map
{
    meta:
        description = "HTML assessment report or attack-surface map written by Mitsu into <session>/artifacts/"
        mitre_att = "T1595.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/ARCANGEL0/Mitsu/blob/a4844932fd1bd0e7b26a442bd0cc8b4a25460521/workspace/assessment_report.py#L1022-L1026"
        confidence = "high"
    strings:
        $r1 = "<strong>Mitsu</strong><span>Agentic RedTeam Framework</span>" ascii
        $r2 = "Mitsu | Assessment report | Page" ascii
        $r3 = "src=\"mitsu-logo.png\"" ascii
        $m1 = { E2 9C A6 20 4D 69 74 73 75 20 C2 B7 20 53 65 73 73 69 6F 6E 20 49 6E 74 65 6C }  // "✦ Mitsu · Session Intel"
        $m2 = { 20 C2 B7 20 4D 69 74 73 75 3C 2F 74 69 74 6C 65 3E }  // " · Mitsu</title>"
        $m3 = "querySelector('#footer').textContent='Mitsu " ascii
    condition:
        filesize < 20MB and (2 of ($r*) or 2 of ($m*))
}
