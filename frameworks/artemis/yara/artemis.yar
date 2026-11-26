/*
   Agentic attack detections by ThreatDefence: ARTEMIS
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Built from the ARTEMIS source code (Stanford-Trinity/ARTEMIS at f309242d).
*/

rule ARTEMIS_Codex_Fork_Binary
{
    meta:
        description = "ARTEMIS build of the Codex CLI (codex-rs/target/release/codex): fork-only exec flags, the embedded red-team specialist prompts and the autonomous mode backup folder"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Stanford-Trinity/ARTEMIS/blob/f309242d2a74493cd41aa3f8b02cec4d3fdd479d/codex-rs/exec/src/cli.rs#L66-L80"
        confidence = "high"
    strings:
        $f1 = "wait-for-followup" ascii
        $f2 = "log-session-dir" ascii
        $f3 = "=== CODEX INSTANCE: " ascii
        $f4 = "waiting_for_followup" ascii
        $f5 = "codex-logs-backup" ascii
        $f6 = "latest_session_heartbeat.json" ascii
        $p1 = "You are Codex, a deployed cybersecurity red-teaming agent operating inside a fully-equipped Kali Linux container" ascii
        $p2 = "You are Codex, the Shelling Agent deployed inside a fully-equipped Kali Linux container" ascii
        $p3 = "You are Codex, the Active Directory Enumeration Agent" ascii
        $p4 = "You are Codex, the Windows Privilege Escalation Agent inside Kali" ascii
    condition:
        (uint32(0) == 0x464c457f or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint16(0) == 0x5a4d)
        and filesize < 300MB and 1 of ($p*) and 3 of ($f*)
}

rule ARTEMIS_Supervisor_Source
{
    meta:
        description = "ARTEMIS Python supervisor source (supervisor/*.py) or a fork that keeps its codex exec command and report strings"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Stanford-Trinity/ARTEMIS/tree/f309242d2a74493cd41aa3f8b02cec4d3fdd479d/supervisor"
        confidence = "high"
    strings:
        $s1 = "\"--wait-for-followup\"" ascii
        $s2 = "\"--instance-id\", instance_id" ascii
        $s3 = "Codex Supervisor - AI Security Testing Orchestrator" ascii
        $s4 = "supervisor_session_{timestamp}" ascii
        $s5 = "=== VULNERABILITY SUBMITTED TO SLACK ===" ascii
        $s6 = "You are an autonomous security testing supervisor, orchestrating multiple Codex instances" ascii
        $s7 = "supervisor_heartbeat.json" ascii
        $s8 = "\"web-enumeration\"" ascii
    condition:
        filesize < 200KB and 2 of them
}

rule ARTEMIS_Specialist_Prompt
{
    meta:
        description = "ARTEMIS specialist system prompt files (codex-rs/core/*.md), a custom prompt it generated, or a workspace log that holds one"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Stanford-Trinity/ARTEMIS/tree/f309242d2a74493cd41aa3f8b02cec4d3fdd479d/codex-rs/core"
        confidence = "medium"
    strings:
        $p1 = "You are Codex, a deployed cybersecurity red-teaming agent operating inside a fully-equipped Kali Linux container" ascii
        $p2 = "You are Codex, the Shelling Agent deployed inside a fully-equipped Kali Linux container" ascii
        $p3 = "You are Codex, the Active Directory Enumeration Agent running inside a fully-equipped Kali Linux container" ascii
        $p4 = "You are Codex, the Windows Privilege Escalation Agent inside Kali" ascii
        $x1 = "s:4:\"test\";s:11:\"injection\";" ascii
    condition:
        filesize < 50MB and (1 of ($p*) or ($x1 and filesize < 64KB))
}

rule ARTEMIS_Session_Files
{
    meta:
        description = "ARTEMIS run output: a sub-agent realtime_context.txt, status.json or final_result.json, or the vulnerabilities_found.log the supervisor keeps"
        mitre_att = "T1059"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/Stanford-Trinity/ARTEMIS/blob/f309242d2a74493cd41aa3f8b02cec4d3fdd479d/codex-rs/exec/src/realtime_logger.rs#L80-L87"
        confidence = "high"
    strings:
        $ctx = "=== CODEX INSTANCE: " ascii
        $sys = "] SYSTEM: " ascii
        $vul = "=== VULNERABILITY SUBMITTED TO SLACK ===" ascii
        $vul2 = "Reproduction Steps:" ascii
        $st1 = "\"status\": \"waiting_for_followup\"" ascii
        $st2 = "\"last_message_index\"" ascii
        $fr1 = "\"instance_id\"" ascii
        $fr2 = "\"specialist\"" ascii
        $fr3 = "\"system_prompt\"" ascii
        $fr4 = "\"conversation\"" ascii
        $fr5 = "fully-equipped Kali Linux container" ascii
    condition:
        ($ctx at 0 and $sys)
        or ($vul and $vul2)
        or (filesize < 4KB and $st1 and $st2)
        or (uint8(0) == 0x7b and $fr1 and $fr3 and $fr4 and ($fr2 or $fr5))
}
