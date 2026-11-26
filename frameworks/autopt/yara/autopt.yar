/*
   Agentic attack detections by ThreatDefence: AutoPT
   https://github.com/ThreatDefence/agentic-attack-detections

   Experimental. Tested against the evenhu9/AutoPT and Dizzy-K/AutoPT source trees, a synthetic run result, and
   this repository (no matches there).
*/

rule AutoPT_Source
{
    meta:
        description = "AutoPT source (evenhu9/AutoPT or the upstream Dizzy-K/AutoPT): its agent prompts, console banner, result file name or user agent"
        mitre_att = "T1588.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/evenhu9/AutoPT"
        confidence = "medium"
    strings:
        $console = "AutoPT Web Console" ascii
        $title = "<title>AutoPT - " ascii
        $vulhub = "=== VULHUB PoC REFERENCE (from github.com/vulhub/vulhub) ===" ascii
        $scan_role = "ROLE: Vulnerability scanner (SCAN ONLY, NO EXPLOITATION)" ascii
        $fsm = "_FSM.jsonl" ascii
        $ua = "\"User-Agent\": \"AutoPT/1.0\"" ascii
        $tool = "Execute the command in an interactive shell on your local machine (on Ubuntu 22.04 as root user" ascii
    condition:
        filesize < 2MB and any of them
}

rule AutoPT_Run_Result
{
    meta:
        description = "AutoPT run result (src/result/<model>/<service>_<CVE>_<model>_FSM.jsonl): JSON lines with the run flag, the commands the agent ran and its check messages"
        mitre_att = "T1595.002"
        author = "ThreatDefence"
        date = "2026-11-26"
        reference = "https://github.com/evenhu9/AutoPT"
        confidence = "medium"
    strings:
        $flag = "\"flag\": \"" ascii
        $commands = "\"commands\": [" ascii
        $history = "\"history\": [" ascii
        $ok = "Successfully exploited the vulnerability, a total of " ascii
        $fail1 = "Failed to exploit the vulnerability, please try " ascii
        $fail2 = "Failed to exploit the vulnerability - " ascii
    condition:
        filesize < 20MB and $flag and $commands and $history and any of ($ok, $fail1, $fail2)
}
